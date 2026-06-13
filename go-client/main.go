package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme"
)

var (
	deviceID   string
	deviceMu   sync.RWMutex
	acmeCert   = "/app/data/acme-client.crt"
	acmeKey    = "/app/data/acme-client-key.pem"
	acmeAcctKey = "/app/data/acme-account-key.pem"
	rootCA     = "/app/certs/root-ca.crt"
	caChain    = "/app/certs/ca-chain.crt"
	trustChain = "/app/certs/trust-chain.crt"
)

func main() {
	log.Println("=== Zero-FAS Device Client Daemon ===")

	// Step 1: ACME boot — obtain client certificate from step-ca
	log.Println("[1/5] ACME certificate enrollment...")
	if err := acmeBoot(); err != nil {
		log.Fatalf("ACME boot failed: %v", err)
	}

	// Start ACME certificate auto-renewal goroutine (checks daily, renews at 7d threshold)
	go func() {
		// Create ACME client from saved account key for renewal
		renewClient, err := newACMEClient()
		if err != nil {
			log.Printf("Renewal: cannot initialize ACME client: %v", err)
			return
		}
		// Renewal goroutine also needs the cert key — loaded from disk each time
		log.Println("  Auto-renewal background worker started (check interval: 24h, threshold: 7d)")
		autoRenewCert(context.Background(), renewClient)
	}()

		log.Println("✅ ACME certificate obtained")

	// Step 2: Register with go-server (direct mTLS, bypassing nginx,
	// so go-server sees the ACME client cert CN, not nginx-proxy's CN)
	log.Println("[2/5] Device registration with go-server...")
	if err := registerDevice(); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	log.Printf("✅ Registered as device: %s", getDeviceID())

	// Step 3: Configure and start system OpenSSH daemon
	log.Println("[3/5] Configuring system OpenSSH daemon...")
	if err := configureSSHD(); err != nil {
		log.Printf("⚠️ SSHD configuration failed: %v", err)
	} else {
		log.Println("✅ OpenSSH daemon started on port 22")
	}

	// Step 4: Start heartbeat loop (goroutine)
	log.Println("[4/5] Starting heartbeat loop (30s interval)...")
	go heartbeatLoop()

	// Step 5: Maintain WebSocket echo connection through nginx
	log.Println("[5/5] Connecting to WebSocket echo through nginx...")
	go wsEchoLoop()

	log.Println("=== Daemon ready. Waiting for shutdown signal (Ctrl+C) ===")

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig

	log.Println("Shutting down...")
}

// getDeviceID safely reads the device ID
func getDeviceID() string {
	deviceMu.RLock()
	defer deviceMu.RUnlock()
	return deviceID
}

// setDeviceID safely sets the device ID
func setDeviceID(id string) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	deviceID = id
}

// ---------------------------------------------------------------------------
// Phase 1: ACME certificate enrollment
// ---------------------------------------------------------------------------

// acmeBoot runs `step ca certificate` to obtain a client cert from step-ca ACME.
// Step CLI generates its own key pair and handles the HTTP-01 challenge.
// acmeBoot obtains a client certificate from step-ca using the ACME protocol.
// Uses golang.org/x/crypto/acme (no external step binary dependency).
// HTTP-01 challenge: starts a temp HTTP server on port 80, step-ca validates
// by connecting to http://go-client:80/.well-known/acme-challenge/<token>.
func acmeBoot() error {
	// Ensure data directory exists
	dataDir := filepath.Dir(acmeCert)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dataDir, err)
	}

	// Remove any stale cert/key from previous failed runs
	os.Remove(acmeCert)
	os.Remove(acmeKey)
	os.Remove(acmeAcctKey)

	ctx := context.Background()

	// Generate ECDSA P-256 account key (standard for ACME)
	log.Println("  Generating ACME account key (ECDSA P-256)...")
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}

	// TLS config for ACME server connection.
	// step-ca serves TLS with intermediate.crt signed by root-ca.crt.
	caCertPEM, err := os.ReadFile(rootCA)
	if err != nil {
		return fmt.Errorf("read root CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return fmt.Errorf("failed to parse root CA PEM")
	}
	acmeTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // step-ca dev-tls uses ephemeral self-signed cert
		ServerName:         "step-ca",
		MinVersion:         tls.VersionTLS12,
	}

	acmeHTTPClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: acmeTLSConfig,
		},
	}

	// Create ACME client
	client := &acme.Client{
		DirectoryURL: "https://step-ca:8443/acme/acme/directory",
		UserAgent:    "zero-fas-go-client/1.0",
		HTTPClient:   acmeHTTPClient,
		Key:          accountKey,
	}

	// Register ACME account
	log.Println("  Registering ACME account...")
	acct := &acme.Account{}
	acct, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		if ae, ok := err.(*acme.Error); ok && ae.StatusCode == http.StatusConflict {
			log.Println("  Account already exists, continuing...")
		} else {
			return fmt.Errorf("ACME register: %w", err)
		}
	} else {
		log.Printf("  Account registered: %s", acct.URI)
	}

	// Save account key to disk for renewal
	if err := saveECKey(acmeAcctKey, accountKey); err != nil {
		return fmt.Errorf("save account key: %w", err)
	}
	log.Println("  Account key saved")

	// Generate certificate key (RSA 2048)
	log.Println("  Generating certificate key (RSA 2048)...")
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("cert key: %w", err)
	}

	// Save private key before ACME flow
	if err := savePrivateKey(acmeKey, certKey); err != nil {
		return fmt.Errorf("save key: %w", err)
	}

	// Create order for "go-client" identifier
	log.Println("  Creating ACME order...")
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs("go-client"))
	if err != nil {
		return fmt.Errorf("ACME order: %w", err)
	}
	log.Printf("  Order created: %s", order.URI)

	// Complete all authorizations (HTTP-01 challenge)
	for _, authzURL := range order.AuthzURLs {
		if err := completeHTTP01Challenge(ctx, client, authzURL); err != nil {
			return fmt.Errorf("challenge for %s: %w", authzURL, err)
		}
	}

	// Generate CSR
	log.Println("  Generating CSR...")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "go-client",
		},
	}, certKey)
	if err != nil {
		return fmt.Errorf("CSR: %w", err)
	}

	// Finalize order and get certificate
	log.Println("  Finalizing order...")
	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	// Save certificate (first element is the leaf, rest is chain)
	if len(certDER) > 0 {
		var certPEMBuf bytes.Buffer
		for _, der := range certDER {
			pem.Encode(&certPEMBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		if err := os.WriteFile(acmeCert, certPEMBuf.Bytes(), 0644); err != nil {
			return fmt.Errorf("save cert: %w", err)
		}
		log.Printf("  Certificate saved to %s (%d bytes)", acmeCert, certPEMBuf.Len())
	}

	return nil
}

// completeHTTP01Challenge completes an HTTP-01 ACME authorization challenge.
// Starts a temporary HTTP server on port 80 that serves the challenge token.
func completeHTTP01Challenge(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("get authz: %w", err)
	}
	log.Printf("  Authorization for %s (%s)", authz.Identifier.Value, authz.Identifier.Type)

	// Find HTTP-01 challenge
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("no http-01 challenge for %s", authz.Identifier.Value)
	}

	// Get challenge response token
	respToken, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return fmt.Errorf("challenge response: %w", err)
	}

	// Start temporary HTTP server for challenge
	challengePath := client.HTTP01ChallengePath(chal.Token)
	log.Printf("  Serving HTTP-01 challenge at %s", challengePath)

	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(respToken))
	})

	server := &http.Server{Addr: ":80", Handler: mux}
	go server.ListenAndServe()
	time.Sleep(100 * time.Millisecond)
	defer server.Close()

	// Accept the challenge
	log.Println("  Accepting HTTP-01 challenge...")
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}

	// Wait for authorization
	log.Println("  Waiting for step-ca to validate...")
	if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("wait authz: %w", err)
	}
	log.Println("  Challenge validated!")

	return nil
}

// savePrivateKey saves an RSA private key to the given path in PEM format.
func savePrivateKey(path string, key *rsa.PrivateKey) error {
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600)
}

// saveECKey saves an ECDSA private key to the given path in PEM format.
func saveECKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600)
}

// loadECKey loads an ECDSA private key from a PEM file.
func loadECKey(path string) (*ecdsa.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM data in %s", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// newACMEClient creates a new ACME client from the saved account key on disk.
func newACMEClient() (*acme.Client, error) {
	// Load the saved account key
	acctKey, err := loadECKey(acmeAcctKey)
	if err != nil {
		return nil, fmt.Errorf("load account key: %w", err)
	}

	// TLS config for step-ca
	caCertPEM, err := os.ReadFile(rootCA)
	if err != nil {
		return nil, fmt.Errorf("read root CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse root CA PEM")
	}

	acmeHTTPClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "step-ca",
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	return &acme.Client{
		DirectoryURL: "https://step-ca:8443/acme/acme/directory",
		UserAgent:    "zero-fas-go-client/1.0",
		HTTPClient:   acmeHTTPClient,
		Key:          acctKey,
	}, nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ACME Auto-Renewal
// ---------------------------------------------------------------------------

// autoRenewCert runs in a goroutine, checking certificate expiration daily.
// If the remaining lifetime drops below 7 days, it renews via ACME.
func autoRenewCert(ctx context.Context, client *acme.Client) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Read current certificate
		certPEM, err := os.ReadFile(acmeCert)
		if err != nil {
			log.Printf("Renewal: cannot read cert: %v", err)
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Printf("Renewal: cannot parse cert PEM")
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Renewal: cannot parse cert: %v", err)
			continue
		}

		// Check if certificate expires within 7 days
		remaining := time.Until(cert.NotAfter)
		renewThreshold := 7 * 24 * time.Hour

		if remaining > renewThreshold {
			log.Printf("Renewal: cert expires in %v (threshold: %v), no action needed",
				roundDuration(remaining), roundDuration(renewThreshold))
			continue
		}

		log.Printf("Renewal: cert expires in %v — starting renewal...", roundDuration(remaining))

		// Load the certificate key
		keyPEM, err := os.ReadFile(acmeKey)
		if err != nil {
			log.Printf("Renewal: cannot read key: %v", err)
			continue
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			log.Printf("Renewal: cannot parse key PEM")
			continue
		}
		certKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Printf("Renewal: cannot parse key: %v", err)
			continue
		}

		// Generate new CSR
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "go-client"},
		}, certKey)
		if err != nil {
			log.Printf("Renewal: CSR failed: %v", err)
			continue
		}

		// Create new order and complete challenges
		certDER, err := renewCertificate(ctx, client, csrDER)
		if err != nil {
			log.Printf("Renewal failed: %v", err)
			continue
		}

		// Save renewed certificate
		var certPEMBuf bytes.Buffer
		pem.Encode(&certPEMBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(acmeCert, certPEMBuf.Bytes(), 0644); err != nil {
			log.Printf("Renewal: save cert failed: %v", err)
			continue
		}

		log.Printf("✅ Certificate renewed successfully (expires: %s)",
			time.Now().Add(720*time.Hour).Format(time.RFC3339))
	}
}

// renewCertificate creates a new ACME order and completes the HTTP-01 challenge
// to obtain a renewed certificate.
func renewCertificate(ctx context.Context, client *acme.Client, csrDER []byte) ([]byte, error) {
	// Create a new order
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs("go-client"))
	if err != nil {
		return nil, fmt.Errorf("renewal order: %w", err)
	}

	// Complete all authorizations
	for _, authzURL := range order.AuthzURLs {
		if err := completeHTTP01Challenge(ctx, client, authzURL); err != nil {
			return nil, fmt.Errorf("renewal challenge: %w", err)
		}
	}

	// Finalize and get cert
	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("renewal finalize: %w", err)
	}

	if len(certDER) == 0 {
		return nil, fmt.Errorf("renewal: empty cert bundle")
	}

	return certDER[0], nil
}

// roundDuration rounds a duration to the nearest hour for display.
func roundDuration(d time.Duration) time.Duration {
	return d.Round(time.Hour)
}
// ---------------------------------------------------------------------------
// Phase 2: Device registration (direct mTLS to go-server:9090)
// ---------------------------------------------------------------------------

// registerDevice registers this device with the go-server via direct mTLS.
// Must connect DIRECTLY to go-server:9090 (not through nginx) so that the
// register handler sees the ACME client cert's CN, not nginx-proxy's CN.
func registerDevice() error {
	// Load the ACME-issued client cert for mTLS
	cert, err := tls.LoadX509KeyPair(acmeCert, acmeKey)
	if err != nil {
		return fmt.Errorf("load ACME cert: %w", err)
	}

	// Load trust chain for verifying go-server's TLS cert.
	// go-server's server.crt is signed by "Vault PKI Intermediate CA"
	// which is in trust-chain.crt (Vault PKI Intermediate + Zero-FAS Root CA).
	caCert, err := os.ReadFile(trustChain)
	if err != nil {
		return fmt.Errorf("read trust chain: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse trust chain PEM")
	}

	// mTLS config: present ACME client cert, verify go-server with trust chain
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   "go-server",
		MinVersion:   tls.VersionTLS12,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	// Register
	body := map[string]string{
		"label": "acme-client-001",
		"dc":    "1",
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := client.Post(
		"https://go-server:9090/api/register",
		"application/json",
		bytes.NewReader(bodyJSON),
	)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	id, _ := result["device_id"].(string)
	if id == "" {
		return fmt.Errorf("registration response missing device_id: %s", string(respBody))
	}
	setDeviceID(id)

	// Save SSH CA public key if provided (for TrustedUserCAKeys)
	if sshCAKey, ok := result["ssh_ca_pub_key"].(string); ok && sshCAKey != "" {
		sshDir := "/etc/ssh"
		if err := os.MkdirAll(sshDir, 0755); err == nil {
			_ = os.WriteFile(sshDir+"/ca.pub", []byte(sshCAKey), 0644)
			log.Printf("SSH CA public key saved to %s/ca.pub", sshDir)
		}
	}
	// Send SSH host key to go-server for known_hosts
	hostKeyPath := "/etc/ssh/ssh_host_rsa_key.pub"
	if hostKeyBytes, err := os.ReadFile(hostKeyPath); err == nil {
		log.Printf("SSH host key: %s", strings.TrimSpace(string(hostKeyBytes[:80])))
	}

	// Log registration details
	log.Printf("Registered device_id=%s, ssh_target=%v, ssh_user=%v",
		id,
		result["ssh_target"],
		result["ssh_user"],
	)

	return nil
}

// Phase 4: Heartbeat loop
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Phase 3: System OpenSSH daemon (for remote access via Web UI)
// ---------------------------------------------------------------------------

// configureSSHD configures and starts the system OpenSSH daemon.
// Replaces the custom Go SSH server with a production-grade SSH daemon.
func configureSSHD() error {
	// Ensure SSH CA public key is in place (saved by registerDevice)
	caKeyPath := "/etc/ssh/ca.pub"
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		log.Printf("⚠️ SSH CA key not found at %s — generating host keys only", caKeyPath)
	}

	// Generate host keys if not present (default Alpine sshd needs them)
	if err := exec.Command("ssh-keygen", "-A").Run(); err != nil {
		return fmt.Errorf("ssh-keygen -A: %w", err)
	}
	log.Printf("SSH host keys generated")

	// Update sshd_config to trust the SSH CA and disable password auth
	configPath := "/etc/ssh/sshd_config"
	config, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	lines := strings.Split(string(config), "\n")
	var newLines []string
	hadTrustedCA := false
	hadPasswordAuth := false
	hadPubkeyAuth := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "TrustedUserCAKeys") {
			newLines = append(newLines, "TrustedUserCAKeys /etc/ssh/ca.pub")
			hadTrustedCA = true
		} else if strings.HasPrefix(trimmed, "PasswordAuthentication") {
			newLines = append(newLines, "PasswordAuthentication no")
			hadPasswordAuth = true
		} else if strings.HasPrefix(trimmed, "PubkeyAuthentication") {
			newLines = append(newLines, "PubkeyAuthentication yes")
			hadPubkeyAuth = true
		} else {
			newLines = append(newLines, line)
		}
	}

	if !hadTrustedCA {
		newLines = append(newLines, "TrustedUserCAKeys /etc/ssh/ca.pub")
	}
	if !hadPasswordAuth {
		newLines = append(newLines, "PasswordAuthentication no")
	}
	// Allow RSA SHA-1 for Vault CA certificate compatibility (OpenSSH 9.6+)
	newLines = append(newLines, "PubkeyAcceptedAlgorithms +ssh-rsa")
	newLines = append(newLines, "CASignatureAlgorithms +ssh-rsa")
	if !hadPubkeyAuth {
		newLines = append(newLines, "PubkeyAuthentication yes")
	}

	if err := os.WriteFile(configPath, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}
	log.Printf("SSHD config updated: TrustedUserCAKeys, PasswordAuthentication no")

	// Start sshd (must use exec, not the init system — Alpine doesn't have one by default)
	cmd := exec.Command("/usr/sbin/sshd")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sshd: %w", err)
	}
	log.Printf("OpenSSH daemon started (pid: %d)", cmd.Process.Pid)

	return nil
}

// ---------------------------------------------------------------------------// heartbeatLoop sends heartbeat to go-server every 30 seconds.
// Uses HTTP (not mTLS) because go-server:9091 is the HTTP (non-mTLS) port.
func heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		id := getDeviceID()
		if id == "" {
			continue
		}

		body := map[string]string{"device_id": id}
		bodyJSON, _ := json.Marshal(body)

		resp, err := http.Post(
			"http://go-server:9091/api/heartbeat",
			"application/json",
			bytes.NewReader(bodyJSON),
		)
		if err != nil {
			log.Printf("Heartbeat failed: %v", err)
			continue
		}
		resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// Phase 5: WebSocket echo (through nginx, original design)
// ---------------------------------------------------------------------------

// wsEchoLoop maintains a WebSocket echo connection through nginx:443.
// Uses the ACME cert for mTLS to nginx.
func wsEchoLoop() {
	// Give registration time to complete before first WS connection
	time.Sleep(2 * time.Second)

	for {
		conn, err := dialWSEcho()
		if err != nil {
			log.Printf("WS echo dial failed (retry in 5s): %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("WS echo connected through nginx:443")
		keepAlive(conn)
		log.Printf("WS echo disconnected, reconnecting in 5s...")
		time.Sleep(5 * time.Second)
	}
}

// dialWSEcho dials the WebSocket echo endpoint through nginx
func dialWSEcho() (*websocket.Conn, error) {
	// Load ACME cert for mTLS
	cert, err := tls.LoadX509KeyPair(acmeCert, acmeKey)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}

	// Load ca-chain.crt for nginx server verification.
	// nginx.crt is signed by step-ca Intermediate CA, which is in ca-chain.crt.
	caCert, err := os.ReadFile(caChain)
	if err != nil {
		return nil, fmt.Errorf("read ca-chain: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   "nginx",
		MinVersion:   tls.VersionTLS12,
	}

	u := url.URL{Scheme: "wss", Host: "nginx:443", Path: "/ws"}
	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// keepAlive sends periodic echo messages over the WebSocket connection
func keepAlive(conn *websocket.Conn) {
	defer conn.Close()

	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})

	for i := 0; ; i++ {
		msg := fmt.Sprintf("Heartbeat %d from ACME client (%s)", i, getDeviceID())
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			log.Printf("WS write error: %v", err)
			return
		}

		// Set read deadline for the response
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		_, response, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WS read error: %v", err)
			return
		}
		log.Printf("WS echo: %s", string(response))

		time.Sleep(60 * time.Second)
	}
}
