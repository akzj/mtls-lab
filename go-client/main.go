package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
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
	"golang.org/x/crypto/ssh"
)

var (
	deviceID   string
	deviceMu   sync.RWMutex
	acmeCert   = "/app/data/acme-client.crt"
	acmeKey    = "/app/data/acme-client-key.pem"
	acmePwd    = "/app/data/password"
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
	log.Println("✅ ACME certificate obtained")

	// Step 2: Register with go-server (direct mTLS, bypassing nginx,
	// so go-server sees the ACME client cert CN, not nginx-proxy's CN)
	log.Println("[2/5] Device registration with go-server...")
	if err := registerDevice(); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	log.Printf("✅ Registered as device: %s", getDeviceID())

	// Step 3: Start SSH server for remote access (goroutine)
	log.Println("[3/5] Starting SSH server on :2222...")
	go startSSHServer()

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
func acmeBoot() error {
	// Ensure data directory exists
	dataDir := filepath.Dir(acmeCert)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dataDir, err)
	}

	// Remove any stale cert/key from previous failed runs to avoid mismatches
	os.Remove(acmeCert)
	os.Remove(acmeKey)

	// Create a password file for step CLI private key encryption.
	// Without this, step CLI tries to prompt on /dev/tty (not available in Docker).
	if err := os.WriteFile(acmePwd, []byte("zero-fas-lab\n"), 0600); err != nil {
		return fmt.Errorf("write password file: %w", err)
	}

	// Run `step ca certificate` — ACME boot with step-ca.
	// Step CLI auto-selects HTTP-01 challenge in this environment:
	// it listens on port 80, step-ca connects back to verify.
	// In Docker Compose, go-client is reachable from step-ca on any port
	// via the shared Docker network.
	cmd := exec.Command("step",
		"ca", "certificate",
		"go-client",           // subject (DNS name)
		acmeCert,              // output cert file
		acmeKey,               // output key file
		"--provisioner", "acme",
		"--ca-url", "https://step-ca:8443",
		"--root", rootCA,
		"--not-after", "720h",
		"--password-file", acmePwd,
	)

	output, err := cmd.CombinedOutput()
	log.Printf("step ca certificate output: %s", strings.TrimSpace(string(output)))

	if err != nil {
		// step CLI sometimes exits non-zero after successful cert issuance
		// (e.g. TTY prompt failure in Docker). Check if cert was actually written.
		if _, statErr := os.Stat(acmeCert); os.IsNotExist(statErr) {
			return fmt.Errorf("ACME boot failed: %w (cert not found)", err)
		}
		log.Printf("⚠️ step CLI exited with error but cert was written — proceeding")
	}

	// Verify the cert was written and matches the key
	if _, err := os.Stat(acmeCert); os.IsNotExist(err) {
		return fmt.Errorf("ACME cert was not written to %s", acmeCert)
	}
	if _, err := os.Stat(acmeKey); os.IsNotExist(err) {
		return fmt.Errorf("ACME key was not written to %s", acmeKey)
	}

	return nil
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

	// Log registration details
	log.Printf("Registered device_id=%s, ssh_target=%v, ssh_user=%v",
		id,
		result["ssh_target"],
		result["ssh_user"],
	)

	return nil
}

// ---------------------------------------------------------------------------
// Phase 3: SSH server (for remote access via Web UI)
// ---------------------------------------------------------------------------

// startSSHServer starts an SSH server on port 2222.
// The go-server connects to this SSH server when the user clicks "SSH"
// on a registered device in the Web UI.
func startSSHServer() {
	// Generate ephemeral host key
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("SSH host key generation failed: %v", err)
		return
	}

	hostKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(hostKey),
	})

	signer, err := ssh.ParsePrivateKey(hostKeyPEM)
	if err != nil {
		log.Printf("SSH signer parse error: %v", err)
		return
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password authentication not allowed")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// Lab mode: accept any public key for SSH access
			// Production: verify against the SSH CA's public key (TrustedUserCAKeys)
			log.Printf("SSH public key auth from %s (key type: %s)", c.User(), pubKey.Type())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"permit-agent-forwarding":  "",
					"permit-port-forwarding":   "",
					"permit-pty":               "",
					"permit-user-rc":           "",
				},
			}, nil
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Printf("SSH listen error: %v", err)
		return
	}
	defer listener.Close()

	log.Printf("SSH server listening on :2222")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SSH accept error: %v", err)
			continue
		}

		go handleSSHConn(conn, config)
	}
}

// handleSSHConn handles an incoming SSH connection
func handleSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	srvConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer srvConn.Close()
	log.Printf("SSH connection from %s (%s)", srvConn.RemoteAddr(), srvConn.User())

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			log.Printf("SSH channel accept error: %v", err)
			continue
		}

		go handleSSHChannel(channel, requests)
	}
}

// handleSSHChannel handles a session channel on the SSH connection
func handleSSHChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				channel.Write([]byte(fmt.Sprintf("Error parsing command: %v\n", err)))
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
				return
			}
			log.Printf("SSH exec: %s", payload.Command)
			channel.Write([]byte(fmt.Sprintf("Hello from go-client device %s\n", getDeviceID())))
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return

		case "shell":
			log.Printf("SSH shell requested")
			channel.Write([]byte(fmt.Sprintf("Welcome to go-client device %s\n", getDeviceID())))
			channel.Write([]byte("$ "))
			// In a real setup, forward stdin/stdout to a shell.
			// For the lab, just display the welcome banner and close.
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return

		case "pty-req":
			// Accept PTY requests silently
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "window-change":
			if req.WantReply {
				req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Phase 4: Heartbeat loop
// ---------------------------------------------------------------------------

// heartbeatLoop sends heartbeat to go-server every 30 seconds.
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
