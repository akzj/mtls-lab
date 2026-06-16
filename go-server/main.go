package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"context"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"encoding/base64"
)

//go:embed static/*
var staticFS embed.FS

//go:embed migrations/*.sql
var migrationsFS embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// vaultHTTPClient is an HTTP client configured for Vault TLS (dev-tls self-signed cert).
// Initialized once in main() with InsecureSkipVerify for dev mode.
var vaultHTTPClient *http.Client


// vaultTokenManager provides thread-safe access to the Vault token,
// allowing the renewal goroutine to update it without races.
var (
	vaultTokenValue string
	vaultTokenMu    sync.RWMutex
)

func getVaultToken() string {
	vaultTokenMu.RLock()
	defer vaultTokenMu.RUnlock()
	return vaultTokenValue
}

func setVaultToken(token string) {
	vaultTokenMu.Lock()
	defer vaultTokenMu.Unlock()
	vaultTokenValue = token
}
// VaultConfig holds the secret from Vault
type VaultConfig struct {
	APIKey     string `json:"api_key"`
	DBPassword string `json:"db_password"`
}

// ===== PBAC (Permission-Based Access Control) =====

// permStore is the global PermissionStore instance (nil if DB is unavailable)
var permStore *PermissionStore

// PermissionStore provides database-backed permission lookups
type PermissionStore struct {
	db *sql.DB
}

// GetUserPermissions retrieves all permission names for a given username
func (ps *PermissionStore) GetUserPermissions(username string) ([]string, error) {
	rows, err := ps.db.Query(`
		SELECT p.name FROM permissions p
		JOIN user_permissions up ON p.id = up.permission_id
		JOIN users u ON u.id = up.user_id
		WHERE u.username = $1
	`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// initDB initializes a PostgreSQL connection pool
func initDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	return db, nil
}
// runMigrations applies golang-migrate migrations embedded in the binary.
// Uses postgres URL format for the migration DSN (different from lib/pq DSN format).
func runMigrations(dbDsn string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, dbDsn)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Println("DB migrations applied successfully")
	return nil
}



// ===== OIDC Authentication =====

// SessionStore manages browser sessions with in-memory store
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	secret   []byte
}

// Session represents an authenticated browser session
type Session struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Email     string    `json:"email"`
	Groups    []string  `json:"groups"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	sessionStore *SessionStore
	oidcProvider *oidc.Provider
	oauthConfig  *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
)

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		secret:   []byte("lab-session-secret-key-32-chars!"),
	}
}

// Create creates a new session for a user
func (ss *SessionStore) Create(user, email string, groups []string) *Session {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	id := generateSessionID()
	session := &Session{
		ID:        id,
		User:      user,
		Email:     email,
		Groups:    groups,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	ss.sessions[id] = session
	return session
}

// IsValid checks if a session ID is valid (exists and not expired)
func (ss *SessionStore) IsValid(sessionID string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	session, ok := ss.sessions[sessionID]
	if !ok {
		return false
	}
	return time.Now().Before(session.ExpiresAt)
}

// GetUser returns the username for a session ID
func (ss *SessionStore) GetUser(sessionID string) string {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if session, ok := ss.sessions[sessionID]; ok {
		return session.User
	}
	return ""
}

// GetGroups returns the groups for a session ID
func (ss *SessionStore) GetGroups(sessionID string) []string {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if session, ok := ss.sessions[sessionID]; ok {
		return session.Groups
	}
	return nil
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// checkPermission checks if the request has a specific permission
// Queries the DB-backed PermissionStore, with fallback to hardcoded maps for dev compatibility.
func checkPermission(r *http.Request, permission string) bool {
	userPerms := getUserPermissions(r, permStore)
	for _, p := range userPerms {
		if p == permission {
			return true
		}
	}
	return false
}

// ===== Identity Federation (mTLS + OIDC) =====

// IdentityInfo represents a resolved user identity
type IdentityInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
	Source   string   `json:"source"` // "mtls_cert" or "oidc_session"
}

// oidcUserToGroup maps usernames to their RBAC groups
var oidcUserToGroup = map[string][]string{
	"admin": {"admin-group"},
	"ops":   {"ops-group"},
	"dev":   {"dev-group"},
}

// resolveIdentityFromCertCN extracts identity from a client certificate CN
// CN format: username@lab.local → username → group lookup
func resolveIdentityFromCertCN(cn string) *IdentityInfo {
	// Extract username part (before @)
	username := cn
	if idx := strings.Index(cn, "@"); idx >= 0 {
		username = cn[:idx]
	}

	// Look up groups
	groups := oidcUserToGroup[username]
	if groups == nil {
		groups = []string{}
	}

	return &IdentityInfo{
		Username: username,
		Groups:   groups,
		Source:   "mtls_cert",
	}
}

func getUserPermissions(r *http.Request, ps *PermissionStore) []string {
	// First check: mTLS client certificate (forwarded by nginx from verified client cert)
	clientDN := r.Header.Get("X-Forwarded-Ssl-Client-DN")
	if clientDN != "" {
		// Parse CN from DN string (format: "CN=value,...")
		certCN := ""
		if idx := strings.Index(clientDN, "CN="); idx >= 0 {
			cnPart := clientDN[idx+3:]
			if end := strings.IndexAny(cnPart, ",;"); end >= 0 {
				certCN = strings.TrimSpace(cnPart[:end])
			} else {
				certCN = strings.TrimSpace(cnPart)
			}
		}
		if certCN != "" {
			// Try DB first
			username := certCN
			if idx := strings.Index(certCN, "@"); idx >= 0 {
				username = certCN[:idx]
			}
			if ps != nil {
				perms, err := ps.GetUserPermissions(username)
				if err == nil && len(perms) > 0 {
					return perms
				}
				if err != nil {
					log.Printf("PBAC: DB lookup failed for mTLS user %s: %v", username, err)
				}
			}
			// Fallback: hardcoded map
			identity := resolveIdentityFromCertCN(certCN)
			if len(identity.Groups) > 0 {
				log.Printf("PBAC: using fallback groups for mTLS user %s: %v", username, identity.Groups)
				return identity.Groups
			}
		}
	}

	// Second check: OIDC session cookie (independent of mTLS)
	cookie, err := r.Cookie("session_id")
	if err != nil {
		log.Printf("PBAC: no session cookie: %v", err)
	} else if !sessionStore.IsValid(cookie.Value) {
		log.Printf("PBAC: session cookie invalid or expired: %s", cookie.Value[:12])
	} else {
		username := sessionStore.GetUser(cookie.Value)
		// Try DB by username first
		if ps != nil && username != "" {
			perms, err := ps.GetUserPermissions(username)
			if err == nil && len(perms) > 0 {
				return perms
			}
			if err != nil {
				log.Printf("PBAC: DB lookup failed for OIDC user %s: %v", username, err)
			}
		}
		// Fallback: use session groups
		groups := sessionStore.GetGroups(cookie.Value)
		if len(groups) > 0 {
			log.Printf("PBAC: using fallback session groups for %s: %v", username, groups)
			return groups
		}
	}

	log.Printf("PBAC: no permissions found (header=%q)", r.Header.Get("X-Forwarded-Ssl-Client-DN"))
	return nil
}

func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://vault:8200"
	}

	// Login to Vault using TLS client certificate (server.crt signed by Vault PKI)
	var config VaultConfig
	// Initialize HTTP client for Vault API calls (dev-tls: skip server cert verification)
	vaultHTTPClient = newVaultHTTPClient()

	// Retry OIDC init in background if it fails (Authentik may not be ready yet)
	go func() {
		for i := 0; i < 12; i++ {
			if oauthConfig != nil {
				return
			}
			if err := initOIDC(); err != nil {
				log.Printf("OIDC init attempt %d/12 failed: %v", i+1, err)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	// Try VAULT_TOKEN from environment first (simplest), fall back to cert-based login
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken != "" {
		log.Printf("Using VAULT_TOKEN from environment")
	} else {
		var loginErr error
		vaultToken, loginErr = loginWithCert(
			vaultAddr,
			"certs/vault-client.crt",       // Dedicated cert (Vault PKI signed, CN=go-server)
			"certs/vault-client-key.pem",   // Dedicated key
			"certs/trust-chain.crt",  // Vault PKI intermediate + root CA
		)
		if loginErr != nil {
			log.Printf("WARNING: Vault cert login failed: %v", loginErr)
		}

	// Store token in global for thread-safe access by handlers and the renewal goroutine
	setVaultToken(vaultToken)

	// Start Vault token renewal goroutine: re-authenticates via cert auth every 30 min.
	// This prevents token expiry in long-running instances (token TTL = 86400s = 24h).
	// On renewal failure the goroutine logs and retries — no cascading failure.
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			newToken, err := loginWithCert(
				vaultAddr,
				"certs/vault-client.crt",
				"certs/vault-client-key.pem",
				"certs/trust-chain.crt",
			)
			if err != nil {
				log.Printf("Vault token renewal failed: %v — will retry in 30 min", err)
				continue
			}
			setVaultToken(newToken)
			log.Printf("Vault token renewed via cert auth")
		}
	}()
	}
	if vaultToken != "" {
		// Read Vault config
		config = readVaultConfig(vaultAddr, vaultToken)
		log.Printf("Vault config loaded: api_key=%s, db_password=%s",
			maskString(config.APIKey), maskString(config.DBPassword))
	}

	// Initialize PostgreSQL connection for PBAC
	if config.DBPassword != "" {
		dbDsn := fmt.Sprintf("host=mtls-db port=5432 user=mtls dbname=mtls password=%s sslmode=disable", config.DBPassword)
		db, err := initDB(dbDsn)
		if err != nil {
			log.Printf("WARNING: PostgreSQL unavailable — falling back to hardcoded permission maps: %v", err)
		} else {
			// Run golang-migrate migrations before initializing PermissionStore
			migrateDsn := fmt.Sprintf("postgres://mtls:%s@mtls-db:5432/mtls?sslmode=disable", url.QueryEscape(config.DBPassword))
			if err := runMigrations(migrateDsn); err != nil {
				log.Printf("WARNING: DB migration failed (using existing tables): %v", err)
			}
			permStore = &PermissionStore{db: db}
			log.Printf("PBAC: PostgreSQL connected, permission-based access control active")
		}
	} else {
		log.Printf("PBAC: No db_password in Vault config — using hardcoded permission maps (dev mode)")
	}


	// Load server cert
	serverCertFile := "certs/vault-client.crt"
	serverKeyFile := "certs/vault-client-key.pem"
	caCertFile := "certs/ca-chain.crt"

	// Create mTLS config
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	// ===== Separate muxes for mTLS (:9090) and HTTP (:9091) =====
	mtlsMux := http.NewServeMux()
	httpMux := http.NewServeMux()

	// --- Routes on mTLS mux (:9090, requires client cert) ---

	// Route: existing WebSocket echo endpoint
	mtlsMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleWebSocket(w, r, config)
	})

	// Route: Device registration API (requires mTLS client cert)
	mtlsMux.HandleFunc("/api/register", registerHandler)

	// Route: Whoami — returns authenticated user from client cert
	mtlsMux.HandleFunc("/api/whoami", whoamiHandler)

	// --- Routes on HTTP mux (:9091, no client cert needed) ---

	// Device manager (initializes SSH CA keys, heartbeat checker)
	initDeviceManager(vaultAddr, vaultToken)

	// Initialize OIDC session store
	sessionStore = NewSessionStore()

	// Try to initialize OIDC provider (non-fatal if unavailable)
	if err := initOIDC(); err != nil {
		log.Printf("OIDC provider init (optional): %v", err)
	} else {
		log.Printf("OIDC provider initialized")
	}

	// Tunnel manager for SSH port forwarding through gateway
	tunnelMgr := NewTunnelManager(vaultAddr, httpMux)

	// Route: Tunnel management API
	httpMux.HandleFunc("/api/tunnel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// PBAC: tunnel creation requires tunnel:create permission
		if !checkPermission(r, "tunnel:create") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden","message":"Only admins and ops can create tunnels"}`))
			return
		}
		tunnelMgr.handleCreateTunnel(w, r)
	})

	// Route: xterm.js terminal page (redirects to login if not authenticated)
	httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// Check if authenticated
		if !sessionCheck(r) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		html, err := staticFS.ReadFile("static/xterm.html")
		if err != nil {
			log.Printf("Failed to read xterm.html: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(html)
	})

	// OIDC login endpoint (public)
	httpMux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if oauthConfig == nil {
			log.Printf("OIDC login called but oauthConfig is nil (init likely failed)")
			http.Error(w, "OIDC not configured", http.StatusServiceUnavailable)
			return
		}
		state := generateState()
		http.Redirect(w, r, oauthConfig.AuthCodeURL(state), http.StatusFound)
	})

	// OIDC callback endpoint (public)
	httpMux.HandleFunc("/auth/callback", oidcCallbackHandler)

	// OIDC logout endpoint (public, clears session)
	httpMux.HandleFunc("/auth/logout", oidcLogoutHandler)

	// Session status API (public, returns auth status)
	httpMux.HandleFunc("/api/session", sessionHandler)

	// Health check (public)
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Route: WebSocket shell endpoint (protected by OIDC middleware)
	httpMux.HandleFunc("/shell", func(w http.ResponseWriter, r *http.Request) {
		if !sessionCheck(r) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		// PBAC: DC2 requires shell:dc2 permission
		dc := r.URL.Query().Get("dc")
		if dc == "2" && !checkPermission(r, "shell:dc2") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden","message":"DC2 access requires admin group"}`))
			return
		}
		if cookie, err := r.Cookie("session_id"); err == nil {
			r.Header.Set("X-User", sessionStore.GetUser(cookie.Value))
		}
		shellHandler(w, r, vaultAddr)
	})

	// Route: Device SSH shell endpoint (protected by OIDC middleware)
	httpMux.HandleFunc("/shell/device", func(w http.ResponseWriter, r *http.Request) {
		if !sessionCheck(r) {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		deviceShellHandler(w, r, vaultAddr)
	})

	// Route: Tunnel proxy
	httpMux.HandleFunc("/tunnel/", tunnelMgr.TunnelHandler)

	// Route: Device heartbeat API
	httpMux.HandleFunc("/api/heartbeat", heartbeatHandler)

	// Route: Device list API
	httpMux.HandleFunc("/api/devices", devicesHandler)

	// Cert: issue (httpMux, requires OIDC session or mTLS)
	httpMux.HandleFunc("/api/cert/issue", certIssueHandler)

	// Cert: renew (mtlsMux, requires mTLS client cert)
	mtlsMux.HandleFunc("/api/cert/renew", certRenewHandler)

	// Start mTLS server on :9090 (existing behavior)
	mtlsServer := &http.Server{
		Addr:      ":9090",
		Handler:   mtlsMux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Go server mTLS starting on :9090")
	go func() {
		if err := mtlsServer.ListenAndServeTLS(serverCertFile, serverKeyFile); err != nil {
			log.Fatalf("mTLS server failed: %v", err)
		}
	}()

	// Start HTTP server on :9091 for web UI (browser-friendly, no client cert required)
	log.Printf("Web UI HTTP server starting on :9091")
	if err := http.ListenAndServe(":9091", httpMux); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

// sendWSMessage sends a text message over a WebSocket connection
func sendWSMessage(conn *websocket.Conn, msg string) {
	conn.WriteMessage(websocket.TextMessage, []byte(msg))
}

// shellHandler handles WebSocket connections for xterm terminal → SSH via Vault CA
// Supports ?dc=1 (default) or ?dc=2 for multi-datacenter isolation demo.
func shellHandler(w http.ResponseWriter, r *http.Request, vaultAddr string) {
	vaultToken := getVaultToken()
	// Determine which datacenter to connect to
	dc := r.URL.Query().Get("dc")
	if dc == "" {
		dc = "1"
	}

	var sshTarget, sshRole, sshUser string
	switch dc {
	case "2":
		sshTarget = "gateway-dc2:22"
		sshRole = "ssh-dc2/sign/sign-ssh"
		sshUser = "gateway-user"
	default: // "1"
		sshTarget = "go-client:22"
		sshRole = "ssh/sign/sign-ssh"
		sshUser = "gateway-user"
	}

	log.Printf("Shell connecting to %s with role %s (DC%s)", sshTarget, sshRole, dc)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Shell WS upgrade error: %v", err)
		return
	}
	defer conn.Close()
	log.Printf("Shell WS upgraded, starting SSH dial...")

	if vaultToken == "" {
		log.Printf("No vault token available, cannot sign SSH key")
		sendWSMessage(conn, "Vault SSH CA not available (no token)")
		return
	}

	// Step 1: Generate ephemeral SSH key pair
	sshKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("SSH key gen error: %v", err)
		sendWSMessage(conn, "Error generating SSH key")
		return
	}

	sshPubKey, err := ssh.NewPublicKey(&sshKey.PublicKey)
	if err != nil {
		log.Printf("SSH pub key error: %v", err)
		return
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	// Step 2: Sign public key with Vault SSH CA (DC-aware role)
	sshSignURL := fmt.Sprintf("%s/v1/%s", vaultAddr, sshRole)
	payload := map[string]string{
		"public_key":       string(pubKeyBytes),
		"valid_principals": sshUser,
		"ttl":              "4m",
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", sshSignURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("Failed to create Vault sign request: %v", err)
		sendWSMessage(conn, "Internal error")
		return
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		log.Printf("Vault SSH sign error: %v", err)
		sendWSMessage(conn, "Error signing SSH key with Vault")
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	signedKeyStr := ""
	if data, ok := result["data"].(map[string]interface{}); ok {
		signedKeyStr, _ = data["signed_key"].(string)
	}
	if signedKeyStr == "" {
		log.Printf("Failed to get signed key: %s", string(respBody))
		sendWSMessage(conn, "Failed to get SSH certificate from Vault")
		return
	}

	log.Printf("Shell SSH dial succeeded, creating session...")

	// Try Ed25519 key first (pre-deployed), fall back to signed certificate
	keySigner, err := ssh.NewSignerFromKey(sshKey)
	if err != nil {
		log.Printf("Failed to create key signer: %v", err)
		sendWSMessage(conn, "Failed to create SSH key signer")
		return
	}

	// Try Vault-signed certificate FIRST, Ed25519 key as fallback
	sshAuthMethod := ssh.PublicKeys(keySigner)
	parsedCert, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(signedKeyStr))
	if parseErr == nil {
		if cert, ok := parsedCert.(*ssh.Certificate); ok {
			certSigner, signErr := ssh.NewCertSigner(cert, keySigner)
			if signErr == nil {
				log.Printf("Using Vault-signed cert for SSH auth")
				sshAuthMethod = ssh.PublicKeys(certSigner)
			}
		}
	} else {
		// Fall back to Ed25519 key
		keyBytes, readErr := os.ReadFile("/app/keys/ssh-key")
		if readErr == nil {
			loadedKey, parseErr := ssh.ParsePrivateKey(keyBytes)
			if parseErr == nil {
				log.Printf("Using Ed25519 key for SSH auth (cert not available)")
				sshAuthMethod = ssh.PublicKeys(loadedKey)
			}
		}
	}

	// Step 4: Connect to SSH server (DC-aware target)
	sshConfig := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			sshAuthMethod,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", sshTarget, sshConfig)
	if err != nil {
		log.Printf("SSH dial error: %v", err)
		sendWSMessage(conn, fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Printf("SSH session error: %v", err)
		sendWSMessage(conn, "Failed to create SSH session")
		return
	}
	defer session.Close()

	// Set up terminal with PTY
	if err := session.RequestPty("vt100", 40, 80, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		log.Printf("PTY request error (non-fatal): %v", err)
	}
	// Start shell

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	// Start shell
	if err := session.Shell(); err != nil {
		log.Printf("SSH shell error: %v", err)
		sendWSMessage(conn, "Failed to start SSH shell")
		return
	}
	log.Printf("Shell started, launching data forwarders...")

	// WebSocket → SSH stdin (handle resize messages)
	go func() {
		defer stdin.Close()
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Check for resize messages
			var msg map[string]interface{}
			if json.Unmarshal(message, &msg) == nil {
				if msg["type"] == "resize" {
					cols := int(msg["cols"].(float64))
					rows := int(msg["rows"].(float64))
					session.WindowChange(rows, cols)
					continue
				}
			}
			log.Printf("WS→SSH: %d bytes", len(message))
			stdin.Write(message)
		}
	}()

	// SSH stdout → WebSocket (binary)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				log.Printf("SSH→WS: %d bytes [%q]", n, string(buf[:n]))
				conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// SSH stderr → WebSocket (binary)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for session to complete
	session.Wait()
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, config VaultConfig) {
	// Log client cert info
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		log.Printf("Client connected: %s", cert.Subject)
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}
	defer conn.Close()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			break
		}
		log.Printf("Received: %s", string(message))

		response := fmt.Sprintf("[server-echo]: %s", string(message))
		if err := conn.WriteMessage(websocket.TextMessage, []byte(response)); err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}
}

// ──────────────────────────────────────────────
// Device Manager — Device Registration & Heartbeat API
// ──────────────────────────────────────────────

// deviceManager is the global device manager instance
var deviceManager *DeviceManager

// Device represents a registered edge device
type Device struct {
	ID            string    `json:"id"`
	CertCN        string    `json:"cert_cn"`
	Label         string    `json:"label"`
	DC            string    `json:"dc"`
	SSHUser       string    `json:"ssh_user"`
	SSHTarget     string    `json:"ssh_target"`
	Online        bool      `json:"online"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	RegisteredAt  time.Time `json:"registered_at"`
}

// DeviceManager manages registered devices and their heartbeats
type DeviceManager struct {
	mu        sync.Mutex
	devices   map[string]*Device
	byCN      map[string]*Device
	nextID    int
	dc1CAKey  string
	dc2CAKey  string
}

// NewDeviceManager creates a new device manager
func NewDeviceManager() *DeviceManager {
	return &DeviceManager{
		devices: make(map[string]*Device),
		byCN:    make(map[string]*Device),
		nextID:  1,
	}
}

// SetCAKeys sets the SSH CA public keys for DC1 and DC2
func (dm *DeviceManager) SetCAKeys(dc1, dc2 string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.dc1CAKey = dc1
	dm.dc2CAKey = dc2
}

// Register registers a device by certificate CN, label, and datacenter
func (dm *DeviceManager) Register(certCN string, label string, dc string) *Device {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Check if CN already registered
	if existing, ok := dm.byCN[certCN]; ok {
		existing.Label = label
		existing.DC = dc
		existing.Online = true
		existing.LastHeartbeat = time.Now()
		return existing
	}

	id := fmt.Sprintf("dev-%04d", dm.nextID)
	dm.nextID++

	var sshTarget string
	if dc == "2" {
		sshTarget = "gateway-dc2:22"
	} else {
		sshTarget = "go-client:22"
	}

	device := &Device{
		ID:            id,
		CertCN:        certCN,
		Label:         label,
		DC:            dc,
		SSHUser:       "gateway-user",
		SSHTarget:     sshTarget,
		Online:        true,
		LastHeartbeat: time.Now(),
		RegisteredAt:  time.Now(),
	}

	dm.devices[id] = device
	dm.byCN[certCN] = device
	return device
}

// Heartbeat updates the heartbeat timestamp for a device
func (dm *DeviceManager) Heartbeat(deviceID string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dev, ok := dm.devices[deviceID]; ok {
		dev.Online = true
		dev.LastHeartbeat = time.Now()
	}
}

// HeartbeatChecker runs a goroutine that marks devices offline after 90s of no heartbeat
func (dm *DeviceManager) HeartbeatChecker() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			dm.mu.Lock()
			now := time.Now()
			for _, dev := range dm.devices {
				if now.Sub(dev.LastHeartbeat) > 90*time.Second {
					dev.Online = false
				}
			}
			dm.mu.Unlock()
		}
	}()
}

// GetAll returns all registered devices
func (dm *DeviceManager) GetAll() []Device {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	result := make([]Device, 0, len(dm.devices))
	for _, dev := range dm.devices {
		result = append(result, *dev)
	}
	return result
}

// GetByID returns a device by ID, or nil if not found
func (dm *DeviceManager) GetByID(id string) *Device {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dev, ok := dm.devices[id]
	if !ok {
		return nil
	}
	// Return a copy to avoid data races
	copy := *dev
	return &copy
}

// initDeviceManager initializes the global device manager and loads SSH CA keys
func initDeviceManager(vaultAddr, vaultToken string) {
	deviceManager = NewDeviceManager()

	// Load SSH CA public keys from Vault
	dc1CA := getSSHCAKey(vaultAddr, vaultToken, "ssh/config/ca")
	dc2CA := getSSHCAKey(vaultAddr, vaultToken, "ssh-dc2/config/ca")

	deviceManager.SetCAKeys(dc1CA, dc2CA)

	// Start heartbeat checker
	deviceManager.HeartbeatChecker()

	log.Printf("Device manager initialized (DC1 CA: %v, DC2 CA: %v)", dc1CA != "", dc2CA != "")
}

// getSSHCAKey fetches an SSH CA public key from Vault
func getSSHCAKey(addr, token, path string) string {
	url := fmt.Sprintf("%s/v1/%s", addr, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create request for %s: %v", path, err)
		return ""
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		log.Printf("Failed to read SSH CA key from %s: %v", path, err)
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	if data, ok := result["data"].(map[string]interface{}); ok {
		if pk, ok := data["public_key"].(string); ok {
			return pk
		}
	}
	log.Printf("No public_key found in %s response", path)
	return ""
}

// whoamiHandler handles GET /api/whoami — returns user identity from client cert
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	var username string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		username = cert.Subject.CommonName
		log.Printf("[whoami] User authenticated via client cert: CN=%s", username)
	} else {
		username = "anonymous"
	}

	// Resolve identity from certificate CN
	identity := resolveIdentityFromCertCN(username)
	groups := []string{}
	resolvedName := username
	if identity != nil {
		groups = identity.Groups
		resolvedName = identity.Username
	}

	// Try to get permissions from DB if available
	var permissions []string
	if permStore != nil {
		perms, err := permStore.GetUserPermissions(resolvedName)
		if err == nil {
			permissions = perms
		} else {
			log.Printf("[whoami] DB lookup failed for %s: %v", resolvedName, err)
		}
	}

	resp := map[string]interface{}{
		"username":      username,
		"resolved_name": resolvedName,
		"groups":        groups,
		"permissions":   permissions,
		"auth_method":   "client_cert",
		"cn":            username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}


// registerHandler handles POST /api/register (mTLS required)
// ===== Certificate Self-Service =====

// groupToPolicy maps OIDC groups to Vault policies (for cert auth role binding)
var groupToPolicy = map[string]string{
	"admin-group": "admin-policy",
	"ops-group":   "ops-policy",
	"dev-group":   "dev-policy",
}

// certIssueHandler handles POST /api/cert/issue — issues a personal certificate via Vault PKI
// Auth: OIDC session cookie OR mTLS client cert
// Flow: getUserIdentity -> Vault PKI issue -> create/update cert auth role -> return cert
func certIssueHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate — get user identity
	var username string
	var groups []string

	// Check mTLS cert first (X-Forwarded-Ssl-Client-DN from nginx)
	clientDN := r.Header.Get("X-Forwarded-Ssl-Client-DN")
	if clientDN != "" {
		if idx := strings.Index(clientDN, "CN="); idx >= 0 {
			cnPart := clientDN[idx+3:]
			if end := strings.IndexAny(cnPart, ",;"); end >= 0 {
				cnPart = strings.TrimSpace(cnPart[:end])
			} else {
				cnPart = strings.TrimSpace(cnPart)
			}
			if cnPart != "" {
				identity := resolveIdentityFromCertCN(cnPart)
				username = identity.Username
				groups = identity.Groups
			}
		}
	}

	// Fall back to OIDC session cookie
	if username == "" {
		cookie, err := r.Cookie("session_id")
		if err == nil && sessionStore.IsValid(cookie.Value) {
			username = sessionStore.GetUser(cookie.Value)
			groups = sessionStore.GetGroups(cookie.Value)
		}
	}

	if username == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"Login required"}`))
		return
	}

	log.Printf("[cert] Issue request for user=%s groups=%v", username, groups)

	// 2. Build CN = username@lab.local
	commonName := username + "@lab.local"
	ttl := "720h" // 30 days

	// 3. Call Vault PKI to issue certificate
	token := getVaultToken()
	if token == "" {
		log.Printf("[cert] No Vault token available")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"vault_unavailable","message":"Vault token not available"}`))
		return
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://vault:8200"
	}

	// Prepare request body for Vault PKI
	issueReq := map[string]interface{}{
		"common_name":       commonName,
		"alt_names":         "",
		"ttl":               ttl,
		"format":            "pem",
		"private_key_format": "pem",
		"key_type":          "rsa",
		"key_bits":          2048,
	}
	issueBody, _ := json.Marshal(issueReq)

	req, err := http.NewRequest("POST", vaultAddr+"/v1/pki/issue/user", bytes.NewReader(issueBody))
	if err != nil {
		log.Printf("[cert] Failed to create request: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
		return
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		log.Printf("[cert] Vault PKI issue failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"vault_error","message":"Failed to issue certificate from Vault"}`))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var vaultResp map[string]interface{}
	json.Unmarshal(body, &vaultResp)

	if resp.StatusCode != 200 {
		log.Printf("[cert] Vault PKI error: %s", string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(fmt.Sprintf(`{"error":"vault_error","detail":%s}`, string(body))))
		return
	}

	data, ok := vaultResp["data"].(map[string]interface{})
	if !ok {
		log.Printf("[cert] Unexpected Vault response format")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"vault_response_error"}`))
		return
	}

	// 4. Create/update Vault cert auth role for this user
	// Determine which Vault policy to assign based on user groups
	vaultPolicies := getVaultPoliciesForGroups(groups)
	if err := ensureCertAuthRole(username, commonName, vaultPolicies); err != nil {
		log.Printf("[cert] Warning: failed to update cert auth role: %v", err)
		// Non-fatal — user can still download cert
	}

	// 5. Build response
	response := map[string]interface{}{
		"certificate":   data["certificate"],
		"private_key":   data["private_key"],
		"issuing_ca":    data["issuing_ca"],
		"ca_chain":      data["ca_chain"],
		"serial_number": data["serial_number"],
		"expiration":    data["expiration"],
		"common_name":   commonName,
		"username":      username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("[cert] Issued cert for %s (CN=%s)", username, commonName)
}

// getVaultPoliciesForGroups maps user RBAC groups to Vault policies
func getVaultPoliciesForGroups(groups []string) []string {
	policies := []string{}
	seen := map[string]bool{}
	for _, g := range groups {
		if p, ok := groupToPolicy[g]; ok && !seen[p] {
			policies = append(policies, p)
			seen[p] = true
		}
	}
	if len(policies) == 0 {
		policies = append(policies, "dev-policy")
	}
	return policies
}

// ensureCertAuthRole creates or updates the Vault cert auth role for a user
func ensureCertAuthRole(username, commonName string, policies []string) error {
	token := getVaultToken()
	if token == "" {
		return fmt.Errorf("no vault token")
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://vault:8200"
	}

	// First check if role exists
	roleName := "personal-" + username
	rolePath := "/v1/auth/cert/certs/" + roleName

	// Read ca-chain.crt for the certificate field
	caChain, err := os.ReadFile("certs/ca-chain.crt")
	if err != nil {
		// Fall back to all-chain.crt
		caChain, err = os.ReadFile("certs/all-chain.crt")
		if err != nil {
			return fmt.Errorf("failed to read CA chain: %w", err)
		}
	}

	roleReq := map[string]interface{}{
		"certificate":           string(caChain),
		"allowed_common_names": []string{commonName},
		"token_policies":        policies,
		"token_ttl":             "86400",
		"token_type":            "service",
	}
	roleBody, _ := json.Marshal(roleReq)

	req, err := http.NewRequest("POST", vaultAddr+rolePath, bytes.NewReader(roleBody))
	if err != nil {
		return fmt.Errorf("failed to create role request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to write cert auth role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[cert] Cert auth role '%s' updated for CN=%s policies=%v", roleName, commonName, policies)
	return nil
}

// certRenewHandler handles POST /api/cert/renew — renews a certificate via mTLS auth
// Auth: mTLS client cert (verified by nginx/go-server)
// Flow: extract CN from mTLS cert -> re-issue via Vault PKI -> return new cert
func certRenewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Extract CN from mTLS cert
	var commonName string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		commonName = r.TLS.PeerCertificates[0].Subject.CommonName
	} else {
		// Also check header (nginx proxy path)
		clientDN := r.Header.Get("X-Forwarded-Ssl-Client-DN")
		if clientDN != "" {
			if idx := strings.Index(clientDN, "CN="); idx >= 0 {
				cnPart := clientDN[idx+3:]
				if end := strings.IndexAny(cnPart, ",;"); end >= 0 {
					commonName = strings.TrimSpace(cnPart[:end])
				} else {
					commonName = strings.TrimSpace(cnPart)
				}
			}
		}
	}

	if commonName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"Client certificate required"}`))
		return
	}

	log.Printf("[cert] Renew request for CN=%s", commonName)

	// Call Vault PKI to re-issue
	token := getVaultToken()
	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"vault_unavailable"}`))
		return
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://vault:8200"
	}

	ttl := "2160h" // 90 days for renewal (longer than initial issue)

	// Check if old cert is about to expire — if so use shorter TTL
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		timeLeft := time.Until(r.TLS.PeerCertificates[0].NotAfter)
		if timeLeft < 24*time.Hour {
			ttl = "720h" // 30 days if expiring soon
		}
	}

	issueReq := map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
		"key_type":    "rsa",
		"key_bits":    2048,
	}
	issueBody, _ := json.Marshal(issueReq)

	req, err := http.NewRequest("POST", vaultAddr+"/v1/pki/issue/user", bytes.NewReader(issueBody))
	if err != nil {
		log.Printf("[cert] Renew: request error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
		return
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		log.Printf("[cert] Renew: Vault error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"vault_error"}`))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var vaultResp map[string]interface{}
	json.Unmarshal(body, &vaultResp)

	if resp.StatusCode != 200 {
		log.Printf("[cert] Renew: Vault PKI error: %s", string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(fmt.Sprintf(`{"error":"vault_error","detail":%s}`, string(body))))
		return
	}

	data, ok := vaultResp["data"].(map[string]interface{})
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"vault_response_error"}`))
		return
	}

	response := map[string]interface{}{
		"certificate":   data["certificate"],
		"issuing_ca":    data["issuing_ca"],
		"ca_chain":      data["ca_chain"],
		"serial_number": data["serial_number"],
		"expiration":    data["expiration"],
		"common_name":   commonName,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("[cert] Renewed cert for CN=%s (expires in %s)", commonName, ttl)
}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require mTLS — extract client cert CN
	var certCN string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		certCN = r.TLS.PeerCertificates[0].Subject.CommonName
	} else {
		http.Error(w, `{"error":"mTLS required"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Label string `json:"label"`
		DC    string `json:"dc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.DC == "" {
		req.DC = "1"
	}
	if req.Label == "" {
		req.Label = certCN
	}

	device := deviceManager.Register(certCN, req.Label, req.DC)

	// Get the appropriate SSH CA key
	deviceManager.mu.Lock()
	var sshCAKey string
	if device.DC == "2" {
		sshCAKey = deviceManager.dc2CAKey
	} else {
		sshCAKey = deviceManager.dc1CAKey
	}
	deviceManager.mu.Unlock()

	resp := map[string]interface{}{
		"device_id":      device.ID,
		"cert_cn":        device.CertCN,
		"ssh_ca_pub_key": sshCAKey,
		"ssh_target":     device.SSHTarget,
		"ssh_user":       device.SSHUser,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("Device registered: %s (CN=%s, DC=%s, SSH=%s)", device.ID, certCN, req.DC, device.SSHTarget)
}

// heartbeatHandler handles POST /api/heartbeat
func heartbeatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" {
		http.Error(w, `{"error":"device_id required"}`, http.StatusBadRequest)
		return
	}

	deviceManager.Heartbeat(req.DeviceID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// devicesHandler handles GET /api/devices
func devicesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deviceManager.GetAll())
}

// deviceShellHandler handles WebSocket connections for SSH to a registered device
func deviceShellHandler(w http.ResponseWriter, r *http.Request, vaultAddr string) {
	vaultToken := getVaultToken()
	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}

	// Look up device
	device := deviceManager.GetByID(deviceID)
	if device == nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	if !device.Online {
		http.Error(w, "device offline", http.StatusServiceUnavailable)
		return
	}

	log.Printf("Device shell: connecting to %s (%s)", device.ID, device.SSHTarget)

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Device shell WS upgrade error: %v", err)
		return
	}
	defer conn.Close()

	if vaultToken == "" {
		log.Printf("No vault token available, cannot sign SSH key")
		sendWSMessage(conn, "Vault SSH CA not available (no token)")
		return
	}

	// Determine which SSH CA role to use based on device DC
	var sshRole string
	if device.DC == "2" {
		sshRole = "ssh-dc2/sign/sign-ssh"
	} else {
		sshRole = "ssh/sign/sign-ssh"
	}

	// Generate ephemeral SSH key pair
	sshKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Device shell key gen error: %v", err)
		sendWSMessage(conn, "Error generating SSH key")
		return
	}

	sshPubKey, err := ssh.NewPublicKey(&sshKey.PublicKey)
	if err != nil {
		log.Printf("Device shell pub key error: %v", err)
		return
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	// Sign with Vault SSH CA
	sshSignURL := fmt.Sprintf("%s/v1/%s", vaultAddr, sshRole)
	payload := map[string]string{
		"public_key":       string(pubKeyBytes),
		"valid_principals": device.SSHUser,
		"ttl":              "4m",
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", sshSignURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("Device shell vault request error: %v", err)
		sendWSMessage(conn, "Internal error")
		return
	}
	req.Header.Set("X-Vault-Token", vaultToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		log.Printf("Device shell vault sign error: %v", err)
		sendWSMessage(conn, "Error signing SSH key with Vault")
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	signedKeyStr := ""
	if data, ok := result["data"].(map[string]interface{}); ok {
		signedKeyStr, _ = data["signed_key"].(string)
	}
	if signedKeyStr == "" {
		log.Printf("Device shell failed to get signed key: %s", string(respBody))
		sendWSMessage(conn, "Failed to get SSH certificate from Vault")
		return
	}

	// Parse the signed certificate
	parsedCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKeyStr))
	if err != nil {
		log.Printf("Device shell cert parse error: %v", err)
		sendWSMessage(conn, "Failed to parse SSH certificate")
		return
	}

	cert, ok := parsedCert.(*ssh.Certificate)
	if !ok {
		log.Printf("Device shell: parsed key is not a certificate")
		sendWSMessage(conn, "Parsed key is not a certificate")
		return
	}

	keySigner, err := ssh.NewSignerFromKey(sshKey)
	if err != nil {
		log.Printf("Device shell key signer error: %v", err)
		sendWSMessage(conn, "Failed to create SSH key signer")
		return
	}

	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		log.Printf("Device shell cert signer error: %v", err)
		sendWSMessage(conn, "Failed to create SSH cert signer")
		return
	}

	// Connect to the device via SSH
	sshConfig := &ssh.ClientConfig{
		User:            device.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", device.SSHTarget, sshConfig)
	if err != nil {
		log.Printf("Device shell SSH dial to %s error: %v", device.SSHTarget, err)
		sendWSMessage(conn, fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Printf("Device shell session error: %v", err)
		sendWSMessage(conn, "Failed to create SSH session")
		return
	}
	defer session.Close()

	// Set up terminal with PTY
	if err := session.RequestPty("vt100", 40, 80, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		log.Printf("PTY request error (non-fatal): %v", err)
	}
	// Start shell

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	if err := session.Shell(); err != nil {
		log.Printf("Device shell error: %v", err)
		sendWSMessage(conn, "Failed to start SSH shell")
		return
	}

	// WebSocket → SSH stdin
	go func() {
		defer stdin.Close()
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Check for resize messages
			var msg map[string]interface{}
			if json.Unmarshal(message, &msg) == nil {
				if msg["type"] == "resize" {
					cols := int(msg["cols"].(float64))
					rows := int(msg["rows"].(float64))
					session.WindowChange(rows, cols)
					continue
				}
			}
			log.Printf("WS→SSH: %d bytes", len(message))
			stdin.Write(message)
		}
	}()

	// SSH stdout → WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// SSH stderr → WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	session.Wait()
}

// ===== OIDC Handlers =====

// initOIDC initializes the OIDC provider connection (non-fatal if unavailable)
func initOIDC() error {
	ctx := context.Background()

	// Authentik OIDC discovery URL
	providerURL := "http://auth.lab.local:9000/application/o/go-server/"

	var err error
	log.Printf("OIDC init: fetching discovery from %s", providerURL)
	oidcProvider, err = oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return fmt.Errorf("OIDC provider discovery from %s: %w", providerURL, err)
	}
	log.Printf("OIDC init: discovery OK, token endpoint: %s", oidcProvider.Endpoint().TokenURL)

	oauthConfig = &oauth2.Config{
		ClientID:     "go-server-client-id",
		ClientSecret: "go-server-client-secret",
		RedirectURL:  "http://web.lab.local:9091/auth/callback",
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcVerifier = oidcProvider.Verifier(&oidc.Config{ClientID: "go-server-client-id"})

	return nil
}

// oidcCallbackHandler handles the OIDC redirect from the identity provider
func oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Exchange auth code for token
	code := r.URL.Query().Get("code")
	log.Printf("OIDC token exchange: code=%s..., redirect_uri=%s, client_id=%s", 
		code[:min(len(code),8)], oauthConfig.RedirectURL, oauthConfig.ClientID)
	oauth2Token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("OIDC token exchange error: %v", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// Verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Printf("OIDC: no id_token in response")
		http.Error(w, "No id_token", http.StatusInternalServerError)
		return
	}

	idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("OIDC token verification error: %v", err)
		http.Error(w, "Token verification failed", http.StatusInternalServerError)
		return
	}

	// Extract claims
	var claims struct {
		Sub    string   `json:"sub"`
		Name   string   `json:"name"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("OIDC claims error: %v", err)
		http.Error(w, "Claims extraction failed", http.StatusInternalServerError)
		return
	}

	// Try UserInfo endpoint for more user details
	userInfo, err := oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err == nil {
		var uiClaims struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := userInfo.Claims(&uiClaims); err == nil {
			if uiClaims.Name != "" {
				claims.Name = uiClaims.Name
			}
			if uiClaims.Email != "" {
				claims.Email = uiClaims.Email
			}
		}
	}

	// Use email or sub as fallback username when name is empty
	username := claims.Name
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Sub
	}

	// Create session
	session := sessionStore.Create(username, claims.Email, claims.Groups)

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600,
	})

	log.Printf("OIDC login: user=%s email=%s groups=%v", claims.Name, claims.Email, claims.Groups)

	// Redirect to Web UI
	http.Redirect(w, r, "/", http.StatusFound)
}

// sessionCheck checks if the request has a valid session cookie
func sessionCheck(r *http.Request) bool {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return false
	}
	if !sessionStore.IsValid(cookie.Value) {
		return false
	}
	// Reject sessions with empty username (partial login)
	return sessionStore.GetUser(cookie.Value) != ""
}

// oidcLogoutHandler clears the session and redirects to Authentik
func oidcLogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	// Redirect to Authentik end-session endpoint
	http.Redirect(w, r, "http://auth.lab.local:9000/application/o/go-server/end-session/", http.StatusFound)
}

// sessionHandler returns the current session status including groups
func sessionHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"authenticated": false,
	}

	cookie, err := r.Cookie("session_id")
	if err == nil && sessionStore.IsValid(cookie.Value) {
		user := sessionStore.GetUser(cookie.Value)
		groups := sessionStore.GetGroups(cookie.Value)
		if user != "" {
			resp["authenticated"] = true
			resp["user"] = user
			resp["groups"] = groups
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ──────────────────────────────────────────────
// Tunnel Manager — SSH port forwarding through gateway
// ──────────────────────────────────────────────

// TunnelManager manages SSH tunnels through gateway
type TunnelManager struct {
	mu         sync.Mutex
	tunnels    map[int]*Tunnel
	nextID     int
	vaultAddr  string
	httpMux    *http.ServeMux
}

// Tunnel represents an SSH tunnel through gateway
type Tunnel struct {
	ID          int    `json:"id"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	client      *ssh.Client
	stopCh      chan struct{}
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(vaultAddr string, httpMux *http.ServeMux) *TunnelManager {
	return &TunnelManager{
		tunnels:   make(map[int]*Tunnel),
		nextID:     1,
		vaultAddr:  vaultAddr,
		httpMux:    httpMux,
	}
}

// handleCreateTunnel handles POST /api/tunnel
func (tm *TunnelManager) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetHost  string `json:"target_host"`
		TargetPort  int    `json:"target_port"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.TargetHost == "" || req.TargetPort == 0 {
		http.Error(w, `{"error":"target_host and target_port required"}`, http.StatusBadRequest)
		return
	}
	if req.Description == "" {
		req.Description = fmt.Sprintf("%s:%d", req.TargetHost, req.TargetPort)
	}

	tunnel, err := tm.createTunnel(req.TargetHost, req.TargetPort, req.Description)
	if err != nil {
		log.Printf("Tunnel creation error: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tunnel)
}

// TunnelHandler handles HTTP requests to /tunnel/<id>/ by proxying through SSH
func (tm *TunnelManager) TunnelHandler(w http.ResponseWriter, r *http.Request) {
	// Extract tunnel ID from path: /tunnel/<id>/...
	idStr := strings.TrimPrefix(r.URL.Path, "/tunnel/")
	parts := strings.SplitN(idStr, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "tunnel ID required", http.StatusBadRequest)
		return
	}

	var id int
	if _, err := fmt.Sscanf(parts[0], "%d", &id); err != nil {
		http.Error(w, "invalid tunnel ID", http.StatusBadRequest)
		return
	}

	tm.mu.Lock()
	tunnel, ok := tm.tunnels[id]
	tm.mu.Unlock()

	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	// Build target URL from the original request path
	targetPath := ""
	if idx := strings.Index(r.URL.Path, "/tunnel/"); idx >= 0 {
		afterID := strings.TrimPrefix(r.URL.Path[idx:], fmt.Sprintf("/tunnel/%d", id))
		if afterID == "" || afterID == "/" {
			targetPath = "/"
		} else {
			targetPath = afterID
		}
	} else {
		targetPath = "/"
	}

	targetURL := fmt.Sprintf("http://%s:%d%s", tunnel.TargetHost, tunnel.TargetPort, targetPath)

	// Create a reverse proxy that dials through the SSH connection
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL, _ = url.Parse(targetURL)
			req.Host = fmt.Sprintf("%s:%d", tunnel.TargetHost, tunnel.TargetPort)
			// Preserve original headers
			for k, v := range r.Header {
				if k != "Connection" {
					req.Header[k] = v
				}
			}
		},
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				// Dial through the SSH tunnel to the target
				targetAddr := fmt.Sprintf("%s:%d", tunnel.TargetHost, tunnel.TargetPort)
				log.Printf("Tunnel %d: dialing %s through SSH", id, targetAddr)
				conn, err := tunnel.client.Dial("tcp", targetAddr)
				if err != nil {
					log.Printf("Tunnel %d: remote dial failed: %v", id, err)
					return nil, err
				}
				log.Printf("Tunnel %d: SSH dial succeeded", id)
				return conn, nil
			},
		},
		ErrorLog: log.Default(),
	}

	proxy.ServeHTTP(w, r)
}

// createTunnel creates a new SSH tunnel through gateway to target:port
func (tm *TunnelManager) createTunnel(targetHost string, targetPort int, description string) (*Tunnel, error) {
	tm.mu.Lock()
	id := tm.nextID
	tm.nextID++
	tm.mu.Unlock()

	// Generate SSH key pair and sign with Vault
	sshKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	sshPubKey, err := ssh.NewPublicKey(&sshKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("public key error: %w", err)
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	// Sign with Vault SSH CA
	signedKey, err := tm.signSSHKey(string(pubKeyBytes), "gateway-user", "10m")
	if err != nil {
		return nil, fmt.Errorf("vault signing failed: %w", err)
	}

	// Parse certificate
	parsedCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKey))
	if err != nil {
		return nil, fmt.Errorf("cert parsing failed: %w", err)
	}
	cert, ok := parsedCert.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate")
	}

	keySigner, err := ssh.NewSignerFromKey(sshKey)
	if err != nil {
		return nil, fmt.Errorf("key signer error: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		return nil, fmt.Errorf("cert signer error: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            "gateway-user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	gatewayClient, err := ssh.Dial("tcp", "gateway:22", sshConfig)
	if err != nil {
		return nil, fmt.Errorf("gateway connection failed: %w", err)
	}

	stopCh := make(chan struct{})

	tunnel := &Tunnel{
		ID:          id,
		TargetHost:  targetHost,
		TargetPort:  targetPort,
		Description: description,
		URL:         fmt.Sprintf("http://web.lab.local:9091/tunnel/%d/", id),
		Status:      "active",
		client:      gatewayClient,
		stopCh:      stopCh,
	}

	tm.mu.Lock()
	tm.tunnels[id] = tunnel
	tm.mu.Unlock()

	// Register HTTP handler for this tunnel on the HTTP mux
	pattern := fmt.Sprintf("/tunnel/%d/", id)
	tm.httpMux.HandleFunc(pattern, tm.TunnelHandler)

	log.Printf("Tunnel %d created: /tunnel/%d/ → gateway → %s:%d", id, id, targetHost, targetPort)
	return tunnel, nil
}

// signSSHKey signs a public key with Vault SSH CA
func (tm *TunnelManager) signSSHKey(publicKey, validPrincipals, ttl string) (string, error) {
	sshSignURL := fmt.Sprintf("%s/v1/ssh/sign/sign-ssh", tm.vaultAddr)
	payload := map[string]string{
		"public_key":       publicKey,
		"valid_principals": validPrincipals,
		"ttl":              ttl,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", sshSignURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", getVaultToken())
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	if data, ok := result["data"].(map[string]interface{}); ok {
		if signedKey, ok := data["signed_key"].(string); ok {
			return signedKey, nil
		}
	}
	return "", fmt.Errorf("vault signing failed: %s", string(respBody))
}

// newVaultHTTPClient creates an HTTP client that skips TLS verification
// for connecting to Vault's -dev-tls self-signed certificate.
func newVaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func readVaultConfig(addr, token string) VaultConfig {
	url := fmt.Sprintf("%s/v1/kv/data/server-config", addr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create Vault request: %v", err)
		return VaultConfig{}
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		log.Printf("Failed to read Vault config: %v", err)
		return VaultConfig{}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	if data, ok := result["data"].(map[string]interface{}); ok {
		if d, ok := data["data"].(map[string]interface{}); ok {
			return VaultConfig{
				APIKey:     getString(d, "api_key"),
				DBPassword: getString(d, "db_password"),
			}
		}
	}
	return VaultConfig{}
}

// loginWithCert authenticates to Vault using TLS client certificate authentication.
// server.crt is signed by Vault PKI Intermediate CA (CN=go-server), which maps to
// the server-policy in Vault's cert auth configuration.
func loginWithCert(vaultAddr, certFile, keyFile, caCertFile string) (string, error) {
	// Load client cert for mTLS
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", fmt.Errorf("failed to load client cert: %w", err)
	}

	// Load CA cert chain for Vault server verification
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return "", fmt.Errorf("failed to read CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config with client cert for Vault mTLS auth
	// Note: InsecureSkipVerify is needed for Vault's -dev-tls self-signed cert.
	// In production, replace with proper RootCAs verification.
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
		ServerName:         "vault",
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}

	// POST to Vault cert login endpoint
	url := fmt.Sprintf("%s/v1/auth/cert/login", vaultAddr)

	resp, err := client.Post(url, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", fmt.Errorf("cert login failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	if auth, ok := result["auth"].(map[string]interface{}); ok {
		if token, ok := auth["client_token"].(string); ok {
			log.Printf("mTLS cert login successful (CN=go-server)")
			return token, nil
		}
	}

	return "", fmt.Errorf("failed to extract client_token from cert login: %s", string(respBody))
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func maskString(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// The readAppRoleCredentials and loginAppRole functions have been removed.
// Vault authentication is now done via TLS client certificate (loginWithCert).
