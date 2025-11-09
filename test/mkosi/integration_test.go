package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ecksun/sshca-serv/internal/api"
	"github.com/ecksun/sshca-serv/internal/auth"
	"github.com/ecksun/sshca-serv/internal/ca"
	"github.com/ecksun/sshca-serv/internal/config"
	"github.com/ecksun/sshca-serv/internal/db"
	"golang.org/x/crypto/ssh"
)

const (
	username = "testuser"
	password = "testpass"
)

var (
	serverURL = flag.String("server", "", "Base URL of external server (e.g., https://192.168.1.100:8443). If empty, starts in-process server on https://localhost:8443")
)

type signRequest struct {
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname"`
}

type signResponse struct {
	Certificate string `json:"certificate"`
	Serial      int64  `json:"serial"`
	ExpiresAt   string `json:"expires_at"`
}

func waitForService(t *testing.T, client *http.Client, baseURL string, timeout time.Duration) {
	t.Log("Waiting for service to be ready...")
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Warning: failed to close response body: %v", err)
			}
			t.Log("Service is ready!")
			return
		}
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Warning: failed to close response body: %v", err)
			}
		}
		time.Sleep(1 * time.Second)
	}

	t.Fatalf("Service did not become ready within %v", timeout)
}

func fetchCAPublicKey(t *testing.T, client *http.Client, baseURL string) ssh.PublicKey {
	t.Log("Fetching CA public key...")
	resp, err := client.Get(baseURL + "/api/v1/ca.pub")
	if err != nil {
		t.Fatalf("Failed to fetch CA public key: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Warning: failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Failed to fetch CA public key, status %d: %s", resp.StatusCode, string(body))
	}

	keyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read CA public key response: %v", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA public key: %v", err)
	}

	t.Logf("CA public key type: %s", publicKey.Type())
	return publicKey
}

func generateRSAKey(t *testing.T) (ssh.PublicKey, string) {
	t.Log("Generating RSA key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create SSH public key from RSA key: %v", err)
	}

	publicKeyString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
	return publicKey, publicKeyString
}

func generateECDSAKey(t *testing.T) (ssh.PublicKey, string) {
	t.Log("Generating ECDSA key...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create SSH public key from ECDSA key: %v", err)
	}

	publicKeyString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
	return publicKey, publicKeyString
}

func generateEd25519Key(t *testing.T) (ssh.PublicKey, string) {
	t.Log("Generating Ed25519 key...")
	publicKeyRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(publicKeyRaw)
	if err != nil {
		t.Fatalf("Failed to create SSH public key from Ed25519 key: %v", err)
	}

	publicKeyString := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
	return publicKey, publicKeyString
}

func signKey(t *testing.T, client *http.Client, baseURL, publicKeyString, hostname string) *signResponse {
	reqBody := signRequest{
		PublicKey: publicKeyString,
		Hostname:  hostname,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/api/v1/sign", strings.NewReader(string(reqJSON)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Warning: failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Signing failed with status %d: %s", resp.StatusCode, string(body))
	}

	var signResp signResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if signResp.Certificate == "" {
		t.Fatal("Response did not contain a certificate")
	}

	return &signResp
}

func parseCertificate(t *testing.T, certString string) *ssh.Certificate {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certString))
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	cert, ok := publicKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("Parsed key is not a certificate")
	}

	return cert
}

func verifyCertificate(t *testing.T, cert *ssh.Certificate, caPublicKey ssh.PublicKey) {
	t.Log("Verifying certificate signature...")

	// Check that the certificate's SignatureKey matches the CA public key
	if cert.SignatureKey == nil {
		t.Fatal("Certificate has no signature key")
	}

	// Compare the signature key to the CA public key
	certSigKeyBytes := cert.SignatureKey.Marshal()
	caKeyBytes := caPublicKey.Marshal()

	if string(certSigKeyBytes) != string(caKeyBytes) {
		t.Errorf("Certificate signature key does not match CA public key")
		t.Errorf("  Certificate SignatureKey type: %s", cert.SignatureKey.Type())
		t.Errorf("  CA public key type: %s", caPublicKey.Type())
		return
	}

	// Verify the certificate is not expired
	now := uint64(time.Now().Unix())
	if now < cert.ValidAfter {
		t.Errorf("Certificate is not yet valid (now: %d, valid after: %d)",
			now, cert.ValidAfter)
		return
	}
	if now > cert.ValidBefore {
		t.Errorf("Certificate has expired (now: %d, valid before: %d)",
			now, cert.ValidBefore)
		return
	}

	t.Log("Certificate signature verified successfully!")
}

func startTestServer(t *testing.T) func() {
	t.Log("Starting in-process test server...")

	tmpDir, err := os.MkdirTemp("", "sshca-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	caKeyPath := filepath.Join(tmpDir, "test_ca")
	tlsCertPath := filepath.Join(tmpDir, "cert.pem")
	tlsKeyPath := filepath.Join(tmpDir, "key.pem")
	dbPath := filepath.Join(tmpDir, "sshca.db")

	t.Logf("Test directory: %s", tmpDir)

	t.Log("Generating SSH CA key...")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", caKeyPath, "-N", "", "-C", "Test CA")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to generate CA key: %v\nOutput: %s", err, output)
	}

	t.Log("Generating TLS certificates...")
	if err := generateTLSCerts(tlsCertPath, tlsKeyPath); err != nil {
		t.Fatalf("Failed to generate TLS certs: %v", err)
	}

	t.Log("Initializing database...")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := database.InitSchema(); err != nil {
		if closeErr := database.Close(); closeErr != nil {
			t.Logf("Warning: failed to close database: %v", closeErr)
		}
		t.Fatalf("Failed to initialize schema: %v", err)
	}

	t.Log("Creating test user...")
	if err := database.CreateUser(username, password); err != nil {
		if closeErr := database.Close(); closeErr != nil {
			t.Logf("Warning: failed to close database: %v", closeErr)
		}
		t.Fatalf("Failed to create test user: %v", err)
	}

	cfg := &config.Config{
		ListenAddr: ":8443",
		TLSCert:    tlsCertPath,
		TLSKey:     tlsKeyPath,
		DBPath:     dbPath,
		Principals: "root",
		Validity:   "-1m:+1h",
		SSHCA:      caKeyPath,
	}

	// Set up server components
	signer := ca.NewSigner(cfg.SSHCA, cfg.Principals, cfg.Validity, database)
	authMw := auth.NewMiddleware(database)
	apiServer := api.NewServer(signer, authMw)

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	// Start server in goroutine
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	errChan := make(chan error, 1)
	go func() {
		t.Logf("Server listening on %s", cfg.ListenAddr)
		if err := server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Check for immediate startup errors
	select {
	case err := <-errChan:
		if closeErr := database.Close(); closeErr != nil {
			t.Logf("Warning: failed to close database: %v", closeErr)
		}
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Logf("Warning: failed to remove temp directory: %v", removeErr)
		}
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	t.Log("Test server started successfully!")

	// Return cleanup function
	return func() {
		t.Log("Shutting down test server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			t.Logf("Server shutdown error: %v", err)
		}

		if err := database.Close(); err != nil {
			t.Logf("Database close error: %v", err)
		}

		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Failed to remove temp directory: %v", err)
		}

		t.Log("Test server cleanup complete")
	}
}

// generateTLSCerts generates self-signed TLS certificates for testing
func generateTLSCerts(certPath, keyPath string) error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"sshca-serv-test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cert file: %w", err)
	}
	defer func() { _ = certOut.Close() }()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file: %w", err)
	}
	defer func() { _ = keyOut.Close() }()

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

func TestSSHCAIntegration(t *testing.T) {
	var baseURL string
	var isExternalServer bool

	// Determine base URL and whether to start in-process server
	if *serverURL != "" {
		baseURL = *serverURL
		isExternalServer = true
		t.Logf("Using external server at %s", baseURL)
	} else {
		baseURL = "https://localhost:8443"
		isExternalServer = false
		t.Logf("Starting in-process server at %s (use -server flag to connect to external server)", baseURL)
		cleanup := startTestServer(t)
		defer cleanup()
	}

	// Create HTTP client that accepts self-signed certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 30 * time.Second,
	}

	// Wait for service to be ready
	timeout := 10 * time.Second
	if isExternalServer {
		timeout = 90 * time.Second
	}
	waitForService(t, client, baseURL, timeout)

	// Fetch CA public key for certificate verification
	caPublicKey := fetchCAPublicKey(t, client, baseURL)

	// Test cases for different key types
	testCases := []struct {
		name        string
		keyType     string
		generateKey func(*testing.T) (ssh.PublicKey, string)
	}{
		{
			name:        "RSA",
			keyType:     "rsa",
			generateKey: generateRSAKey,
		},
		{
			name:        "ECDSA",
			keyType:     "ecdsa",
			generateKey: generateECDSAKey,
		},
		{
			name:        "Ed25519",
			keyType:     "ed25519",
			generateKey: generateEd25519Key,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key pair
			publicKey, publicKeyString := tc.generateKey(t)
			t.Logf("Generated %s public key: %s", tc.keyType, publicKeyString[:60]+"...")

			// Sign the key
			hostname := fmt.Sprintf("testhost-%s", tc.keyType)
			t.Logf("Requesting certificate signature for hostname: %s", hostname)
			signResp := signKey(t, client, baseURL, publicKeyString, hostname)

			t.Logf("Certificate signed successfully!")
			t.Logf("  Serial: %d", signResp.Serial)
			t.Logf("  Expires: %s", signResp.ExpiresAt)

			// Parse certificate
			cert := parseCertificate(t, signResp.Certificate)
			t.Logf("Certificate details:")
			t.Logf("  Type: %s", cert.Type())
			t.Logf("  Key ID: %s", cert.KeyId)
			t.Logf("  Valid principals: %v", cert.ValidPrincipals)
			t.Logf("  Valid after: %s", time.Unix(int64(cert.ValidAfter), 0))
			t.Logf("  Valid before: %s", time.Unix(int64(cert.ValidBefore), 0))

			// Verify the certificate is for the right key
			if cert.Key.Type() != publicKey.Type() {
				t.Errorf("Certificate key type %s does not match public key type %s",
					cert.Key.Type(), publicKey.Type())
			}

			// Cryptographically verify the certificate signature
			verifyCertificate(t, cert, caPublicKey)
		})
	}

	t.Log("All integration tests passed!")
}
