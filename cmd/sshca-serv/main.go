package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/ecksun/sshca-serv/internal/api"
	"github.com/ecksun/sshca-serv/internal/auth"
	"github.com/ecksun/sshca-serv/internal/ca"
	"github.com/ecksun/sshca-serv/internal/config"
	"github.com/ecksun/sshca-serv/internal/db"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	case "add-user":
		cmdAddUser()
	case "serve":
		cmdServe()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sshca-serv <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  add-user <username>  Add a new user with password")
	fmt.Println("  serve                Start the HTTPS server (auto-initializes DB and TLS)")
	fmt.Println("  help                 Show this help message")
}

func ensureDBDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}
	return nil
}

func ensureTLSCerts(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// Both exist, nothing to do
			return nil
		}
	}

	log.Printf("Generating self-signed TLS certificate with ECDSA P-256...")

	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	pubKey := &privKey.PublicKey

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"sshca-serv"},
			CommonName:   "sshca-serv",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(40 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cert file for writing: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certOut.Close()
		return fmt.Errorf("failed to write cert: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("failed to close cert file: %w", err)
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file for writing: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		_ = keyOut.Close()
		return fmt.Errorf("failed to write key: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("failed to close key file: %w", err)
	}

	log.Printf("Generated TLS certificate: %s", certPath)
	log.Printf("Generated TLS private key: %s", keyPath)

	return nil
}

func initializeDB(cfg *config.Config) (err error) {
	if err := ensureDBDir(cfg.DBPath); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	database, dbErr := db.Open(cfg.DBPath)
	if dbErr != nil {
		return fmt.Errorf("failed to open database: %w", dbErr)
	}
	defer func() {
		if closeErr := database.Close(); closeErr != nil {
			// If we don't already have an error, return the close error
			if err == nil {
				err = fmt.Errorf("failed to close database: %w", closeErr)
			}
		}
	}()

	if err := database.InitSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}
	return nil
}

func cmdAddUser() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sshca-serv add-user <username>")
		os.Exit(1)
	}

	username := os.Args[2]

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := initializeDB(cfg); err != nil {
		log.Fatalf("Failed to initialize the  database: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("Failed to close database: %v", err)
		}
	}()

	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println()

	password := string(passwordBytes)
	if password == "" {
		log.Fatal("Password cannot be empty")
	}

	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println()

	if password != string(confirmBytes) {
		log.Fatal("Passwords do not match")
	}

	if err := database.CreateUser(username, password); err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	fmt.Printf("User '%s' created successfully\n", username)
}

func cmdServe() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := initializeDB(cfg); err != nil {
		log.Fatalf("Failed to initialize the database: %v", err)
	}
	if err := ensureTLSCerts(cfg.TLSCert, cfg.TLSKey); err != nil {
		log.Fatalf("Failed to generate TLS certificates: %v", err)
	}
	fmt.Println("Initialization complete!")

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("Failed to close database: %v", err)
		}
	}()

	if _, err := os.Stat(cfg.SSHCA); os.IsNotExist(err) {
		log.Fatalf("CA private key not found at: %s", cfg.SSHCA)
	}

	signer := ca.NewSigner(cfg.SSHCA, cfg.Principals, cfg.Validity, database)
	authMw := auth.NewMiddleware(database)
	apiServer := api.NewServer(signer, authMw)

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	log.Printf("Starting SSH CA service on %s", cfg.ListenAddr)
	log.Printf("CA principals: %s", cfg.Principals)
	log.Printf("Certificate validity: %s", cfg.Validity)

	if err := http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCert, cfg.TLSKey, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
