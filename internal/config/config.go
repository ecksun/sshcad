package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	// Server configuration
	ListenAddr string
	TLSCert    string
	TLSKey     string

	// Database configuration
	DBPath string

	// CA configuration
	Principals string
	Validity   string
	SSHCA      string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr: ":8443",
		TLSCert:    "./tmp/cert.pem",
		TLSKey:     "./tmp/key.pem",

		// Database configuration
		DBPath: "./tmp/sshca.db",

		// CA configuration
		Principals: "root",
		Validity:   "-1m:+1h",
		SSHCA:      "./tmp/test_ca",
	}

	if stateDir, ok := os.LookupEnv("STATE_DIRECTORY"); ok {
		cfg.DBPath = filepath.Join(stateDir, "sshca.db")
	}
	if configDir, ok := os.LookupEnv("CONFIGURATION_DIRECTORY"); ok {
		cfg.TLSCert = filepath.Join(configDir, "cert.pem")
		cfg.TLSKey = filepath.Join(configDir, "key.pem")
	}
	if credsDir := os.Getenv("CREDENTIALS_DIRECTORY"); credsDir != "" {
		cfg.SSHCA = credsDir + "/ca-private-key"
	}

	if val, ok := os.LookupEnv("SSHCA_LISTEN_ADDR"); ok {
		cfg.ListenAddr = val
	}
	if val, ok := os.LookupEnv("SSHCA_DB_PATH"); ok {
		cfg.DBPath = val
	}
	if val, ok := os.LookupEnv("SSHCA_PRINCIPALS"); ok {
		cfg.Principals = val
	}
	if val, ok := os.LookupEnv("SSHCA_VALIDITY"); ok {
		cfg.Validity = val
	}

	return cfg, nil
}
