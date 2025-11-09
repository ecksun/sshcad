package ca

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ecksun/sshcad/internal/db"
)

type Signer struct {
	caKeyPath  string
	principals string
	validity   string
	db         *db.DB
}

func NewSigner(caKeyPath, principals, validity string, database *db.DB) *Signer {
	return &Signer{
		caKeyPath:  caKeyPath,
		principals: principals,
		validity:   validity,
		db:         database,
	}
}

type SignRequest struct {
	PublicKey string
	Username  string
}

type SignResponse struct {
	Certificate string
	Serial      int64
	ExpiresAt   time.Time
	Identity    string
	Fingerprint string
	Principal   string
}

func (s *Signer) Sign(req *SignRequest) (*SignResponse, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)

	serial, err := s.db.AllocateSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate serial: %w", err)
	}

	tmpDir, err := os.MkdirTemp("/tmp", "sshca-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("Warning: failed to cleanup temporary directory %s: %v", tmpDir, err)
		}
	}()

	pubKeyPath := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(pubKeyPath, []byte(req.PublicKey), 0600); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	identity := req.Username

	certPath := filepath.Join(tmpDir, "key-cert.pub")
	cmd := exec.Command(
		"ssh-keygen",
		"-s", s.caKeyPath,
		"-I", identity,
		"-n", s.principals,
		"-z", fmt.Sprintf("%d", serial),
		"-V", s.validity,
		pubKeyPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ssh-keygen failed: %w, output: %s", err, string(output))
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	expiresAt, err := s.extractExpirationTime(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract expiration: %w", err)
	}

	certLog := &db.Certificate{
		Serial:               serial,
		Identity:             identity,
		PublicKeyFingerprint: fingerprint,
		ExpiresAt:            expiresAt,
		Principal:            s.principals,
	}

	if err := s.db.LogCertificate(certLog); err != nil {
		return nil, fmt.Errorf("failed to log certificate: %w", err)
	}

	return &SignResponse{
		Certificate: string(certData),
		Serial:      serial,
		Identity:    identity,
		ExpiresAt:   expiresAt,
		Fingerprint: fingerprint,
		Principal:   s.principals,
	}, nil
}

func (s *Signer) extractExpirationTime(certData []byte) (time.Time, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return time.Time{}, err
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return time.Time{}, fmt.Errorf("not a certificate")
	}

	return time.Unix(int64(cert.ValidBefore), 0), nil
}

func (s *Signer) GetCAPublicKey() (string, error) {
	keyData, err := os.ReadFile(s.caKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read CA key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA key: %w", err)
	}

	pubKey := signer.PublicKey()
	authorizedKey := ssh.MarshalAuthorizedKey(pubKey)

	return string(authorizedKey), nil
}
