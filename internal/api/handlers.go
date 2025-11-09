package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/ecksun/sshcad/internal/auth"
	"github.com/ecksun/sshcad/internal/ca"
)

type Server struct {
	signer *ca.Signer
	authMw *auth.Middleware
}

func NewServer(signer *ca.Signer, authMw *auth.Middleware) *Server {
	return &Server{
		signer: signer,
		authMw: authMw,
	}
}

type SignRequest struct {
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname,omitempty"`
}

type SignResponse struct {
	Certificate string `json:"certificate"`
	Serial      int64  `json:"serial"`
	ExpiresAt   string `json:"expires_at"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (s *Server) HandleSign(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		s.jsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	// Sign the certificate
	signReq := &ca.SignRequest{
		PublicKey: req.PublicKey,
		Username:  user.Username,
	}

	result, err := s.signer.Sign(signReq)
	if err != nil {
		log.Printf("Failed to sign certificate for user %s: %v", user.Username, err)
		s.jsonError(w, "Failed to sign certificate", http.StatusInternalServerError)
		return
	}

	expiresAt := result.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	log.Printf("Signed certificate %s for id %q serial %d principal %q valid until %s", result.Fingerprint, result.Identity, result.Serial, result.Principal, expiresAt)

	resp := SignResponse{
		Certificate: result.Certificate,
		Serial:      result.Serial,
		ExpiresAt:   expiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (s *Server) HandleCAPublicKey(w http.ResponseWriter, r *http.Request) {
	pubKey, err := s.signer.GetCAPublicKey()
	if err != nil {
		log.Printf("Failed to get CA public key: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := fmt.Fprint(w, pubKey); err != nil {
		log.Printf("Failed to write CA public key: %v", err)
	}
}

func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		log.Printf("Failed to encode health response: %v", err)
	}
}

// RegisterRoutes registers all HTTP routes
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Public endpoints
	mux.HandleFunc("GET /health", s.HandleHealth)
	mux.HandleFunc("GET /api/v1/ca.pub", s.HandleCAPublicKey)

	// Protected endpoints
	mux.Handle("POST /api/v1/sign", s.authMw.RequireAuth(http.HandlerFunc(s.HandleSign)))
}

func (s *Server) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(ErrorResponse{Error: message}); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}
}
