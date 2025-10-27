package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/ecksun/sshca-serv/internal/db"
)

type contextKey string

const userContextKey contextKey = "user"

type Middleware struct {
	db *db.DB
}

func NewMiddleware(database *db.DB) *Middleware {
	return &Middleware{db: database}
}

func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			m.unauthorized(w)
			return
		}

		if !strings.HasPrefix(auth, "Basic ") {
			m.unauthorized(w)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			m.unauthorized(w)
			return
		}

		// Split username:password
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 {
			m.unauthorized(w)
			return
		}

		username, password := pair[0], pair[1]

		user, err := m.db.AuthenticateUser(username, password)
		if err != nil {
			m.unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUser retrieves the authenticated user from the request context
func GetUser(r *http.Request) *db.User {
	user, ok := r.Context().Value(userContextKey).(*db.User)
	if !ok {
		return nil
	}
	return user
}

func (m *Middleware) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="SSH CA Service"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
