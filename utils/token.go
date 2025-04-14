package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VULNERABILITY: Hardcoded secret key
const secretKey = "mysupersecretkey123"

// GenerateToken creates a simple token for authentication
// VULNERABILITY: Weak token generation algorithm
func GenerateToken(username, role string) string {
	timestamp := time.Now().Unix()
	// VULNERABILITY: Token uses predictable pattern and no encryption
	tokenData := fmt.Sprintf("%s:%s:%d", username, role, timestamp)
	// VULNERABILITY: Simple encoding instead of proper JWT
	return base64.StdEncoding.EncodeToString([]byte(tokenData))
}

// ValidateToken checks if a token is valid
// VULNERABILITY: No proper token validation
func ValidateToken(token string) (string, string, bool) {
	// VULNERABILITY: No signature validation
	decodedBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", false
	}
	
	parts := strings.Split(string(decodedBytes), ":")
	if len(parts) != 3 {
		return "", "", false
	}
	
	username := parts[0]
	role := parts[1]
	
	// VULNERABILITY: No token expiration check
	
	return username, role, true
}

// RequireAuth is middleware to check if a request is authenticated
// VULNERABILITY: Weak authentication implementation
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// VULNERABILITY: Multiple token locations without proper validation
		var token string
		
		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		
		// Check query parameter
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		
		// Check cookie
		if token == "" {
			cookie, err := r.Cookie("session")
			if err == nil {
				token = cookie.Value
			}
		}
		
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		username, role, valid := ValidateToken(token)
		if !valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		// VULNERABILITY: Storing sensitive data in context without encryption
		ctx := context.WithValue(r.Context(), "username", username)
		ctx = context.WithValue(ctx, "role", role)
		
		next(w, r.WithContext(ctx))
	}
}

// RequireAdmin checks if a user has admin role
// VULNERABILITY: Poor role-based access control
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value("role")
		
		// VULNERABILITY: Simple string comparison for authorization
		if role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		
		next(w, r)
	}
}
