package controllers

import (
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/majid/govulnapp/models"
	"github.com/majid/govulnapp/utils"
)

// UserController handles user-related requests
type UserController struct {
	DB *sql.DB
}

// Register handles user registration
func (c *UserController) Register(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation
	var user models.User
	
	// VULNERABILITY: No request body size limit
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// VULNERABILITY: No error handling if JSON is malformed
	json.Unmarshal(body, &user)

	// Set default role
	if user.Role == "" {
		user.Role = "user"
	}

	// VULNERABILITY: No password complexity check
	err = models.CreateUser(c.DB, &user)
	if err != nil {
		// VULNERABILITY: Exposing detailed error information
		http.Error(w, "Error creating user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// VULNERABILITY: Returning sensitive data (password) in response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// Login handles user login
func (c *UserController) Login(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// VULNERABILITY: No request body size limit
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// VULNERABILITY: No error handling if JSON is malformed
	json.Unmarshal(body, &credentials)

	// VULNERABILITY: No brute force protection
	user, err := models.AuthenticateUser(c.DB, credentials.Username, credentials.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		} else {
			// VULNERABILITY: Exposing detailed error information
			http.Error(w, "Login error: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// VULNERABILITY: Weak token generation - predictable
	token := utils.GenerateToken(user.Username, user.Role)

	// VULNERABILITY: Returning sensitive data in response
	response := map[string]interface{}{
		"token":    token,
		"user":     user,
		"message":  "Login successful",
		"serverTime": time.Now(),
	}

	// Set cookie with token - VULNERABILITY: No Secure flag, no HttpOnly flag
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetUsers retrieves all users
func (c *UserController) GetUsers(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No authentication check for sensitive operation
	users, err := models.GetAllUsers(c.DB)
	if err != nil {
		http.Error(w, "Error retrieving users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GetUser retrieves a specific user
func (c *UserController) GetUser(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	username := parts[len(parts)-1]

	// VULNERABILITY: No authentication check for sensitive operation
	user, err := models.GetUser(c.DB, username)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error retrieving user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
