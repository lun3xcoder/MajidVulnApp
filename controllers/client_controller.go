package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/majid/govulnapp/models"
)

// ClientController handles client-related requests
type ClientController struct {
	DB *sql.DB
}

// GetClients retrieves all clients
func (c *ClientController) GetClients(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No authorization check
	clients, err := models.GetAllClients(c.DB)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error retrieving clients: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// VULNERABILITY: No rate limiting
	w.Header().Set("Content-Type", "application/json")
	// VULNERABILITY: No CORS policy
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(clients)
}

// GetClient retrieves a specific client
func (c *ClientController) GetClient(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	// VULNERABILITY: No authentication check
	client, err := models.GetClient(c.DB, id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Client not found", http.StatusNotFound)
		} else {
			// VULNERABILITY: Detailed error exposure
			http.Error(w, "Error retrieving client: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(client)
}

// CreateClient creates a new client
func (c *ClientController) CreateClient(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No CSRF protection
	var client models.Client
	
	// VULNERABILITY: No request body size limit
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// VULNERABILITY: No error handling for malformed JSON
	json.Unmarshal(body, &client)

	// VULNERABILITY: No input validation
	err = models.CreateClient(c.DB, &client)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error creating client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// UpdateClient updates an existing client
func (c *ClientController) UpdateClient(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	var client models.Client
	
	// VULNERABILITY: No request body size limit
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// VULNERABILITY: No error handling for malformed JSON
	json.Unmarshal(body, &client)

	// Set ID from URL
	// VULNERABILITY: No validation that id is a valid integer
	clientID := 0
	_, err = fmt.Sscanf(id, "%d", &clientID)
	if err != nil {
		http.Error(w, "Invalid client ID", http.StatusBadRequest)
		return
	}
	client.ID = clientID

	// VULNERABILITY: No authorization check
	err = models.UpdateClient(c.DB, &client)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error updating client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// DeleteClient deletes a client
func (c *ClientController) DeleteClient(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	// VULNERABILITY: No authorization check
	err := models.DeleteClient(c.DB, id)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error deleting client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Client deleted successfully"})
}
