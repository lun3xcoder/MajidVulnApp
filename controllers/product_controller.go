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

// ProductController handles product-related requests
type ProductController struct {
	DB *sql.DB
}

// GetProducts retrieves all products
func (c *ProductController) GetProducts(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No authorization check
	products, err := models.GetAllProducts(c.DB)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error retrieving products: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// VULNERABILITY: No rate limiting
	w.Header().Set("Content-Type", "application/json")
	// VULNERABILITY: No CORS policy
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(products)
}

// GetProduct retrieves a specific product
func (c *ProductController) GetProduct(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	// VULNERABILITY: No authentication check
	product, err := models.GetProduct(c.DB, id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Product not found", http.StatusNotFound)
		} else {
			// VULNERABILITY: Detailed error exposure
			http.Error(w, "Error retrieving product: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(product)
}

// CreateProduct creates a new product
func (c *ProductController) CreateProduct(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No CSRF protection
	var product models.Product
	
	// VULNERABILITY: No request body size limit
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// VULNERABILITY: No error handling for malformed JSON
	json.Unmarshal(body, &product)

	// VULNERABILITY: No input validation
	err = models.CreateProduct(c.DB, &product)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error creating product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(product)
}

// UpdateProduct updates an existing product
func (c *ProductController) UpdateProduct(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	var product models.Product
	
	// VULNERABILITY: No request body size limit
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// VULNERABILITY: No error handling for malformed JSON
	json.Unmarshal(body, &product)

	// Set ID from URL
	// VULNERABILITY: No validation that id is a valid integer
	productID := 0
	_, err = fmt.Sscanf(id, "%d", &productID)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}
	product.ID = productID

	// VULNERABILITY: No authorization check
	err = models.UpdateProduct(c.DB, &product)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error updating product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(product)
}

// DeleteProduct deletes a product
func (c *ProductController) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	parts := strings.Split(r.URL.Path, "/")
	id := parts[len(parts)-1]

	// VULNERABILITY: No authorization check
	err := models.DeleteProduct(c.DB, id)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error deleting product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Product deleted successfully"})
}

// SearchProducts searches for products by name
func (c *ProductController) SearchProducts(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: No input validation or sanitization
	searchTerm := r.URL.Query().Get("q")
	
	// VULNERABILITY: No input validation, potential for SQL injection
	products, err := models.SearchProducts(c.DB, searchTerm)
	if err != nil {
		// VULNERABILITY: Detailed error exposure
		http.Error(w, "Error searching products: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}
