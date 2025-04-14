package routes

import (
	"database/sql"
	"net/http"

	"github.com/majid/govulnapp/controllers"
)

// SetupRoutes configures all the routes for the application
func SetupRoutes(db *sql.DB) http.Handler {
	// Initialize controllers
	userController := &controllers.UserController{DB: db}
	clientController := &controllers.ClientController{DB: db}
	productController := &controllers.ProductController{DB: db}

	// Create a new mux (multiplexer)
	mux := http.NewServeMux()

	// User routes
	mux.HandleFunc("/api/register", userController.Register)
	mux.HandleFunc("/api/login", userController.Login)
	// VULNERABILITY: No authentication required for sensitive operations
	mux.HandleFunc("/api/users", userController.GetUsers)
	mux.HandleFunc("/api/users/", userController.GetUser)

	// Client routes
	// VULNERABILITY: No authentication middleware for CRUD operations
	mux.HandleFunc("/api/clients", clientController.GetClients)
	mux.HandleFunc("/api/clients/", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABILITY: No proper method check
		if r.Method == http.MethodGet {
			clientController.GetClient(w, r)
		} else if r.Method == http.MethodPost {
			clientController.CreateClient(w, r)
		} else if r.Method == http.MethodPut {
			clientController.UpdateClient(w, r)
		} else if r.Method == http.MethodDelete {
			clientController.DeleteClient(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Product routes
	// VULNERABILITY: No authentication middleware for CRUD operations
	mux.HandleFunc("/api/products", productController.GetProducts)
	mux.HandleFunc("/api/products/search", productController.SearchProducts)
	mux.HandleFunc("/api/products/", func(w http.ResponseWriter, r *http.Request) {
		// VULNERABILITY: No proper method check
		if r.Method == http.MethodGet {
			productController.GetProduct(w, r)
		} else if r.Method == http.MethodPost {
			productController.CreateProduct(w, r)
		} else if r.Method == http.MethodPut {
			productController.UpdateProduct(w, r)
		} else if r.Method == http.MethodDelete {
			productController.DeleteProduct(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// VULNERABILITY: No CORS protection
	return addCORSMiddleware(mux)
}

// VULNERABILITY: Overly permissive CORS policy
func addCORSMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}
