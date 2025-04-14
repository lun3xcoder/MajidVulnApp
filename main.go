package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/majid/govulnapp/config"
	"github.com/majid/govulnapp/routes"
)

func main() {
	// Initialize database connection
	db, err := config.InitDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Setup routes
	router := routes.SetupRoutes(db)

	// Start server - VULNERABILITY: No TLS configuration
	fmt.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}
