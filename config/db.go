// This file contains database configuration with intentional security vulnerabilities
// for educational purposes. DO NOT use in production environments.
package config

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

// VULNERABILITY: Hardcoded credentials
const (
	DBUser     = "root"
	DBPassword = "password123"
	DBHost     = "localhost"
	DBPort     = "3306"
	DBName     = "govulnapp"
)

// InitDB initializes the database connection
func InitDB() (*sql.DB, error) {
	// VULNERABILITY: Credentials directly in connection string
	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", 
		DBUser, DBPassword, DBHost, DBPort, DBName)
	
	// Open database connection
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return nil, err
	}

	// VULNERABILITY: No connection pool limits
	
	// Check if connection is alive
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	// Create tables if they don't exist
	err = createTables(db)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// createTables creates the necessary tables if they don't exist
func createTables(db *sql.DB) error {
	// VULNERABILITY: No prepared statements, potential for SQL injection
	
	// Create users table
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(255) NOT NULL UNIQUE,
		password VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		role VARCHAR(50) DEFAULT 'user',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	
	_, err := db.Exec(userTable)
	if err != nil {
		return err
	}

	// Create clients table
	clientTable := `
	CREATE TABLE IF NOT EXISTS clients (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		address TEXT,
		phone VARCHAR(50),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	
	_, err = db.Exec(clientTable)
	if err != nil {
		return err
	}

	// Create products table
	productTable := `
	CREATE TABLE IF NOT EXISTS products (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		price DECIMAL(10,2) NOT NULL,
		stock INT DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	
	_, err = db.Exec(productTable)
	if err != nil {
		return err
	}

	return nil
}
