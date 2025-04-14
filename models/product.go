package models

import (
	"database/sql"
	"fmt"
	"time"
)

// Product represents a product in the system
type Product struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Price       float64   `json:"price"`
	Stock       int       `json:"stock"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetProduct fetches a product by ID
func GetProduct(db *sql.DB, id string) (*Product, error) {
	// VULNERABILITY: SQL Injection - direct string concatenation
	query := "SELECT id, name, description, price, stock, created_at FROM products WHERE id = " + id
	
	row := db.QueryRow(query)
	
	var product Product
	err := row.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.Stock, &product.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	return &product, nil
}

// CreateProduct creates a new product
func CreateProduct(db *sql.DB, product *Product) error {
	// VULNERABILITY: No input validation
	query := "INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)"
	
	_, err := db.Exec(query, product.Name, product.Description, product.Price, product.Stock)
	return err
}

// UpdateProduct updates an existing product
func UpdateProduct(db *sql.DB, product *Product) error {
	// VULNERABILITY: No checking if product exists
	query := fmt.Sprintf("UPDATE products SET name='%s', description='%s', price=%f, stock=%d WHERE id=%d", 
		product.Name, product.Description, product.Price, product.Stock, product.ID)
	
	// VULNERABILITY: Direct string formatting in SQL query
	_, err := db.Exec(query)
	return err
}

// DeleteProduct deletes a product by ID
func DeleteProduct(db *sql.DB, id string) error {
	// VULNERABILITY: SQL Injection - direct string concatenation
	query := "DELETE FROM products WHERE id = " + id
	
	_, err := db.Exec(query)
	return err
}

// GetAllProducts retrieves all products from the database
func GetAllProducts(db *sql.DB) ([]Product, error) {
	// VULNERABILITY: No limit on query results, potential DoS
	query := "SELECT id, name, description, price, stock, created_at FROM products"
	
	// VULNERABILITY: No filtering or pagination
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.Stock, &product.CreatedAt)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}
	
	return products, nil
}

// SearchProducts searches for products by name
func SearchProducts(db *sql.DB, searchTerm string) ([]Product, error) {
	// VULNERABILITY: SQL Injection via string concatenation
	query := "SELECT id, name, description, price, stock, created_at FROM products WHERE name LIKE '%" + searchTerm + "%'"
	
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.Stock, &product.CreatedAt)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}
	
	return products, nil
}
