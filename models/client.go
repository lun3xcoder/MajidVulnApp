package models

import (
	"database/sql"
	"fmt"
	"time"
)

// Client represents a client in the system
type Client struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Address   string    `json:"address"`
	Phone     string    `json:"phone"`
	CreatedAt time.Time `json:"created_at"`
}

// GetClient fetches a client by ID
func GetClient(db *sql.DB, id string) (*Client, error) {
	// VULNERABILITY: SQL Injection - direct string concatenation
	query := "SELECT id, name, email, address, phone, created_at FROM clients WHERE id = " + id
	
	row := db.QueryRow(query)
	
	var client Client
	err := row.Scan(&client.ID, &client.Name, &client.Email, &client.Address, &client.Phone, &client.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	return &client, nil
}

// CreateClient creates a new client
func CreateClient(db *sql.DB, client *Client) error {
	// VULNERABILITY: No input validation
	query := "INSERT INTO clients (name, email, address, phone) VALUES (?, ?, ?, ?)"
	
	_, err := db.Exec(query, client.Name, client.Email, client.Address, client.Phone)
	return err
}

// UpdateClient updates an existing client
func UpdateClient(db *sql.DB, client *Client) error {
	// VULNERABILITY: No checking if client exists
	query := fmt.Sprintf("UPDATE clients SET name='%s', email='%s', address='%s', phone='%s' WHERE id=%d", 
		client.Name, client.Email, client.Address, client.Phone, client.ID)
	
	// VULNERABILITY: Direct string formatting in SQL query
	_, err := db.Exec(query)
	return err
}

// DeleteClient deletes a client by ID
func DeleteClient(db *sql.DB, id string) error {
	// VULNERABILITY: SQL Injection - direct string concatenation
	query := "DELETE FROM clients WHERE id = " + id
	
	_, err := db.Exec(query)
	return err
}

// GetAllClients retrieves all clients from the database
func GetAllClients(db *sql.DB) ([]Client, error) {
	// VULNERABILITY: No limit on query results, potential DoS
	query := "SELECT id, name, email, address, phone, created_at FROM clients"
	
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var clients []Client
	for rows.Next() {
		var client Client
		err := rows.Scan(&client.ID, &client.Name, &client.Email, &client.Address, &client.Phone, &client.CreatedAt)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	
	return clients, nil
}
