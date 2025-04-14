package models

import (
	"database/sql"
	"time"
)

// User represents a user in the system
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // VULNERABILITY: Password stored directly in struct and exposed in JSON
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// GetUser fetches a user by username
func GetUser(db *sql.DB, username string) (*User, error) {
	// VULNERABILITY: SQL Injection - direct string concatenation
	query := "SELECT id, username, password, email, role, created_at FROM users WHERE username = '" + username + "'"
	
	row := db.QueryRow(query)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	return &user, nil
}

// CreateUser creates a new user
func CreateUser(db *sql.DB, user *User) error {
	// VULNERABILITY: No password hashing
	query := "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)"
	
	_, err := db.Exec(query, user.Username, user.Password, user.Email, user.Role)
	return err
}

// AuthenticateUser checks if username and password match
func AuthenticateUser(db *sql.DB, username, password string) (*User, error) {
	// VULNERABILITY: SQL Injection vulnerability
	query := "SELECT id, username, password, email, role, created_at FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
	
	row := db.QueryRow(query)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	return &user, nil
}

// GetAllUsers retrieves all users from the database
func GetAllUsers(db *sql.DB) ([]User, error) {
	// VULNERABILITY: No limit on query results, potential DoS
	query := "SELECT id, username, password, email, role, created_at FROM users"
	
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.Role, &user.CreatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	
	return users, nil
}
