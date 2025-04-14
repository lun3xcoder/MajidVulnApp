# GoVulnApp

A deliberately vulnerable Go backend API for security testing with SonarCloud.

## Description

This application is created specifically for security testing and educational purposes. It contains numerous security vulnerabilities that can be detected by tools like SonarCloud. **DO NOT USE IN PRODUCTION ENVIRONMENTS.**

## Features

- User authentication (login/register)
- Client management (CRUD operations)
- Product management (CRUD operations)
- MySQL database integration

## Vulnerabilities

This application intentionally contains the following vulnerabilities:

1. **SQL Injection**
   - Direct string concatenation in SQL queries
   - Unsanitized user input

2. **Authentication Issues**
   - Weak token generation
   - Plaintext password storage
   - No proper session management

3. **Authorization Issues**
   - Missing access controls
   - Improper authorization checks

4. **Data Exposure**
   - Sensitive data exposure in responses
   - Detailed error messages

5. **Input Validation**
   - Missing input validation
   - No request size limits

6. **Configuration Issues**
   - Hardcoded credentials
   - Insecure cookie settings
   - No TLS

7. **CORS Vulnerabilities**
   - Overly permissive CORS policy

8. **Other Issues**
   - No rate limiting
   - No CSRF protection
   - No proper error handling

## Setup

### Prerequisites

- Go 1.16+
- MySQL

### Installation

1. Clone the repository
2. Set up a MySQL database named `govulnapp`
3. Run the following commands:

```bash
go mod download
go run main.go
```

## API Endpoints

- **Authentication**
  - POST `/api/register` - Register a new user
  - POST `/api/login` - Login

- **Users**
  - GET `/api/users` - Get all users
  - GET `/api/users/{username}` - Get user by username

- **Clients**
  - GET `/api/clients` - Get all clients
  - GET `/api/clients/{id}` - Get client by ID
  - POST `/api/clients/` - Create a new client
  - PUT `/api/clients/{id}` - Update client
  - DELETE `/api/clients/{id}` - Delete client

- **Products**
  - GET `/api/products` - Get all products
  - GET `/api/products/{id}` - Get product by ID
  - POST `/api/products/` - Create a new product
  - PUT `/api/products/{id}` - Update product
  - DELETE `/api/products/{id}` - Delete product
  - GET `/api/products/search?q={term}` - Search products

## Disclaimer

This application is meant for educational purposes and security testing only. It contains intentional security vulnerabilities and should never be used in a production environment.
