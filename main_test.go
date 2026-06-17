package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func TestJWTEncodingDecoding(t *testing.T) {
	// Setup custom secret
	jwtSecret = "test_secret_key"
	username := "testadmin"

	token, err := GenerateJWT(username)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}

	if claims.Username != username {
		t.Errorf("expected username %q, got %q", username, claims.Username)
	}
}

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	jwtSecret = "test_secret_key"

	r.Use(AuthMiddleware())
	r.GET("/test-protected", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "success", "username": c.MustGet("username")})
	})

	// Test case 1: No Authorization header
	req1 := httptest.NewRequest("GET", "/test-protected", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w1.Code)
	}

	// Test case 2: Invalid Authorization header format
	req2 := httptest.NewRequest("GET", "/test-protected", nil)
	req2.Header.Set("Authorization", "InvalidFormat token")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w2.Code)
	}

	// Test case 3: Valid Authorization header
	token, _ := GenerateJWT("testadmin")
	req3 := httptest.NewRequest("GET", "/test-protected", nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w3.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w3.Body.Bytes(), &resp)
	if resp["username"] != "testadmin" {
		t.Errorf("expected username testadmin inside response, got %v", resp["username"])
	}
}

func TestAdminLoginIntegration(t *testing.T) {
	// Load actual connection for DB testing
	godotenv.Load()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set in environment, skipping DB login integration test")
		return
	}

	// Connect and initialize
	var err error
	db, err = connectDB(dbURL)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	initDatabase() // ensure table is set and admin exists

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/admin/login", adminLogin)

	// Case 1: Wrong password
	payload1 := map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	}
	body1, _ := json.Marshal(payload1)
	req1 := httptest.NewRequest("POST", "/api/admin/login", bytes.NewBuffer(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong credentials, got %d", w1.Code)
	}

	// Case 2: Right credentials
	payload2 := map[string]string{
		"username": "admin",
		"password": "admin123",
	}
	body2, _ := json.Marshal(payload2)
	req2 := httptest.NewRequest("POST", "/api/admin/login", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for correct credentials, got %d", w2.Code)
	}

	var loginResponse map[string]string
	json.Unmarshal(w2.Body.Bytes(), &loginResponse)
	if loginResponse["token"] == "" {
		t.Error("expected JWT token in response, got empty string")
	}
}

// helper to connect to DB for testing
func connectDB(url string) (*sql.DB, error) {
	return sql.Open("postgres", url)
}
