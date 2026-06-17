package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtSecret string

type JWTClaims struct {
	Username string `json:"username"`
	Exp      int64  `json:"exp"`
}

func main() {
	// Load .env
	godotenv.Load()

	// Get JWT Secret
	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "bansos_ternate_secret_key_2026_default"
	}

	// Connect ke database
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	defer db.Close()

	// Test koneksi
	if err = db.Ping(); err != nil {
		log.Fatal("Cannot ping database:", err)
	}
	log.Println("Database connected!")

	// Initialize tables and default admin
	initDatabase()

	// Setup router
	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Public Routes
	r.GET("/api/kecamatan", getKecamatan)
	r.GET("/api/bansos", getBansos)
	r.POST("/api/admin/login", adminLogin)
	r.GET("/api/jenis-bantuan", getJenisBantuan)

	// Protected Routes (Wajib JWT Auth)
	protected := r.Group("/api")
	protected.Use(AuthMiddleware())
	{
		protected.POST("/bansos", createBansos)
		protected.POST("/bansos/batch", createBansosBatch)
		protected.PUT("/bansos/:id", updateBansos)
		protected.DELETE("/bansos/:id", deleteBansos)
	}

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Server running on port:", port)
	r.Run(":" + port)
}

// ── Database Initialization ──────────────────────────────
func initDatabase() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS admin_users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal("Error creating admin_users table:", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	if err != nil {
		log.Fatal("Error counting admin users:", err)
	}

	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal("Error hashing default password:", err)
		}
		_, err = db.Exec("INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)", "admin", string(hash))
		if err != nil {
			log.Fatal("Error inserting default admin:", err)
		}
		log.Println("Default admin user created: admin / admin123")
	}
}

// ── JWT Helpers ──────────────────────────────────────────
func GenerateJWT(username string) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	claims := JWTClaims{
		Username: username,
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
	}
	claimsBytes, _ := json.Marshal(claims)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	unsignedToken := headerEncoded + "." + claimsEncoded

	h := hmac.New(sha256.New, []byte(jwtSecret))
	h.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return unsignedToken + "." + signature, nil
}

func ValidateJWT(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsignedToken := parts[0] + "." + parts[1]
	signature := parts[2]

	h := hmac.New(sha256.New, []byte(jwtSecret))
	h.Write([]byte(unsignedToken))
	expectedSignature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return nil, errors.New("invalid signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// ── Middleware ───────────────────────────────────────────
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be Bearer {token}"})
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := ValidateJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// ── Route Handlers ───────────────────────────────────────
func getKecamatan(c *gin.Context) {
	rows, err := db.Query(`
		SELECT id, name, kota, luas_wilayah 
		FROM kecamatan
		ORDER BY name ASC
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var id int
		var name, kota string
		var luasWilayah float64
		rows.Scan(&id, &name, &kota, &luasWilayah)
		results = append(results, gin.H{
			"id":           id,
			"name":         name,
			"copy_name":    name, // Untuk mapping excel
			"kota":         kota,
			"luas_wilayah": luasWilayah,
		})
	}
	c.JSON(200, results)
}

func getBansos(c *gin.Context) {
	jenis := c.Query("jenis")
	tahun := c.Query("tahun")

	query := `
		SELECT 
			db.id,
			k.name as kecamatan,
			k.id as kecamatan_id,
			jb.name as jenis_bantuan,
			jb.id as jenis_bantuan_id,
			db.jumlah_kpm,
			db.tahun
		FROM data_bansos db
		JOIN kecamatan k ON db.kecamatan_id = k.id
		JOIN jenis_bantuan jb ON db.jenis_bantuan_id = jb.id
		WHERE 1=1
	`

	var args []interface{}
	argCount := 1

	if jenis != "" && jenis != "Semua Jenis" {
		query += fmt.Sprintf(" AND jb.name = $%d", argCount)
		args = append(args, jenis)
		argCount++
	}

	if tahun != "" {
		query += fmt.Sprintf(" AND db.tahun = $%d", argCount)
		args = append(args, tahun)
	}

	query += " ORDER BY db.tahun DESC, k.name ASC, jb.name ASC"

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var id, kecamatanID, jenisBantuanID, jumlahKpm, tahunVal int
		var kecamatan, jenisBantuan string
		rows.Scan(&id, &kecamatan, &kecamatanID, &jenisBantuan, &jenisBantuanID, &jumlahKpm, &tahunVal)
		results = append(results, gin.H{
			"id":               id,
			"kecamatan":        kecamatan,
			"kecamatan_id":     kecamatanID,
			"jenis_bantuan":    jenisBantuan,
			"jenis_bantuan_id": jenisBantuanID,
			"jumlah_kpm":       jumlahKpm,
			"tahun":            tahunVal,
		})
	}
	c.JSON(200, results)
}

func getJenisBantuan(c *gin.Context) {
	rows, err := db.Query(`
		SELECT id, name 
		FROM jenis_bantuan
		ORDER BY name ASC
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		results = append(results, gin.H{
			"id":   id,
			"name": name,
		})
	}
	c.JSON(200, results)
}

type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func adminLogin(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var id int
	var passwordHash string
	err := db.QueryRow("SELECT id, password_hash FROM admin_users WHERE username = $1", input.Username).Scan(&id, &passwordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
		return
	}

	token, err := GenerateJWT(input.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": input.Username,
	})
}

type BansosInput struct {
	KecamatanID    int `json:"kecamatan_id" binding:"required"`
	JenisBantuanID int `json:"jenis_bantuan_id" binding:"required"`
	JumlahKpm      int `json:"jumlah_kpm" binding:"required"`
	Tahun          int `json:"tahun" binding:"required"`
}

func createBansos(c *gin.Context) {
	var input BansosInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Cek apakah data untuk kombinasi ini sudah ada
	var existID int
	err := db.QueryRow("SELECT id FROM data_bansos WHERE kecamatan_id = $1 AND jenis_bantuan_id = $2 AND tahun = $3",
		input.KecamatanID, input.JenisBantuanID, input.Tahun).Scan(&existID)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Data bansos untuk kecamatan, jenis bantuan, dan tahun ini sudah ada. Gunakan Edit jika ingin mengubah."})
		return
	}

	var newID int
	err = db.QueryRow(`
		INSERT INTO data_bansos (kecamatan_id, jenis_bantuan_id, jumlah_kpm, tahun)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, input.KecamatanID, input.JenisBantuanID, input.JumlahKpm, input.Tahun).Scan(&newID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Data bansos berhasil ditambahkan", "id": newID})
}

func createBansosBatch(c *gin.Context) {
	var inputs []BansosInput
	if err := c.ShouldBindJSON(&inputs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	insertedCount := 0
	updatedCount := 0

	for _, input := range inputs {
		if input.KecamatanID <= 0 || input.JenisBantuanID <= 0 || input.Tahun <= 0 {
			continue
		}

		var existID int
		err := tx.QueryRow("SELECT id FROM data_bansos WHERE kecamatan_id = $1 AND jenis_bantuan_id = $2 AND tahun = $3",
			input.KecamatanID, input.JenisBantuanID, input.Tahun).Scan(&existID)

		if err == sql.ErrNoRows {
			// Insert baru
			_, err = tx.Exec(`
				INSERT INTO data_bansos (kecamatan_id, jenis_bantuan_id, jumlah_kpm, tahun)
				VALUES ($1, $2, $3, $4)
			`, input.KecamatanID, input.JenisBantuanID, input.JumlahKpm, input.Tahun)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Gagal memasukkan data: %s", err.Error())})
				return
			}
			insertedCount++
		} else if err == nil {
			// Update data yang sudah ada
			_, err = tx.Exec(`
				UPDATE data_bansos 
				SET jumlah_kpm = $1
				WHERE id = $2
			`, input.JumlahKpm, existID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Gagal mengupdate data: %s", err.Error())})
				return
			}
			updatedCount++
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  fmt.Sprintf("Batch upload selesai. %d data ditambahkan, %d data diperbarui.", insertedCount, updatedCount),
		"inserted": insertedCount,
		"updated":  updatedCount,
	})
}

func updateBansos(c *gin.Context) {
	id := c.Param("id")
	var input BansosInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := db.Exec(`
		UPDATE data_bansos
		SET kecamatan_id = $1, jenis_bantuan_id = $2, jumlah_kpm = $3, tahun = $4
		WHERE id = $5
	`, input.KecamatanID, input.JenisBantuanID, input.JumlahKpm, input.Tahun, id)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Data bansos tidak ditemukan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data bansos berhasil diubah"})
}

func deleteBansos(c *gin.Context) {
	id := c.Param("id")

	res, err := db.Exec("DELETE FROM data_bansos WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Data bansos tidak ditemukan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data bansos berhasil dihapus"})
}