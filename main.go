package main

import (
	"database/sql"
	"log"
	"os"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {
	// Load .env
	godotenv.Load()

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

	// Setup router
	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Routes
	r.GET("/api/kecamatan", getKecamatan)
	r.GET("/api/bansos", getBansos)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Server running on port:", port)
	r.Run(":" + port)
}

func getKecamatan(c *gin.Context) {
	rows, err := db.Query(`
		SELECT id, name, kota, luas_wilayah 
		FROM kecamatan
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
			jb.name as jenis_bantuan,
			db.jumlah_kpm,
			db.tahun
		FROM data_bansos db
		JOIN kecamatan k ON db.kecamatan_id = k.id
		JOIN jenis_bantuan jb ON db.jenis_bantuan_id = jb.id
		WHERE 1=1
	`

	var args []interface{}
	argCount := 1

	if jenis != "" {
		query += fmt.Sprintf(" AND jb.name = $%d", argCount)
		args = append(args, jenis)
		argCount++
	}

	if tahun != "" {
		query += fmt.Sprintf(" AND db.tahun = $%d", argCount)
		args = append(args, tahun)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var id, tahunVal, jumlahKpm int
		var kecamatan, jenisBantuan string
		rows.Scan(&id, &kecamatan, &jenisBantuan, &jumlahKpm, &tahunVal)
		results = append(results, gin.H{
			"id":            id,
			"kecamatan":     kecamatan,
			"jenis_bantuan": jenisBantuan,
			"jumlah_kpm":    jumlahKpm,
			"tahun":         tahunVal,
		})
	}
	c.JSON(200, results)
}