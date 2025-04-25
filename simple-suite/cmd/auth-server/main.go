package main

import (
	"log"
	"os"

	authfullysimple "github.com/authfully/authfully/simple-suite"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// Load if .env exists
	log.Printf("starting")
	if _, err := os.Stat(".env"); err == nil {
		log.Println("Loading .env file")
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}

	log.Printf("Starting authfully-simple server...")
	db, err := gorm.Open(sqlite.Open("auth-server.sqlite3"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	log.Printf("Connected to database")

	// Migrate the schema
	log.Printf("Migrating database schema")
	db.AutoMigrate(&authfullysimple.DefaultClient{})
	log.Printf("Migrated database schema")
}
