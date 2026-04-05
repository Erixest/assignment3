package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"

	"fintech-payments-mvp/internal/config"
	"fintech-payments-mvp/internal/database"
	"fintech-payments-mvp/internal/models"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: seed <command>")
		fmt.Println("Commands:")
		fmt.Println("  users    - Create test users")
		fmt.Println("  payments - Create test payments")
		fmt.Println("  all      - Create all test data")
		os.Exit(1)
	}

	cfg := config.Load()
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	defer db.Close()

	command := os.Args[1]

	switch command {
	case "users":
		seedUsers(db)
	case "payments":
		seedPayments(db)
	case "all":
		seedUsers(db)
		seedPayments(db)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func seedUsers(db *database.DB) {
	users := []struct {
		email    string
		password string
		role     models.Role
	}{
		{"user@example.com", "password123", models.RoleUser},
		{"analyst@example.com", "analyst123", models.RoleFraudAnalyst},
		{"testuser@example.com", "testpass123", models.RoleUser},
	}

	for _, u := range users {
		hash, _ := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.DefaultCost)
		_, err := db.CreateUser(u.email, string(hash), u.role)
		if err != nil {
			fmt.Printf("User %s already exists or error: %v\n", u.email, err)
		} else {
			fmt.Printf("Created user: %s (role: %s)\n", u.email, u.role)
		}
	}
}

func seedPayments(db *database.DB) {
	payments := []struct {
		userID      int64
		amount      float64
		currency    models.Currency
		recipientID string
		description string
		fraudScore  float64
	}{
		{1, 100.00, models.CurrencyUSD, "RECV12345678", "Test payment 1", 0.1},
		{1, 5500.00, models.CurrencyEUR, "RECV87654321", "Large transfer", 0.5},
		{1, 15000.00, models.CurrencyUSD, "RECV11111111", "Suspicious amount", 0.85},
		{3, 250.00, models.CurrencyRUB, "RECV22222222", "Regular payment", 0.05},
		{3, 8000.00, models.CurrencyEUR, "RECV33333333", "International", 0.6},
	}

	for i, p := range payments {
		_, err := db.CreatePayment(p.userID, p.amount, p.currency, p.recipientID, p.description, p.fraudScore)
		if err != nil {
			fmt.Printf("Payment %d error: %v\n", i+1, err)
		} else {
			fmt.Printf("Created payment %d: %.2f %s\n", i+1, p.amount, p.currency)
		}
	}
}
