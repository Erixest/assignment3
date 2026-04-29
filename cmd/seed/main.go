package main

import (
"fmt"
"log"
"math/rand"
"os"
"time"

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
{"user@example.com", "UserPass1!", models.RoleUser},
{"analyst@example.com", "AnalystPass1!", models.RoleFraudAnalyst},
{"testuser@example.com", "TestPass1!", models.RoleUser},
{"alice@example.com", "AlicePass1!", models.RoleUser},
{"bob@example.com", "BobPass1!", models.RoleUser},
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
rng := rand.New(rand.NewSource(time.Now().UnixNano()))

currencies := []models.Currency{models.CurrencyUSD, models.CurrencyEUR, models.CurrencyRUB}
recipients := []string{
"RECV12345678", "RECV87654321", "RECV11111111", "RECV22222222", "RECV33333333",
"CORP44444444", "CORP55555555", "CORP66666666", "SUSP77777777", "SUSP88888888",
"ACCT99999999", "ACCTAABBCCDD", "XFER12341234", "XFER56785678", "WIRE11223344",
"WIRE55667788", "BIZZ99001122", "BIZZAABBCCDD", "FIAT11112222", "FIAT33334444",
}
descriptions := []string{
"Monthly subscription", "Invoice payment", "Transfer to savings", "Vendor payment",
"Salary disbursement", "Consulting fee", "Equipment purchase", "Office supplies",
"Travel reimbursement", "Software license", "Marketing campaign", "Cloud services",
"Freelance work", "Legal fees", "Insurance premium", "Utility bill",
"Loan repayment", "Investment transfer", "Dividend payment", "Charity donation",
}

// User IDs 1-5 (matching seeded users)
userIDs := []int64{1, 3, 4, 5}

count := 0
for i := 0; i < 210; i++ {
userID := userIDs[rng.Intn(len(userIDs))]
currency := currencies[rng.Intn(len(currencies))]
recipient := recipients[rng.Intn(len(recipients))]
description := descriptions[rng.Intn(len(descriptions))]

// Varied amounts: small (< 1000), medium (1000-10000), large (> 10000)
var amount float64
switch rng.Intn(3) {
case 0:
amount = 10 + rng.Float64()*990 // 10 - 1000
case 1:
amount = 1000 + rng.Float64()*9000 // 1000 - 10000
case 2:
amount = 10000 + rng.Float64()*90000 // 10000 - 100000
}
amount = float64(int(amount*100)) / 100 // round to 2 decimal places

fraudScore := rng.Float64()
_, err := db.CreatePayment(userID, amount, currency, recipient, description, fraudScore)
if err != nil {
fmt.Printf("Payment %d error: %v\n", i+1, err)
} else {
count++
}
}
fmt.Printf("Created %d payments\n", count)
}
