package database

import (
"database/sql"
"errors"
"time"

"fintech-payments-mvp/internal/models"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUserExists = errors.New("user already exists")

func (db *DB) CreateUser(email, passwordHash string, role models.Role) (*models.User, error) {
query := `INSERT INTO users (email, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`
now := time.Now()

result, err := db.conn.Exec(query, email, passwordHash, role, now, now)
if err != nil {
return nil, ErrUserExists
}

id, err := result.LastInsertId()
if err != nil {
return nil, err
}

return &models.User{
ID:           id,
Email:        email,
PasswordHash: passwordHash,
Role:         role,
CreatedAt:    now,
UpdatedAt:    now,
}, nil
}

func (db *DB) GetUserByEmail(email string) (*models.User, error) {
query := `SELECT id, email, password_hash, role, otp_enabled, otp_secret, failed_attempts, locked_until, created_at, updated_at FROM users WHERE email = ?`
row := db.conn.QueryRow(query, email)

var user models.User
var lockedUntil sql.NullTime
var otpSecret sql.NullString
err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role,
&user.OTPEnabled, &otpSecret, &user.FailedAttempts, &lockedUntil,
&user.CreatedAt, &user.UpdatedAt)
if err != nil {
if errors.Is(err, sql.ErrNoRows) {
return nil, ErrUserNotFound
}
return nil, err
}
if lockedUntil.Valid {
t := lockedUntil.Time
user.LockedUntil = &t
}
if otpSecret.Valid {
user.OTPSecret = otpSecret.String
}

return &user, nil
}

func (db *DB) GetUserByID(id int64) (*models.User, error) {
query := `SELECT id, email, password_hash, role, otp_enabled, otp_secret, failed_attempts, locked_until, created_at, updated_at FROM users WHERE id = ?`
row := db.conn.QueryRow(query, id)

var user models.User
var lockedUntil sql.NullTime
var otpSecret sql.NullString
err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role,
&user.OTPEnabled, &otpSecret, &user.FailedAttempts, &lockedUntil,
&user.CreatedAt, &user.UpdatedAt)
if err != nil {
if errors.Is(err, sql.ErrNoRows) {
return nil, ErrUserNotFound
}
return nil, err
}
if lockedUntil.Valid {
t := lockedUntil.Time
user.LockedUntil = &t
}
if otpSecret.Valid {
user.OTPSecret = otpSecret.String
}

return &user, nil
}

func (db *DB) UpdateUserOTP(userID int64, secret string, enabled bool) error {
_, err := db.conn.Exec(`UPDATE users SET otp_secret = ?, otp_enabled = ?, updated_at = ? WHERE id = ?`,
secret, enabled, time.Now(), userID)
return err
}

func (db *DB) IncrementFailedAttempts(userID int64) (int, error) {
_, err := db.conn.Exec(`UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = ? WHERE id = ?`,
time.Now(), userID)
if err != nil {
return 0, err
}
var count int
err = db.conn.QueryRow(`SELECT failed_attempts FROM users WHERE id = ?`, userID).Scan(&count)
return count, err
}

func (db *DB) ResetFailedAttempts(userID int64) error {
_, err := db.conn.Exec(`UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`,
time.Now(), userID)
return err
}

func (db *DB) LockUser(userID int64, until time.Time) error {
_, err := db.conn.Exec(`UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?`,
until, time.Now(), userID)
return err
}
