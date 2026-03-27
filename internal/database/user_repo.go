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
	query := `SELECT id, email, password_hash, role, created_at, updated_at FROM users WHERE email = ?`
	row := db.conn.QueryRow(query, email)

	var user models.User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (db *DB) GetUserByID(id int64) (*models.User, error) {
	query := `SELECT id, email, password_hash, role, created_at, updated_at FROM users WHERE id = ?`
	row := db.conn.QueryRow(query, id)

	var user models.User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}
