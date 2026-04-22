package database

import (
	"database/sql"
	"errors"
	"time"

	"fintech-payments-mvp/internal/models"
)

var ErrPaymentNotFound = errors.New("payment not found")

func (db *DB) CreatePayment(userID int64, amount float64, currency models.Currency, recipientID, description string, fraudScore float64) (*models.Payment, error) {
	query := `INSERT INTO payments (user_id, amount, currency, recipient_id, description, status, fraud_score, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now()
	status := models.PaymentStatusPending

	result, err := db.conn.Exec(query, userID, amount, currency, recipientID, description, status, fraudScore, now, now)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &models.Payment{
		ID:          id,
		UserID:      userID,
		Amount:      amount,
		Currency:    currency,
		RecipientID: recipientID,
		Description: description,
		Status:      status,
		FraudScore:  fraudScore,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (db *DB) GetPaymentByID(id int64) (*models.Payment, error) {
	query := `SELECT id, user_id, amount, currency, recipient_id, description, status, fraud_score, flagged_by_user_id, flag_reason, created_at, updated_at FROM payments WHERE id = ?`
	row := db.conn.QueryRow(query, id)

	var payment models.Payment
	var flaggedByUserID sql.NullInt64
	var flagReason sql.NullString

	err := row.Scan(&payment.ID, &payment.UserID, &payment.Amount, &payment.Currency, &payment.RecipientID, &payment.Description, &payment.Status, &payment.FraudScore, &flaggedByUserID, &flagReason, &payment.CreatedAt, &payment.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPaymentNotFound
		}
		return nil, err
	}

	if flaggedByUserID.Valid {
		payment.FlaggedByUserID = &flaggedByUserID.Int64
	}
	if flagReason.Valid {
		payment.FlagReason = flagReason.String
	}

	return &payment, nil
}

func (db *DB) GetPaymentsByUserID(userID int64, limit, offset int) ([]models.Payment, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	query := `SELECT id, user_id, amount, currency, recipient_id, description, status, fraud_score, flagged_by_user_id, flag_reason, created_at, updated_at FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.conn.Query(query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPayments(rows)
}

func (db *DB) GetFlaggedPayments(limit, offset int) ([]models.Payment, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	query := `SELECT id, user_id, amount, currency, recipient_id, description, status, fraud_score, flagged_by_user_id, flag_reason, created_at, updated_at FROM payments WHERE status = ? OR fraud_score > 0.7 ORDER BY fraud_score DESC, created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.conn.Query(query, models.PaymentStatusFlagged, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPayments(rows)
}

func (db *DB) UpdatePaymentStatus(id int64, status models.PaymentStatus, flaggedByUserID *int64, flagReason string) error {
	query := `UPDATE payments SET status = ?, flagged_by_user_id = ?, flag_reason = ?, updated_at = ? WHERE id = ?`
	_, err := db.conn.Exec(query, status, flaggedByUserID, flagReason, time.Now(), id)
	return err
}

func scanPayments(rows *sql.Rows) ([]models.Payment, error) {
	var payments []models.Payment

	for rows.Next() {
		var payment models.Payment
		var flaggedByUserID sql.NullInt64
		var flagReason sql.NullString

		err := rows.Scan(&payment.ID, &payment.UserID, &payment.Amount, &payment.Currency, &payment.RecipientID, &payment.Description, &payment.Status, &payment.FraudScore, &flaggedByUserID, &flagReason, &payment.CreatedAt, &payment.UpdatedAt)
		if err != nil {
			return nil, err
		}

		if flaggedByUserID.Valid {
			payment.FlaggedByUserID = &flaggedByUserID.Int64
		}
		if flagReason.Valid {
			payment.FlagReason = flagReason.String
		}

		payments = append(payments, payment)
	}

	// FIX: CWE-703 — проверка ошибок итерации курсора БД после завершения цикла.
	// rows.Err() возвращает ошибку, возникшую во время итерации (например,
	// разрыв соединения), которая иначе была бы молча проигнорирована.
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return payments, nil
}
