package database

import (
	"fintech-payments-mvp/internal/models"
)

func (db *DB) CreateAuditLog(userID *int64, action models.AuditAction, resourceID *int64, details, ipAddress string) error {
	query := `INSERT INTO audit_logs (user_id, action, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?)`
	_, err := db.conn.Exec(query, userID, action, resourceID, details, ipAddress)
	return err
}

func (db *DB) GetAuditLogs(limit, offset int) ([]models.AuditLog, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `SELECT id, user_id, action, resource_id, details, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.conn.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.ResourceID, &log.Details, &log.IPAddress, &log.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	// FIX: CWE-703 — проверка rows.Err() после итерации курсора аудит-журнала.
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}
