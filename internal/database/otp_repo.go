package database

import "time"

func (db *DB) CreateOTPPending(token string, userID int64, expiresAt time.Time) error {
	_, err := db.conn.Exec(`INSERT OR REPLACE INTO otp_pending (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expiresAt)
	return err
}

func (db *DB) GetOTPPending(token string) (int64, error) {
	var userID int64
	err := db.conn.QueryRow(`SELECT user_id FROM otp_pending WHERE token = ? AND expires_at > ?`,
		token, time.Now()).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (db *DB) DeleteOTPPending(token string) error {
	_, err := db.conn.Exec(`DELETE FROM otp_pending WHERE token = ?`, token)
	return err
}

func (db *DB) CleanupOTPPending() {
	db.conn.Exec(`DELETE FROM otp_pending WHERE expires_at < ?`, time.Now())
}
