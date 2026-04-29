package models

import (
	"time"
)

type AuditAction string

const (
	AuditActionLogin           AuditAction = "login"
	AuditActionLoginFailed     AuditAction = "login_failed"
	AuditActionRegister        AuditAction = "register"
	AuditActionPaymentCreated  AuditAction = "payment_created"
	AuditActionPaymentConfirm  AuditAction = "payment_confirmed"
	AuditActionPaymentFlagged  AuditAction = "payment_flagged"
	AuditActionPaymentRejected AuditAction = "payment_rejected"
	AuditActionPaymentViewed   AuditAction = "payment_viewed"
	AuditActionOTPEnabled      AuditAction = "otp_enabled"
	AuditActionOTPDisabled     AuditAction = "otp_disabled"
	AuditActionOTPVerified     AuditAction = "otp_verified"
	AuditActionOTPFailed       AuditAction = "otp_failed"
	AuditActionAccountLocked   AuditAction = "account_locked"
	AuditActionCSVExported     AuditAction = "csv_exported"
)

type AuditLog struct {
	ID         int64       `json:"id"`
	UserID     *int64      `json:"user_id,omitempty"`
	Action     AuditAction `json:"action"`
	ResourceID *int64      `json:"resource_id,omitempty"`
	Details    string      `json:"details"`
	IPAddress  string      `json:"ip_address"`
	CreatedAt  time.Time   `json:"created_at"`
}
