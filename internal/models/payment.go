package models

import (
	"time"
)

type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "pending"
	PaymentStatusConfirmed PaymentStatus = "confirmed"
	PaymentStatusFlagged   PaymentStatus = "flagged"
	PaymentStatusRejected  PaymentStatus = "rejected"
)

type Currency string

const (
	CurrencyUSD Currency = "USD"
	CurrencyEUR Currency = "EUR"
	CurrencyRUB Currency = "RUB"
)

var ValidCurrencies = map[Currency]bool{
	CurrencyUSD: true,
	CurrencyEUR: true,
	CurrencyRUB: true,
}

type Payment struct {
	ID              int64         `json:"id"`
	UserID          int64         `json:"user_id"`
	Amount          float64       `json:"amount"`
	Currency        Currency      `json:"currency"`
	RecipientID     string        `json:"recipient_id"`
	Description     string        `json:"description"`
	Status          PaymentStatus `json:"status"`
	FraudScore      float64       `json:"fraud_score,omitempty"`
	FlaggedByUserID *int64        `json:"flagged_by_user_id,omitempty"`
	FlagReason      string        `json:"flag_reason,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

type PaymentResponse struct {
	ID          int64         `json:"id"`
	Amount      float64       `json:"amount"`
	Currency    Currency      `json:"currency"`
	RecipientID string        `json:"recipient_id"`
	Description string        `json:"description"`
	Status      PaymentStatus `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
}

func (p *Payment) ToResponse() PaymentResponse {
	return PaymentResponse{
		ID:          p.ID,
		Amount:      p.Amount,
		Currency:    p.Currency,
		RecipientID: p.RecipientID,
		Description: p.Description,
		Status:      p.Status,
		CreatedAt:   p.CreatedAt,
	}
}

type PaymentAnalystResponse struct {
	ID              int64         `json:"id"`
	UserID          int64         `json:"user_id"`
	Amount          float64       `json:"amount"`
	Currency        Currency      `json:"currency"`
	RecipientID     string        `json:"recipient_id"`
	Description     string        `json:"description"`
	Status          PaymentStatus `json:"status"`
	FraudScore      float64       `json:"fraud_score"`
	FlaggedByUserID *int64        `json:"flagged_by_user_id,omitempty"`
	FlagReason      string        `json:"flag_reason,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
}

func (p *Payment) ToAnalystResponse() PaymentAnalystResponse {
	return PaymentAnalystResponse{
		ID:              p.ID,
		UserID:          p.UserID,
		Amount:          p.Amount,
		Currency:        p.Currency,
		RecipientID:     p.RecipientID,
		Description:     p.Description,
		Status:          p.Status,
		FraudScore:      p.FraudScore,
		FlaggedByUserID: p.FlaggedByUserID,
		FlagReason:      p.FlagReason,
		CreatedAt:       p.CreatedAt,
	}
}
