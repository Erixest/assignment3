package services

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"fintech-payments-mvp/internal/database"
	"fintech-payments-mvp/internal/models"
)

var ErrUnauthorizedAccess = errors.New("unauthorized access to resource")
var ErrInvalidStatusTransition = errors.New("invalid status transition")

type PaymentService struct {
	db *database.DB
}

func NewPaymentService(db *database.DB) *PaymentService {
	return &PaymentService{db: db}
}

func (s *PaymentService) CreatePayment(userID int64, amount float64, currency models.Currency, recipientID, description string) (*models.Payment, error) {
	fraudScore := s.calculateFraudScore(amount, currency, recipientID)
	return s.db.CreatePayment(userID, amount, currency, recipientID, description, fraudScore)
}

func (s *PaymentService) GetPayment(paymentID, userID int64, userRole models.Role) (*models.Payment, error) {
	payment, err := s.db.GetPaymentByID(paymentID)
	if err != nil {
		return nil, err
	}

	if userRole != models.RoleFraudAnalyst && payment.UserID != userID {
		return nil, ErrUnauthorizedAccess
	}

	return payment, nil
}

func (s *PaymentService) GetUserPayments(userID int64, limit, offset int) ([]models.Payment, error) {
	return s.db.GetPaymentsByUserID(userID, limit, offset)
}

func (s *PaymentService) GetFlaggedPayments(limit, offset int) ([]models.Payment, error) {
	return s.db.GetFlaggedPayments(limit, offset)
}

func (s *PaymentService) ConfirmPayment(paymentID, userID int64) error {
	payment, err := s.db.GetPaymentByID(paymentID)
	if err != nil {
		return err
	}

	if payment.UserID != userID {
		return ErrUnauthorizedAccess
	}

	if payment.Status != models.PaymentStatusPending {
		return ErrInvalidStatusTransition
	}

	return s.db.UpdatePaymentStatus(paymentID, models.PaymentStatusConfirmed, nil, "")
}

func (s *PaymentService) FlagPayment(paymentID, analystID int64, reason string) error {
	payment, err := s.db.GetPaymentByID(paymentID)
	if err != nil {
		return err
	}

	if payment.Status == models.PaymentStatusRejected {
		return ErrInvalidStatusTransition
	}

	return s.db.UpdatePaymentStatus(paymentID, models.PaymentStatusFlagged, &analystID, reason)
}

func (s *PaymentService) RejectPayment(paymentID, analystID int64, reason string) error {
	payment, err := s.db.GetPaymentByID(paymentID)
	if err != nil {
		return err
	}

	if payment.Status != models.PaymentStatusFlagged && payment.Status != models.PaymentStatusPending {
		return ErrInvalidStatusTransition
	}

	return s.db.UpdatePaymentStatus(paymentID, models.PaymentStatusRejected, &analystID, reason)
}

func (s *PaymentService) calculateFraudScore(amount float64, currency models.Currency, recipientID string) float64 {
	score := 0.0

	switch {
	case amount > 500000:
		score += 0.85
	case amount > 100000:
		score += 0.70
	case amount > 50000:
		score += 0.55
	case amount > 10000:
		score += 0.35
	case amount > 5000:
		score += 0.15
	}

	if currency != models.CurrencyRUB {
		score += 0.1
	}

	var randomBytes [8]byte
	rand.Read(randomBytes[:])
	randomValue := float64(binary.LittleEndian.Uint64(randomBytes[:])) / float64(^uint64(0))
	score += randomValue * 0.1

	if score > 1.0 {
		score = 1.0
	}

	return score
}
