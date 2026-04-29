package services

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/pquerna/otp/totp"

	"fintech-payments-mvp/internal/database"
)

type OTPService struct {
	db     *database.DB
	issuer string
}

func NewOTPService(db *database.DB, issuer string) *OTPService {
	return &OTPService{db: db, issuer: issuer}
}

func (s *OTPService) GenerateSecret(email string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func (s *OTPService) Validate(secret, passcode string) bool {
	return totp.Validate(passcode, secret)
}

func (s *OTPService) Enable(userID int64, secret string) error {
	return s.db.UpdateUserOTP(userID, secret, true)
}

func (s *OTPService) Disable(userID int64) error {
	return s.db.UpdateUserOTP(userID, "", false)
}

func (s *OTPService) CreatePendingToken(userID int64) (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	return token, s.db.CreateOTPPending(token, userID, time.Now().Add(5*time.Minute))
}

func (s *OTPService) VerifyPendingToken(token string) (int64, error) {
	userID, err := s.db.GetOTPPending(token)
	if err != nil {
		return 0, err
	}
	s.db.DeleteOTPPending(token)
	return userID, nil
}
