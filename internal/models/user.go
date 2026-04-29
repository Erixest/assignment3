package models

import (
	"time"
)

type Role string

const (
	RoleUser         Role = "user"
	RoleFraudAnalyst Role = "fraud_analyst"
)

type User struct {
	ID             int64      `json:"id"`
	Email          string     `json:"email"`
	PasswordHash   string     `json:"-"`
	Role           Role       `json:"role"`
	OTPSecret      string     `json:"-"`
	OTPEnabled     bool       `json:"otp_enabled"`
	FailedAttempts int        `json:"-"`
	LockedUntil    *time.Time `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type UserResponse struct {
	ID         int64     `json:"id"`
	Email      string    `json:"email"`
	Role       Role      `json:"role"`
	OTPEnabled bool      `json:"otp_enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:         u.ID,
		Email:      u.Email,
		Role:       u.Role,
		OTPEnabled: u.OTPEnabled,
		CreatedAt:  u.CreatedAt,
	}
}
