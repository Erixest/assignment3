package validators

import (
	"regexp"

	"github.com/go-playground/validator/v10"

	"fintech-payments-mvp/internal/models"
)

var validate *validator.Validate
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
var recipientIDRegex = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)

func init() {
	validate = validator.New()
	_ = validate.RegisterValidation("validcurrency", validateCurrency)
	_ = validate.RegisterValidation("validrecipient", validateRecipient)
}

func validateCurrency(fl validator.FieldLevel) bool {
	currency := models.Currency(fl.Field().String())
	return models.ValidCurrencies[currency]
}

func validateRecipient(fl validator.FieldLevel) bool {
	return recipientIDRegex.MatchString(fl.Field().String())
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type CreatePaymentRequest struct {
	Amount      float64 `json:"amount" validate:"required,gt=0,lte=1000000"`
	Currency    string  `json:"currency" validate:"required,validcurrency"`
	RecipientID string  `json:"recipient_id" validate:"required,validrecipient"`
	Description string  `json:"description" validate:"max=500"`
}

type FlagPaymentRequest struct {
	Reason string `json:"reason" validate:"required,min=10,max=1000"`
}

type PaginationRequest struct {
	Limit  int `form:"limit" validate:"omitempty,min=1,max=100"`
	Offset int `form:"offset" validate:"omitempty,min=0"`
}

func ValidateStruct(s interface{}) error {
	return validate.Struct(s)
}

func ValidateEmail(email string) bool {
	if len(email) > 255 {
		return false
	}
	return emailRegex.MatchString(email)
}

func ValidatePassword(password string) bool {
	return len(password) >= 8 && len(password) <= 72
}
