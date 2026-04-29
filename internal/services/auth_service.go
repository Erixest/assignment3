package services

import (
"crypto/hmac"
"crypto/rand"
"crypto/sha256"
"encoding/hex"
"errors"
"time"

"github.com/golang-jwt/jwt/v5"
"golang.org/x/crypto/bcrypt"

"fintech-payments-mvp/internal/config"
"fintech-payments-mvp/internal/database"
"fintech-payments-mvp/internal/models"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrTokenExpired = errors.New("token expired")
var ErrInvalidToken = errors.New("invalid token")
var ErrAccountLocked = errors.New("account locked")

type AuthService struct {
db     *database.DB
config *config.Config
}

type Claims struct {
UserID int64       `json:"user_id"`
Email  string      `json:"email"`
Role   models.Role `json:"role"`
jwt.RegisteredClaims
}

func NewAuthService(db *database.DB, cfg *config.Config) *AuthService {
return &AuthService{
db:     db,
config: cfg,
}
}

func (s *AuthService) Register(email, password string, role models.Role) (*models.User, error) {
hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
return nil, err
}
return s.db.CreateUser(email, string(hash), role)
}

func (s *AuthService) Login(email, password string) (*models.User, string, error) {
user, err := s.db.GetUserByEmail(email)
if err != nil {
return nil, "", ErrInvalidCredentials
}

// Check lockout
if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
return nil, "", ErrAccountLocked
}

if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
newCount, _ := s.db.IncrementFailedAttempts(user.ID)
if newCount >= 5 {
lockUntil := time.Now().Add(15 * time.Minute)
s.db.LockUser(user.ID, lockUntil)
}
return nil, "", ErrInvalidCredentials
}

// Reset failed attempts on successful password check
s.db.ResetFailedAttempts(user.ID)

// If OTP enabled, signal caller to do OTP step
if user.OTPEnabled {
return user, "otp_required", nil
}

token, err := s.generateToken(user)
if err != nil {
return nil, "", err
}

return user, token, nil
}

func (s *AuthService) generateToken(user *models.User) (string, error) {
jtiBytes := make([]byte, 16)
if _, err := rand.Read(jtiBytes); err != nil {
return "", err
}
jti := hex.EncodeToString(jtiBytes)

claims := Claims{
UserID: user.ID,
Email:  user.Email,
Role:   user.Role,
RegisteredClaims: jwt.RegisteredClaims{
ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWTExpiry)),
IssuedAt:  jwt.NewNumericDate(time.Now()),
Subject:   user.Email,
ID:        jti,
},
}

token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *AuthService) GenerateTokenForUser(user *models.User) (string, error) {
return s.generateToken(user)
}

func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
return nil, ErrInvalidToken
}
return []byte(s.config.JWTSecret), nil
})

if err != nil {
if errors.Is(err, jwt.ErrTokenExpired) {
return nil, ErrTokenExpired
}
return nil, ErrInvalidToken
}

claims, ok := token.Claims.(*Claims)
if !ok || !token.Valid {
return nil, ErrInvalidToken
}

return claims, nil
}

func (s *AuthService) GetUserByID(id int64) (*models.User, error) {
return s.db.GetUserByID(id)
}

func (s *AuthService) GenerateCSRFToken(jwtToken string) string {
mac := hmac.New(sha256.New, []byte(s.config.JWTSecret))
mac.Write([]byte("csrf\x00" + jwtToken))
return hex.EncodeToString(mac.Sum(nil))
}

func (s *AuthService) ValidateCSRFToken(jwtToken, csrfToken string) bool {
expected := s.GenerateCSRFToken(jwtToken)
return hmac.Equal([]byte(expected), []byte(csrfToken))
}
