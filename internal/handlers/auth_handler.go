package handlers

import (
"net/http"

"github.com/gin-gonic/gin"

"fintech-payments-mvp/internal/models"
"fintech-payments-mvp/internal/services"
"fintech-payments-mvp/internal/validators"
)

type AuthHandler struct {
authService  *services.AuthService
auditService *services.AuditService
otpService   *services.OTPService
}

func NewAuthHandler(authService *services.AuthService, auditService *services.AuditService, otpService *services.OTPService) *AuthHandler {
return &AuthHandler{
authService:  authService,
auditService: auditService,
otpService:   otpService,
}
}

func (h *AuthHandler) Register(c *gin.Context) {
var req validators.RegisterRequest
if err := c.ShouldBindJSON(&req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
return
}

if err := validators.ValidateStruct(req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "validation failed"})
return
}

user, err := h.authService.Register(req.Email, req.Password, models.RoleUser)
if err != nil {
c.JSON(http.StatusConflict, gin.H{"error": "registration failed"})
return
}

h.auditService.Log(&user.ID, models.AuditActionRegister, nil, "user registered", c.ClientIP())

c.JSON(http.StatusCreated, gin.H{
"message": "registration successful",
"user":    user.ToResponse(),
})
}

func (h *AuthHandler) Login(c *gin.Context) {
var req validators.LoginRequest
if err := c.ShouldBindJSON(&req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
return
}

if err := validators.ValidateStruct(req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "validation failed"})
return
}

user, token, err := h.authService.Login(req.Email, req.Password)
if err != nil {
if err == services.ErrAccountLocked {
h.auditService.Log(nil, models.AuditActionLoginFailed, nil, "account locked", c.ClientIP())
c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked"})
return
}
h.auditService.Log(nil, models.AuditActionLoginFailed, nil, "failed login attempt", c.ClientIP())
c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
return
}

if token == "otp_required" {
pendingToken, err := h.otpService.CreatePendingToken(user.ID)
if err != nil {
c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
return
}
h.auditService.Log(&user.ID, models.AuditActionLogin, nil, "otp required", c.ClientIP())
c.JSON(http.StatusOK, gin.H{
"otp_required":  true,
"pending_token": pendingToken,
})
return
}

h.auditService.Log(&user.ID, models.AuditActionLogin, nil, "successful login", c.ClientIP())

c.JSON(http.StatusOK, gin.H{
"token": token,
"user":  user.ToResponse(),
})
}

func (h *AuthHandler) OTPVerifyAPI(c *gin.Context) {
var req struct {
PendingToken string `json:"pending_token" binding:"required"`
Code         string `json:"code" binding:"required"`
}
if err := c.ShouldBindJSON(&req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
return
}

userID, err := h.otpService.VerifyPendingToken(req.PendingToken)
if err != nil {
h.auditService.Log(nil, models.AuditActionOTPFailed, nil, "invalid pending token", c.ClientIP())
c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
return
}

user, err := h.authService.GetUserByID(userID)
if err != nil {
c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
return
}

if !h.otpService.Validate(user.OTPSecret, req.Code) {
h.auditService.Log(&userID, models.AuditActionOTPFailed, nil, "wrong otp code", c.ClientIP())
c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid OTP code"})
return
}

token, err := h.authService.GenerateTokenForUser(user)
if err != nil {
c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
return
}

h.auditService.Log(&userID, models.AuditActionOTPVerified, nil, "otp verified", c.ClientIP())

c.JSON(http.StatusOK, gin.H{
"token": token,
"user":  user.ToResponse(),
})
}

func (h *AuthHandler) OTPSetup(c *gin.Context) {
claims, exists := c.Get("user_claims")
if !exists {
c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
return
}
userClaims := claims.(*services.Claims)

secret, url, err := h.otpService.GenerateSecret(userClaims.Email)
if err != nil {
c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
return
}

c.JSON(http.StatusOK, gin.H{
"secret": secret,
"url":    url,
})
}

func (h *AuthHandler) OTPVerifySetup(c *gin.Context) {
claims, exists := c.Get("user_claims")
if !exists {
c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
return
}
userClaims := claims.(*services.Claims)

var req struct {
Secret string `json:"secret" binding:"required"`
Code   string `json:"code" binding:"required"`
}
if err := c.ShouldBindJSON(&req); err != nil {
c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
return
}

if !h.otpService.Validate(req.Secret, req.Code) {
h.auditService.Log(&userClaims.UserID, models.AuditActionOTPFailed, nil, "wrong setup code", c.ClientIP())
c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OTP code"})
return
}

if err := h.otpService.Enable(userClaims.UserID, req.Secret); err != nil {
c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable OTP"})
return
}

h.auditService.Log(&userClaims.UserID, models.AuditActionOTPEnabled, nil, "otp enabled via api", c.ClientIP())

c.JSON(http.StatusOK, gin.H{"message": "OTP enabled successfully"})
}

func (h *AuthHandler) OTPDisableAPI(c *gin.Context) {
claims, exists := c.Get("user_claims")
if !exists {
c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
return
}
userClaims := claims.(*services.Claims)

if err := h.otpService.Disable(userClaims.UserID); err != nil {
c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable OTP"})
return
}

h.auditService.Log(&userClaims.UserID, models.AuditActionOTPDisabled, nil, "otp disabled via api", c.ClientIP())

c.JSON(http.StatusOK, gin.H{"message": "OTP disabled successfully"})
}

func (h *AuthHandler) Me(c *gin.Context) {
claims, exists := c.Get("user_claims")
if !exists {
c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
return
}

userClaims := claims.(*services.Claims)
user, err := h.authService.GetUserByID(userClaims.UserID)
if err != nil {
c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
return
}

c.JSON(http.StatusOK, user.ToResponse())
}
