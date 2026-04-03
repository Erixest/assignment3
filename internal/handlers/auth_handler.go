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
}

func NewAuthHandler(authService *services.AuthService, auditService *services.AuditService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		auditService: auditService,
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
		h.auditService.Log(nil, models.AuditActionLoginFailed, nil, "failed login attempt", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	h.auditService.Log(&user.ID, models.AuditActionLogin, nil, "successful login", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user.ToResponse(),
	})
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
