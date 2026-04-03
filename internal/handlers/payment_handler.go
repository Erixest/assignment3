package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"fintech-payments-mvp/internal/middleware"
	"fintech-payments-mvp/internal/models"
	"fintech-payments-mvp/internal/services"
	"fintech-payments-mvp/internal/validators"
)

type PaymentHandler struct {
	paymentService *services.PaymentService
	auditService   *services.AuditService
}

func NewPaymentHandler(paymentService *services.PaymentService, auditService *services.AuditService) *PaymentHandler {
	return &PaymentHandler{
		paymentService: paymentService,
		auditService:   auditService,
	}
}

func (h *PaymentHandler) CreatePayment(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req validators.CreatePaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := validators.ValidateStruct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "validation failed"})
		return
	}

	payment, err := h.paymentService.CreatePayment(
		claims.UserID,
		req.Amount,
		models.Currency(req.Currency),
		req.RecipientID,
		req.Description,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create payment"})
		return
	}

	h.auditService.Log(&claims.UserID, models.AuditActionPaymentCreated, &payment.ID, "payment created", c.ClientIP())

	c.JSON(http.StatusCreated, payment.ToResponse())
}

func (h *PaymentHandler) GetPayment(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payment id"})
		return
	}

	payment, err := h.paymentService.GetPayment(paymentID, claims.UserID, claims.Role)
	if err != nil {
		if err == services.ErrUnauthorizedAccess {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		return
	}

	h.auditService.Log(&claims.UserID, models.AuditActionPaymentViewed, &payment.ID, "payment viewed", c.ClientIP())

	if claims.Role == models.RoleFraudAnalyst {
		c.JSON(http.StatusOK, payment.ToAnalystResponse())
		return
	}

	c.JSON(http.StatusOK, payment.ToResponse())
}

func (h *PaymentHandler) GetMyPayments(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var pagination validators.PaginationRequest
	if err := c.ShouldBindQuery(&pagination); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}

	if pagination.Limit == 0 {
		pagination.Limit = 20
	}

	payments, err := h.paymentService.GetUserPayments(claims.UserID, pagination.Limit, pagination.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch payments"})
		return
	}

	response := make([]models.PaymentResponse, len(payments))
	for i, p := range payments {
		response[i] = p.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{
		"payments": response,
		"count":    len(response),
	})
}

func (h *PaymentHandler) ConfirmPayment(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payment id"})
		return
	}

	err = h.paymentService.ConfirmPayment(paymentID, claims.UserID)
	if err != nil {
		if err == services.ErrUnauthorizedAccess {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			return
		}
		if err == services.ErrInvalidStatusTransition {
			c.JSON(http.StatusBadRequest, gin.H{"error": "payment cannot be confirmed"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		return
	}

	h.auditService.Log(&claims.UserID, models.AuditActionPaymentConfirm, &paymentID, "payment confirmed", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"message": "payment confirmed"})
}

func (h *PaymentHandler) GetFlaggedPayments(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil || claims.Role != models.RoleFraudAnalyst {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	var pagination validators.PaginationRequest
	if err := c.ShouldBindQuery(&pagination); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pagination"})
		return
	}

	if pagination.Limit == 0 {
		pagination.Limit = 20
	}

	payments, err := h.paymentService.GetFlaggedPayments(pagination.Limit, pagination.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch payments"})
		return
	}

	response := make([]models.PaymentAnalystResponse, len(payments))
	for i, p := range payments {
		response[i] = p.ToAnalystResponse()
	}

	c.JSON(http.StatusOK, gin.H{
		"payments": response,
		"count":    len(response),
	})
}

func (h *PaymentHandler) FlagPayment(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil || claims.Role != models.RoleFraudAnalyst {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payment id"})
		return
	}

	var req validators.FlagPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := validators.ValidateStruct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "validation failed"})
		return
	}

	err = h.paymentService.FlagPayment(paymentID, claims.UserID, req.Reason)
	if err != nil {
		if err == services.ErrInvalidStatusTransition {
			c.JSON(http.StatusBadRequest, gin.H{"error": "payment cannot be flagged"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		return
	}

	h.auditService.Log(&claims.UserID, models.AuditActionPaymentFlagged, &paymentID, "payment flagged for fraud", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"message": "payment flagged"})
}

func (h *PaymentHandler) RejectPayment(c *gin.Context) {
	claims := middleware.GetUserClaims(c)
	if claims == nil || claims.Role != models.RoleFraudAnalyst {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payment id"})
		return
	}

	var req validators.FlagPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := validators.ValidateStruct(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "validation failed"})
		return
	}

	err = h.paymentService.RejectPayment(paymentID, claims.UserID, req.Reason)
	if err != nil {
		if err == services.ErrInvalidStatusTransition {
			c.JSON(http.StatusBadRequest, gin.H{"error": "payment cannot be rejected"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		return
	}

	h.auditService.Log(&claims.UserID, models.AuditActionPaymentRejected, &paymentID, "payment rejected", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"message": "payment rejected"})
}
