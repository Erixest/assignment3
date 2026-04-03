package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"fintech-payments-mvp/internal/middleware"
	"fintech-payments-mvp/internal/models"
	"fintech-payments-mvp/internal/services"
	"fintech-payments-mvp/internal/validators"
)

type AuditHandler struct {
	auditService *services.AuditService
}

func NewAuditHandler(auditService *services.AuditService) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
	}
}

func (h *AuditHandler) GetAuditLogs(c *gin.Context) {
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
		pagination.Limit = 50
	}

	logs, err := h.auditService.GetLogs(pagination.Limit, pagination.Offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"count": len(logs),
	})
}
