package services

import (
	"fintech-payments-mvp/internal/database"
	"fintech-payments-mvp/internal/models"
)

type AuditService struct {
	db *database.DB
}

func NewAuditService(db *database.DB) *AuditService {
	return &AuditService{db: db}
}

func (s *AuditService) Log(userID *int64, action models.AuditAction, resourceID *int64, details, ipAddress string) {
	_ = s.db.CreateAuditLog(userID, action, resourceID, details, ipAddress)
}

func (s *AuditService) GetLogs(limit, offset int) ([]models.AuditLog, error) {
	return s.db.GetAuditLogs(limit, offset)
}
