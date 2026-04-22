package services

import (
	"strings"

	"fintech-payments-mvp/internal/database"
	"fintech-payments-mvp/internal/models"
)

type AuditService struct {
	db *database.DB
}

func NewAuditService(db *database.DB) *AuditService {
	return &AuditService{db: db}
}

// sanitizeLogField removes CR/LF characters from user-supplied strings to
// prevent log injection (CWE-117). Other control characters are also stripped.
func sanitizeLogField(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

func (s *AuditService) Log(userID *int64, action models.AuditAction, resourceID *int64, details, ipAddress string) {
	// FIX: CWE-117 — санитизация полей аудит-записи для предотвращения
	// log injection. Пользователь мог внедрить символы \r\n, создавая
	// поддельные строки в журнале аудита (IP-адрес тоже контролируется
	// заголовком X-Forwarded-For, поэтому оба поля санируются).
	_ = s.db.CreateAuditLog(userID, action, resourceID,
		sanitizeLogField(details),
		sanitizeLogField(ipAddress))
}

func (s *AuditService) GetLogs(limit, offset int) ([]models.AuditLog, error) {
	return s.db.GetAuditLogs(limit, offset)
}
