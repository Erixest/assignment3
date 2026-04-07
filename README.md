# Fintech Payments MVP

Secure digital payments system with fraud monitoring capabilities.

## Technology Stack Justification

This project uses Go instead of Python as permitted by the assignment ("допускается использование альтернативных технологий при соответствующем обосновании"):

| Python Requirement | Go Equivalent | Justification |
|-------------------|---------------|---------------|
| FastAPI/Flask | Gin | High-performance HTTP framework with middleware support |
| Pydantic | go-playground/validator | Struct validation with custom validators |
| SQLAlchemy | database/sql + SQLite driver | Parameterized queries, connection pooling |
| bcrypt/PBKDF2 | golang.org/x/crypto/bcrypt | Industry-standard password hashing |
| JWT | github.com/golang-jwt/jwt | JWT creation and validation |
| pip-audit | govulncheck | Go's official vulnerability scanner |
| bandit | gosec | Go security linter (SAST) |

## Features

- User registration and authentication with JWT
- Payment creation with fraud score calculation
- Payment confirmation by owner
- Fraud analyst role for monitoring suspicious transactions
- Audit logging for all critical actions
- Rate limiting and security headers

## API Endpoints

### Public
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login and get JWT token

### Protected (Requires JWT)
- `GET /api/v1/me` - Get current user info
- `POST /api/v1/payments` - Create new payment
- `GET /api/v1/payments` - List user's payments
- `GET /api/v1/payments/:id` - Get payment details
- `POST /api/v1/payments/:id/confirm` - Confirm payment

### Fraud Analyst Only
- `GET /api/v1/analyst/payments/flagged` - List flagged payments
- `POST /api/v1/analyst/payments/:id/flag` - Flag suspicious payment
- `POST /api/v1/analyst/payments/:id/reject` - Reject fraudulent payment
- `GET /api/v1/analyst/audit` - View audit logs

## Security Measures

1. **Input Validation**: All inputs validated using go-playground/validator
2. **Password Hashing**: bcrypt with default cost factor
3. **JWT Tokens**: Short-lived tokens (15 minutes default)
4. **Parameterized Queries**: All SQL queries use parameters
5. **Object-Level Authorization**: Users can only access their own payments
6. **Role-Based Access Control**: Fraud analyst functions isolated
7. **Audit Logging**: All critical actions logged with IP
8. **Rate Limiting**: Per-IP request limiting
9. **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
10. **No Sensitive Data in Logs**: Passwords/tokens excluded

## Setup

1. Copy `.env.example` to `.env` and configure:
```bash
cp .env.example .env
```

2. Set a secure JWT secret (min 32 characters):
```
JWT_SECRET=your-secure-secret-key-minimum-32-characters
```

3. Install dependencies:
```bash
go mod download
```

4. Run the server:
```bash
go run cmd/server/main.go
```

## Testing

Create test users:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass123"}'
```

## Security Analysis Tools

Run SAST analysis:
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
```

Run vulnerability check:
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

## Roles

- `user` - Regular user, can create and manage own payments
- `fraud_analyst` - Can view all payments, flag and reject suspicious ones

## Database Schema

- `users` - User accounts with hashed passwords
- `payments` - Payment transactions with fraud scores
- `audit_logs` - Security audit trail
