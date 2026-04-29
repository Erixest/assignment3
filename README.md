# FinPay — Fintech Payments MVP

Вариант 10: Финтех — цифровые платежи и мониторинг мошенничества

## Стек технологий

- Go 1.23, Gin, SQLite, JWT (HS256), TOTP (RFC 6238), bcrypt, HTMX, PicoCSS

## Запуск

### Локально

```bash
cp .env.example .env
# Задайте надёжный JWT_SECRET (минимум 32 символа)
go run ./cmd/server
# Заполните тестовыми данными:
go run ./cmd/seed all
```

### Docker

```bash
docker compose up --build
```

## Безопасность

| Механизм | Реализация |
|---|---|
| Хэширование паролей | bcrypt (cost 10) |
| Аутентификация | JWT HS256, 15 мин, уникальный `jti` |
| TOTP 2FA | RFC 6238, совместим с Google Authenticator / Authy |
| Rate limiting | 100 запросов/мин на IP |
| Account lockout | 5 неудачных попыток → 15 минут блокировки |
| CSRF-защита | HMAC-SHA256 токен для аутентифицированных форм |
| Security headers | CSP, HSTS, X-Frame-Options: DENY, Referrer-Policy, Permissions-Policy |
| Аудит-журнал | Критичные события без утечки чувствительных данных |
| SQL-инъекции | Параметризованные запросы повсеместно |
| Валидация ввода | Allowlist-паттерны, ограничения длины |
| Ограничение размера тела | 1 МБ максимум |

## API

```
POST /api/v1/auth/register          — регистрация
POST /api/v1/auth/login             — вход (JWT или otp_required + pending_token)
POST /api/v1/auth/otp/verify        — верификация OTP → JWT

GET  /api/v1/me                     — профиль текущего пользователя
POST /api/v1/profile/otp/setup      — генерация OTP-секрета
POST /api/v1/profile/otp/verify-setup — подтверждение настройки OTP
DELETE /api/v1/profile/otp          — отключение OTP

POST /api/v1/payments               — создать платёж
GET  /api/v1/payments               — список платежей
GET  /api/v1/payments/:id           — детали платежа
POST /api/v1/payments/:id/confirm   — подтвердить платёж

GET  /api/v1/analyst/payments/flagged — подозрительные платежи (analyst)
POST /api/v1/analyst/payments/:id/flag   — пометить платёж (analyst)
POST /api/v1/analyst/payments/:id/reject — отклонить платёж (analyst)
GET  /api/v1/analyst/audit          — журнал аудита (analyst)
```

## Роли

- **user** — создание и подтверждение своих платежей, экспорт CSV
- **fraud_analyst** — просмотр всех платежей, пометка, отклонение, аудит

## Тестовые аккаунты (после `go run ./cmd/seed all`)

| Email | Пароль | Роль |
|---|---|---|
| user@example.com | UserPass1! | user |
| analyst@example.com | AnalystPass1! | fraud_analyst |
| testuser@example.com | TestPass1! | user |
| alice@example.com | AlicePass1! | user |
| bob@example.com | BobPass1! | user |

## Переменные окружения

| Переменная | Описание | По умолчанию |
|---|---|---|
| `JWT_SECRET` | Секрет для подписи JWT (≥ 32 символов) | — (обязательно) |
| `DATABASE_PATH` | Путь к SQLite-файлу | `./payments.db` |
| `SERVER_PORT` | Порт HTTP-сервера | `8080` |
| `JWT_EXPIRY_MINUTES` | Время жизни JWT в минутах | `15` |
| `RATE_LIMIT_REQUESTS` | Запросов на IP за окно | `100` |
| `RATE_LIMIT_WINDOW_SECONDS` | Окно rate limiting (сек) | `60` |
| `COOKIE_SECURE` | Флаг Secure для cookie | `true` |
| `OTP_ISSUER` | Имя издателя в TOTP-URL | `FinPay` |
