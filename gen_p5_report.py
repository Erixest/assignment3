#!/usr/bin/env python3
"""Generate securep5.docx — Practical Work #5 report for fintech-payments-mvp."""

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

doc = Document()

# ── Page margins ─────────────────────────────────────────────────────────────
for section in doc.sections:
    section.top_margin    = Cm(2)
    section.bottom_margin = Cm(2)
    section.left_margin   = Cm(3)
    section.right_margin  = Cm(1.5)

# ── Helpers ───────────────────────────────────────────────────────────────────
def h1(text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(14)
    run.font.color.rgb = RGBColor(0x1F, 0x49, 0x7D)
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after  = Pt(4)
    return p

def h2(text):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(12)
    run.font.color.rgb = RGBColor(0x2E, 0x74, 0xB5)
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after  = Pt(2)
    return p

def h3(text):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(11)
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after  = Pt(2)
    return p

def body(text, indent=0):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(indent)
    p.add_run(text)
    return p

def code_block(text):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(9)
    pPr = p._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), "F2F2F2")
    pPr.append(shd)
    p.paragraph_format.left_indent  = Cm(0.5)
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after  = Pt(2)
    return p

def table_header_row(table, headers, widths=None):
    row = table.rows[0]
    for i, (cell, hdr) in enumerate(zip(row.cells, headers)):
        cell.text = hdr
        cell.paragraphs[0].runs[0].bold = True
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), "BDD7EE")
        tcPr.append(shd)
        if widths:
            cell.width = Inches(widths[i])

def add_row(table, values):
    row = table.add_row()
    for cell, val in zip(row.cells, values):
        cell.text = str(val)
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

# ═══════════════════════════════════════════════════════════════════════════════
# TITLE PAGE
# ═══════════════════════════════════════════════════════════════════════════════
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = p.add_run("ПРАКТИЧЕСКАЯ РАБОТА № 5")
run.bold = True; run.font.size = Pt(16)

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.add_run("Тема: Комплексный анализ безопасности MVP: обработка памяти и ресурсов,\n"
          "инъекционные уязвимости, аутентификация, авторизация и криптографическая защита").bold = True

doc.add_paragraph()
body("Вариант 10: Финтех — цифровые платежи и мониторинг мошенничества")
body("Выполнил: Студент магистратуры, группа ИБ-1")
body("Проверил: Преподаватель кафедры информационной безопасности")
doc.add_paragraph()

# ═══════════════════════════════════════════════════════════════════════════════
# 1. ЦЕЛЬ РАБОТЫ
# ═══════════════════════════════════════════════════════════════════════════════
h1("1. Цель работы")
body("Провести углублённый комплексный аудит безопасности MVP-системы fintech-payments-mvp "
     "(Go, Gin, SQLite) по четырём направлениям: управление памятью и ресурсами, "
     "инъекционные уязвимости и обработка входных данных, аутентификация/авторизация/"
     "криптография, а также количественная оценка рисков по CVSS v4.0. "
     "Для каждой выявленной проблемы реализовать исправление, подтвердить устранение "
     "дефекта и классифицировать по CWE.")

# ═══════════════════════════════════════════════════════════════════════════════
# 2. ЗАДАНИЕ 1 — Аудит памяти и ресурсов
# ═══════════════════════════════════════════════════════════════════════════════
doc.add_page_break()
h1("2. Задание 1: Аудит управления памятью и ресурсами")

h2("2.1. Таблица рисков — управление памятью и ресурсами")

tbl = doc.add_table(rows=1, cols=5)
tbl.style = "Table Grid"
table_header_row(tbl, ["#", "Область", "Риск", "До исправления", "После исправления"])

risks = [
    ("1", "Размер тела HTTP-запроса\ncmd/server/main.go",
     "CWE-400: нет ограничения — атакующий отправляет тело\n>100 МБ, сервер потребляет всю RAM",
     "Ограничение отсутствует;\nGin читает тело полностью в буфер",
     "MaxBodySizeMiddleware(1 МБ) через http.MaxBytesReader;\nPOST > 1 МБ → 413"),
    ("2", "Курсор БД — scanPayments\ninternal/database/payment_repo.go",
     "CWE-703: rows.Err() не проверяется;\nошибка итерации молча игнорируется",
     "return payments, nil даже при\nошибке разрыва соединения",
     "rows.Err() проверяется после цикла;\nошибка возвращается вызывающему"),
    ("3", "Курсор БД — GetAuditLogs\ninternal/database/audit_repo.go",
     "CWE-703: аналогичная проблема с rows.Err()\nв аудит-репозитории",
     "return logs, nil без проверки\nошибки итерации",
     "rows.Err() проверяется после цикла"),
    ("4", "Загрузка N записей в AnalystPage\ninternal/web/handler.go",
     "CWE-400: GetFlaggedPayments(100,0) —\nнеконтролируемая загрузка на каждый GET /analyst",
     "Жёстко заданный предел 100 записей\nна каждый запрос страницы",
     "Предел снижен до 50;\nдля пагинации используется offset"),
]
for r in risks:
    add_row(tbl, r)

doc.add_paragraph()
h2("2.2. Критический сценарий: переполнение памяти через тело запроса")
body("Endpoint POST /api/v1/auth/register принимает JSON без ограничения размера. "
     "Атакующий отправляет тело объёмом 500 МБ → Gin читает его целиком в RAM → "
     "исчерпание памяти процесса → аварийное завершение (DoS).")

h3("Код до исправления (cmd/server/main.go)")
code_block(
    "r.Use(gin.Recovery())\n"
    "r.Use(middleware.SecurityHeaders())\n"
    "r.Use(middleware.RateLimitMiddleware(cfg))  // без ограничения размера тела"
)

h3("Код после исправления")
code_block(
    "r.Use(gin.Recovery())\n"
    "r.Use(middleware.SecurityHeaders())\n"
    "// FIX: CWE-400 — ограничение тела запроса 1 МБ\n"
    "r.Use(middleware.MaxBodySizeMiddleware(1 << 20))\n"
    "r.Use(middleware.RateLimitMiddleware(cfg))"
)
code_block(
    "// internal/middleware/security.go\n"
    "func MaxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {\n"
    "    return func(c *gin.Context) {\n"
    "        if c.Request.Body != nil {\n"
    "            c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)\n"
    "        }\n"
    "        c.Next()\n"
    "    }\n"
    "}"
)

h3("Код до исправления — scanPayments (payment_repo.go)")
code_block(
    "for rows.Next() {\n"
    "    // ... rows.Scan(...)\n"
    "}\n"
    "return payments, nil  // ошибка итерации молча игнорируется"
)

h3("Код после исправления")
code_block(
    "for rows.Next() {\n"
    "    // ... rows.Scan(...)\n"
    "}\n"
    "// FIX: CWE-703\n"
    "if err := rows.Err(); err != nil {\n"
    "    return nil, err\n"
    "}\n"
    "return payments, nil"
)

h2("2.3. Сравнение поведения до и после")
tbl2 = doc.add_table(rows=1, cols=3)
tbl2.style = "Table Grid"
table_header_row(tbl2, ["Сценарий", "До усиления", "После усиления"])
add_row(tbl2, ["POST /register c телом 500 МБ", "Сервер потребляет 500 МБ RAM, возможен OOM-crash", "Ответ 413 Request Entity Too Large; тело не читается"])
add_row(tbl2, ["Разрыв соединения во время SELECT", "Частичный результат возвращается без ошибки", "Ошибка rows.Err() возвращается → HTTP 500"])
add_row(tbl2, ["GET /analyst (100 записей)", "Каждый запрос страницы загружает до 100 строк", "Загружается не более 50 строк"])

# ═══════════════════════════════════════════════════════════════════════════════
# 3. ЗАДАНИЕ 2 — Secure Code Review
# ═══════════════════════════════════════════════════════════════════════════════
doc.add_page_break()
h1("3. Задание 2: Secure Code Review — точки входа и опасные sink'и")

h2("3.1. Карта доверительных границ (Trust Boundary Map)")
body("Бизнес-сценарий: пользователь создаёт платёж через веб-интерфейс "
     "POST /payments/new → WebHandler.CreatePayment.")
doc.add_paragraph()
body("Граница 1 (Internet → Web Server): HTTP-запрос от браузера. "
     "Данные: amount, currency, recipient_id, description (form-data).")
body("Граница 2 (Web Handler → Service Layer): после первичной валидации. "
     "Доверие: данные частично проверены, но не полностью нормализованы.")
body("Граница 3 (Service → Repository → SQLite): параметризованные запросы. "
     "Доверие: высокое — только prepared statements.")
doc.add_paragraph()

body("Схема потока (текстовая нотация):")
code_block(
    "Browser (HTTP POST)\n"
    "  │  amount, currency, recipient_id, description\n"
    "  ▼\n"
    "[TB-1: Internet → App]\n"
    "  │  RateLimitMiddleware, MaxBodySizeMiddleware, SecurityHeaders\n"
    "  ▼\n"
    "WebHandler.CreatePayment  ← Source\n"
    "  │  Validate: amount (float), currency (allowlist), recipientID (regex)\n"
    "  ▼\n"
    "[TB-2: Handler → Service]\n"
    "  │  PaymentService.CreatePayment\n"
    "  ▼\n"
    "[TB-3: Service → DB]\n"
    "  │  DB.CreatePayment → INSERT ... VALUES (?,?,?,?,?,?,?,?,?)\n"
    "  ▼\n"
    "SQLite  ← Sink (SQL)\n"
    "  │\n"
    "  └─ AuditService.Log → audit_logs  ← Sink (Audit Log)"
)

h2("3.2. Таблица источников, распространения и sink'ов")
tbl3 = doc.add_table(rows=1, cols=5)
tbl3.style = "Table Grid"
table_header_row(tbl3, ["Источник данных", "Путь распространения", "Sink", "Уязвимость (до)", "Мера защиты (после)"])
srcs = [
    ("recipient_id\n(POST form, web)",
     "PostForm → CreatePayment\n→ DB.CreatePayment",
     "SQL (INSERT)",
     "CWE-20: только length check,\nне regex — пробелы и\nспецсимволы проходили",
     "Allowlist regex ^[A-Z0-9]{8,20}$\n(recipientIDPattern)"),
    ("reason\n(POST flag/reject form)",
     "PostForm → FlagPayment\n→ DB.UpdatePaymentStatus",
     "SQL (UPDATE) +\nAudit Log",
     "CWE-20: max-length отсутствовал;\nможно передать 100 КБ текста",
     "len(reason) > 1000 → 400;\nограничение в обоих обработчиках"),
    ("details, ip_address\n(все audit.Log() вызовы)",
     "c.ClientIP(), user input\n→ AuditService.Log\n→ audit_logs",
     "Audit Log (SQLite\nтаблица audit_logs)",
     "CWE-117: пользователь мог\nвнедрить \\r\\n через детали\nили заголовок X-Forwarded-For",
     "sanitizeLogField() удаляет\nCR/LF/TAB, обрезает до 500 символов"),
    ("paymentID\n(URL param :id, web confirm)",
     "c.Param(\"id\") →\nstrconv.ParseInt (ошибка\nигнорировалась)",
     "PaymentService.ConfirmPayment\n→ DB.GetPaymentByID",
     "CWE-703: ParseInt ошибка игнорирована;\nid=0 мог передаться в запрос",
     "Явная проверка err != nil\nи paymentID <= 0 → 400"),
    ("token JWT cookie\n(Set-Cookie при Login)",
     "authService.Login\n→ c.SetCookie",
     "Cookie (браузер\nклиента)",
     "CWE-614: Secure=false —\ncookie доступен по HTTP",
     "Secure=cfg.CookieSecure\n(по умолчанию true)"),
]
for r in srcs:
    add_row(tbl3, r)

h2("3.3. Фрагменты исправленного кода")

h3("3.3.1 recipientID — allowlist-валидация (CWE-20)")
code_block(
    "// ДО:\n"
    "recipientID := strings.ToUpper(strings.TrimSpace(c.PostForm(\"recipient_id\")))\n"
    "if len(recipientID) < 8 || len(recipientID) > 20 {\n"
    "    c.String(http.StatusOK, `<article class=\"flash error\">...8-20 characters</article>`)\n"
    "    return\n"
    "}"
)
code_block(
    "// ПОСЛЕ:\n"
    "var recipientIDPattern = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)\n"
    "recipientID := strings.ToUpper(strings.TrimSpace(c.PostForm(\"recipient_id\")))\n"
    "if !recipientIDPattern.MatchString(recipientID) {\n"
    "    c.String(http.StatusOK, `<article class=\"flash error\">"
    "Recipient ID: 8-20 uppercase alphanumeric</article>`)\n"
    "    return\n"
    "}"
)
body("Объяснение: до исправления допускались любые символы (включая пробел, кириллицу, "
     "управляющие символы). Теперь применяется тот же allowlist-паттерн, что и в "
     "API-валидаторе (validators.go), устраняя расхождение между API и Web-интерфейсом.")
body("Подтверждение: POST /payments/new c recipient_id='<script>' возвращает ошибку 200 "
     "(flash), запись не создаётся. Gosec: 0 issues.")

h3("3.3.2 Log injection — sanitizeLogField (CWE-117)")
code_block(
    "// ДО:\n"
    "func (s *AuditService) Log(userID *int64, action AuditAction, resourceID *int64,\n"
    "        details, ipAddress string) {\n"
    "    _ = s.db.CreateAuditLog(userID, action, resourceID, details, ipAddress)\n"
    "}"
)
code_block(
    "// ПОСЛЕ:\n"
    "func sanitizeLogField(s string) string {\n"
    "    s = strings.ReplaceAll(s, \"\\r\", \"\")\n"
    "    s = strings.ReplaceAll(s, \"\\n\", \" \")\n"
    "    s = strings.ReplaceAll(s, \"\\t\", \" \")\n"
    "    if len(s) > 500 { s = s[:500] }\n"
    "    return s\n"
    "}\n\n"
    "func (s *AuditService) Log(...) {\n"
    "    _ = s.db.CreateAuditLog(userID, action, resourceID,\n"
    "        sanitizeLogField(details), sanitizeLogField(ipAddress))\n"
    "}"
)

# ═══════════════════════════════════════════════════════════════════════════════
# 4. ЗАДАНИЕ 3 — Auth / Authz / Crypto
# ═══════════════════════════════════════════════════════════════════════════════
doc.add_page_break()
h1("4. Задание 3: Аудит аутентификации, авторизации и криптографии")

h2("4.1. Матрица доступа по ролям")
tbl4 = doc.add_table(rows=1, cols=4)
tbl4.style = "Table Grid"
table_header_row(tbl4, ["Действие / Endpoint", "Аноним", "user", "fraud_analyst"])
roles = [
    ("POST /api/v1/auth/register",         "✓", "—",  "—"),
    ("POST /api/v1/auth/login",            "✓", "—",  "—"),
    ("GET  /api/v1/me",                    "—", "✓",  "✓"),
    ("POST /api/v1/payments",              "—", "✓",  "—"),
    ("GET  /api/v1/payments",              "—", "✓ (только свои)", "—"),
    ("GET  /api/v1/payments/:id",          "—", "✓ (только свои)", "✓ (любой)"),
    ("POST /api/v1/payments/:id/confirm",  "—", "✓ (только свои)", "—"),
    ("GET  /api/v1/analyst/payments/flagged","—","—",  "✓"),
    ("POST /api/v1/analyst/payments/:id/flag","—","—", "✓"),
    ("POST /api/v1/analyst/payments/:id/reject","—","—","✓"),
    ("GET  /api/v1/analyst/audit",         "—", "—",  "✓"),
]
for r in roles:
    add_row(tbl4, r)

h2("4.2. Перечень криптографических и authorization-рисков")

tbl5 = doc.add_table(rows=1, cols=4)
tbl5.style = "Table Grid"
table_header_row(tbl5, ["#", "Риск", "CWE", "Статус"])
crypto_risks = [
    ("1", "JWT Secure cookie flag = false (HTTP)", "CWE-614", "ИСПРАВЛЕНО: cfg.CookieSecure"),
    ("2", "Отсутствие jti в JWT — невозможно отозвать отдельный токен", "CWE-613", "ИСПРАВЛЕНО: jti = crypto/rand 16 байт"),
    ("3", "Роль в JWT не re-валидируется по БД — смена роли вступает в силу только после истечения токена", "CWE-269", "ПРИНЯТО: срок жизни 15 минут; TODO: token revocation list"),
    ("4", "Нет механизма блокировки аккаунта при брутфорсе (только IP rate limit)", "CWE-307", "ЧАСТИЧНО: rate limit 100 req/мин; TODO: lockout counter в БД"),
    ("5", "bcrypt.DefaultCost (10) — приемлем, но не адаптируется к росту мощности CPU", "CWE-916", "ПРИНЯТО: для MVP допустимо; рекомендация: использовать bcrypt.MinCost+2"),
    ("6", "JWT подписывается HMAC-SHA256 — симметричный ключ, хранится в .env", "CWE-321", "ПРИНЯТО: .env не коммитится; рекомендация: Vault/HSM в продакшне"),
]
for r in crypto_risks:
    add_row(tbl5, r)

h2("4.3. Два сценария принятия решения о доступе")

h3("Сценарий A — Легитимный: fraud_analyst просматривает чужой платёж")
code_block(
    "GET /api/v1/payments/42\n"
    "Authorization: Bearer <valid_analyst_token>\n\n"
    "1. AuthMiddleware: JWT parsed → claims{UserID:2, Role:fraud_analyst} → OK\n"
    "2. PaymentHandler.GetPayment → PaymentService.GetPayment(42, 2, fraud_analyst)\n"
    "3. userRole == RoleFraudAnalyst → bypass owner check\n"
    "4. AuditLog: action=payment_viewed, resource_id=42\n"
    "5. → 200 OK (analyst response со fraud_score)"
)

h3("Сценарий B — Запрещённый: обычный user пытается подтвердить чужой платёж")
code_block(
    "POST /api/v1/payments/99/confirm\n"
    "Authorization: Bearer <valid_user_token>  (UserID=5)\n"
    "Payment 99 belongs to UserID=7\n\n"
    "1. AuthMiddleware: JWT valid → claims{UserID:5, Role:user} → OK\n"
    "2. PaymentService.ConfirmPayment(99, 5)\n"
    "3. DB.GetPaymentByID(99) → payment.UserID = 7\n"
    "4. payment.UserID (7) != userID (5) → ErrUnauthorizedAccess\n"
    "5. Handler → 403 Forbidden {\"error\":\"access denied\"}"
)

h2("4.4. Исправления — код до/после")

h3("4.4.1 Cookie Secure flag (CWE-614)")
code_block(
    "// ДО (internal/web/handler.go):\n"
    "c.SetCookie(\"token\", token, 900, \"/\", \"\", false, true)\n"
    "//                                           ^^^^^ Secure=false всегда"
)
code_block(
    "// ПОСЛЕ:\n"
    "// internal/config/config.go:\n"
    "type Config struct {\n"
    "    ...\n"
    "    CookieSecure bool  // из переменной окружения COOKIE_SECURE (default: true)\n"
    "}\n\n"
    "// internal/web/handler.go:\n"
    "c.SetCookie(\"token\", token, 900, \"/\", \"\", h.cookieSecure, true)\n"
    "//                                           ^^^^^^^^^^^^^^ из конфига"
)
body("Подтверждение: при COOKIE_SECURE=true в ответе Set-Cookie присутствует атрибут Secure; "
     "curl через HTTP не получит cookie с Secure=true при корректной HTTPS-настройке.")

h3("4.4.2 JWT ID claim (CWE-613)")
code_block(
    "// ДО (internal/services/auth_service.go):\n"
    "claims := Claims{\n"
    "    RegisteredClaims: jwt.RegisteredClaims{\n"
    "        ExpiresAt: ..., IssuedAt: ..., Subject: user.Email,\n"
    "        // ID отсутствует — токены одного пользователя неразличимы\n"
    "    },\n"
    "}"
)
code_block(
    "// ПОСЛЕ:\n"
    "jtiBytes := make([]byte, 16)\n"
    "rand.Read(jtiBytes)\n"
    "jti := hex.EncodeToString(jtiBytes)\n\n"
    "claims := Claims{\n"
    "    RegisteredClaims: jwt.RegisteredClaims{\n"
    "        ExpiresAt: ..., IssuedAt: ..., Subject: user.Email,\n"
    "        ID: jti,  // уникальный UUID-подобный идентификатор токена\n"
    "    },\n"
    "}"
)

h3("4.4.3 Исправление игнорируемой ошибки ParseInt в ConfirmPayment (CWE-703)")
code_block(
    "// ДО:\n"
    "paymentID, _ := strconv.ParseInt(c.Param(\"id\"), 10, 64)\n"
    "err := h.paymentService.ConfirmPayment(paymentID, user.UserID)"
)
code_block(
    "// ПОСЛЕ:\n"
    "paymentID, err := strconv.ParseInt(c.Param(\"id\"), 10, 64)\n"
    "if err != nil || paymentID <= 0 {\n"
    "    c.String(http.StatusBadRequest, `<p class=\"error\">Invalid payment ID</p>`)\n"
    "    return\n"
    "}\n"
    "err = h.paymentService.ConfirmPayment(paymentID, user.UserID)"
)

h2("4.5. Архитектурное обоснование")
body("1. Роль хранится в JWT, а не перечитывается из БД при каждом запросе. "
     "Это архитектурный компромисс: снижение нагрузки на БД vs задержка применения "
     "смены роли. Для MVP с 15-минутным TTL токена — приемлемо. "
     "В продакшне рекомендуется token introspection или revocation list в Redis.")
body("2. bcrypt.DefaultCost (10) обеспечивает ~100 мс на хеш. При необходимости "
     "переноса на более мощный сервер следует увеличить Cost до 12–13.")
body("3. jti позволяет в будущем реализовать мгновенный отзыв токенов через "
     "таблицу revoked_tokens без перевыпуска всей архитектуры.")

# ═══════════════════════════════════════════════════════════════════════════════
# 5. ЗАДАНИЕ 4 — CVSS v4.0
# ═══════════════════════════════════════════════════════════════════════════════
doc.add_page_break()
h1("5. Задание 4: Оценка уязвимостей по CVSS v4.0")

h2("5.1. Выбранные уязвимости (не повторяющиеся из ПР №4)")
body("В ПР №4 были рассмотрены: G104/CWE-703 (ExecuteTemplate), CWE-521 (пароль), "
     "SQLi, XSS, Path Traversal, Command Injection. Для ПР №5 выбраны 5 новых уязвимостей.")

h2("5.2. Сводная таблица CVSS v4.0")
tbl6 = doc.add_table(rows=1, cols=8)
tbl6.style = "Table Grid"
table_header_row(tbl6, ["№", "Уязвимость\nМодуль/endpoint", "CWE", "CVSS v4.0\nVector",
                         "Score", "Severity", "Обоснование метрик", "Приоритет\nисправления"])

cvss_data = [
    ("1",
     "Отсутствие ограничения\nразмера тела запроса\n(DoS через RAM)\ncmd/server/main.go\n→ все POST endpoints",
     "CWE-400",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
     "8.7",
     "HIGH",
     "AV:N (сеть), AC:L (нет условий),\nAT:N, PR:N (анонимно),\nUI:N, VA:H (DoS сервиса).\nЦелостность не нарушается,\nтолько доступность.",
     "1 — Критический\n(устранено)"),
    ("2",
     "JWT cookie без флага Secure\nПередача по HTTP\ninternal/web/handler.go\nPOST /login, /register",
     "CWE-614",
     "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
     "6.3",
     "MEDIUM",
     "AV:A (локальная сеть / MITM),\nAC:H (нужен перехват трафика),\nUI:P (пользователь должен\nработать по HTTP),\nVC:H (кража токена → полный доступ),\nVI:H (аутентификация от его имени).",
     "2 — Высокий\n(устранено)"),
    ("3",
     "Log Injection через\nпользовательский ввод\ninternal/services/\naudit_service.go\nвсе Log() вызовы",
     "CWE-117",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
     "5.3",
     "MEDIUM",
     "AV:N, AC:L, PR:L (нужна\nаутентификация), UI:N.\nVI:L — злоумышленник вносит\nподдельные строки в аудит,\nчто затрудняет расследование\nинцидентов. Данные не утекают.",
     "3 — Средний\n(устранено)"),
    ("4",
     "Отсутствие jti / отзыва\nJWT токенов\ninternal/services/\nauth_service.go\nPOST /login",
     "CWE-613",
     "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
     "7.3",
     "HIGH",
     "AV:N, AC:H (нужно завладеть\nтокеном через утечку),\nVC:H/VI:H — украденный токен\nостаётся действительным до\nистечения, отзыв невозможен.\nСрок жизни 15 мин смягчает риск.",
     "2 — Высокий\n(jti добавлен;\nrevocation list —\nTODO)"),
    ("5",
     "Allowlist-валидация\nrecipientID отсутствовала\n(только length)\ninternal/web/handler.go\nPOST /payments/new",
     "CWE-20",
     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
     "5.3",
     "MEDIUM",
     "AV:N, AC:L, PR:L (авторизован),\nUI:N.\nVI:L — спецсимволы в поле\nrecipientID могут вызвать\nнеожиданное поведение в\nсмежных системах / отчётах.\nSQL уже защищён параметрами.",
     "3 — Средний\n(устранено)"),
]
for r in cvss_data:
    add_row(tbl6, r)

h2("5.3. Ранжирование по приоритету исправления")
body("1. CWE-400 (Score 8.7) — наивысший приоритет: анонимный DoS, не требует авторизации. Устранено.")
body("2. CWE-613 (Score 7.3) — высокий приоритет: украденный токен нельзя отозвать. jti добавлен, revocation list — roadmap.")
body("3. CWE-614 (Score 6.3) — высокий приоритет: кража сессии через MITM. Устранено флагом Secure.")
body("4. CWE-117 (Score 5.3) — средний приоритет: подделка аудит-журнала. Устранено sanitizeLogField().")
body("5. CWE-20 (Score 5.3) — средний приоритет: слабая валидация ввода. Устранено regex-паттерном.")

h2("5.4. Вывод: CVSS-балл vs реальный приоритет")
body("Высокий CVSS-балл в целом совпадает с реальным приоритетом исправления для данного MVP. "
     "CWE-400 с баллом 8.7 является наиболее опасным в контексте финтех-сервиса, поскольку "
     "DoS-атака на платёжный сервис напрямую нарушает бизнес-процессы и SLA. "
     "CWE-613 (балл 7.3) формально высокий, но смягчён 15-минутным TTL токена — "
     "реальный риск ниже максимального. "
     "CWE-614 (балл 6.3) — в production-среде с обязательным HTTPS риск минимален, "
     "поэтому несмотря на «MEDIUM» балл, исправление было реализовано немедленно "
     "как architectural best practice. "
     "CWE-117 и CWE-20 имеют одинаковый балл 5.3, но CWE-117 приоритетнее с точки зрения "
     "compliance (GDPR, PCI DSS требуют целостности audit trail).")

# ═══════════════════════════════════════════════════════════════════════════════
# 6. РЕЗУЛЬТАТЫ SAST / SCA
# ═══════════════════════════════════════════════════════════════════════════════
doc.add_page_break()
h1("6. Результаты SAST (gosec) и SCA (govulncheck) после исправлений")

h2("6.1. Gosec — после всех исправлений")
code_block(
    "$ gosec ./...\n\n"
    "Results:\n\n"
    "Summary:\n"
    "  Gosec  : dev\n"
    "  Files  : 21\n"
    "  Lines  : 2198\n"
    "  Nosec  : 0\n"
    "  Issues : 0   ← нет проблем"
)

h2("6.2. Govulncheck — анализ зависимостей")
code_block(
    "$ govulncheck ./...\n\n"
    "=== Symbol Results ===\n"
    "No vulnerabilities found.\n"
    "Your code is affected by 0 vulnerabilities.\n\n"
    "This scan also found 2 vulnerabilities in packages you import and 4\n"
    "vulnerabilities in modules you require, but your code doesn't appear\n"
    "to call these vulnerabilities.\n"
    "(GO-2026-4440, GO-2026-4441 — golang.org/x/net/html; не вызывается в коде)"
)

# ═══════════════════════════════════════════════════════════════════════════════
# 7. ВЫВОД
# ═══════════════════════════════════════════════════════════════════════════════
doc.add_page_break()
h1("7. Вывод по работе")
body(
    "В ходе практической работы №5 проведён углублённый комплексный аудит безопасности "
    "MVP-системы fintech-payments-mvp по четырём направлениям."
)
doc.add_paragraph()
body(
    "По итогам аудита выявлено и устранено 9 уязвимостей/недостатков, из которых "
    "5 оценены по CVSS v4.0 (баллы 5.3–8.7). Все критические дефекты исправлены в коде; "
    "инструмент gosec подтверждает 0 проблем. Govulncheck не выявил уязвимостей в "
    "вызываемых символах."
)
body(
    "Наиболее значимые улучшения: (1) защита от DoS-атак через тело запроса "
    "(MaxBodySizeMiddleware); (2) устранение log injection через sanitizeLogField; "
    "(3) корректная работа флага Secure на JWT-cookie через конфигурацию; "
    "(4) добавление jti для будущей поддержки отзыва токенов; "
    "(5) согласованная allowlist-валидация recipientID между Web- и API-интерфейсами."
)
body(
    "Архитектура MVP демонстрирует высокий уровень зрелости безопасности: "
    "параметризованные SQL-запросы исключают инъекции, html/template обеспечивает "
    "автоматическое экранирование XSS, ролевая модель корректно реализует "
    "object-level access control. Оставшиеся риски (revocation list, account lockout) "
    "задокументированы как roadmap-элементы для продакшн-деплоя."
)

# ─── Save ─────────────────────────────────────────────────────────────────────
doc.save("securep5.docx")
print("✓  securep5.docx saved")
