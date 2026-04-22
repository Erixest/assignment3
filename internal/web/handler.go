package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"

	"fintech-payments-mvp/internal/config"
	"fintech-payments-mvp/internal/database"
	"fintech-payments-mvp/internal/models"
	"fintech-payments-mvp/internal/services"
)

// recipientIDPattern enforces an allowlist of uppercase alphanumeric characters
// (8–20 chars) matching the same constraint applied in the API validator (CWE-20).
var recipientIDPattern = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)

// validatePassword enforces strong password complexity requirements (CWE-521).
// Returns a non-empty error message string if the password fails any check,
// or an empty string if the password is acceptable.
// Rules: 8–72 characters, at least one uppercase, one lowercase, one digit,
// and one special character from the allowed set.
func validatePassword(password string) string {
	const specialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
	if len(password) < 8 {
		return "Password must be at least 8 characters"
	}
	if len(password) > 72 {
		return "Password must not exceed 72 characters (bcrypt limit)"
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune(specialChars, r):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return "Password must contain at least one uppercase letter (A-Z)"
	}
	if !hasLower {
		return "Password must contain at least one lowercase letter (a-z)"
	}
	if !hasDigit {
		return "Password must contain at least one digit (0-9)"
	}
	if !hasSpecial {
		return "Password must contain at least one special character (!@#$%^&*...)"
	}
	return ""
}

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type WebHandler struct {
	templates      *template.Template
	authService    *services.AuthService
	paymentService *services.PaymentService
	auditService   *services.AuditService
	db             *database.DB
	cookieSecure   bool
}

type PageData struct {
	Title     string
	User      *services.Claims
	Flash     string
	FlashType string
	Data      interface{}
}

type AnalystStats struct {
	Flagged  int
	HighRisk int
	Rejected int
}

func NewWebHandler(authService *services.AuthService, paymentService *services.PaymentService, auditService *services.AuditService, db *database.DB, cfg *config.Config) *WebHandler {
	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))

	return &WebHandler{
		templates:      tmpl,
		authService:    authService,
		paymentService: paymentService,
		auditService:   auditService,
		db:             db,
		cookieSecure:   cfg.CookieSecure,
	}
}

func (h *WebHandler) RegisterRoutes(r *gin.Engine) {
	staticSubFS, _ := fs.Sub(staticFS, "static")
	r.StaticFS("/static", http.FS(staticSubFS))

	r.GET("/", h.Home)
	r.GET("/login", h.LoginPage)
	r.POST("/login", h.Login)
	r.GET("/register", h.RegisterPage)
	r.POST("/register", h.Register)
	r.POST("/logout", h.Logout)

	r.GET("/payments", h.authRequired(h.PaymentsPage))
	r.GET("/payments/list", h.authRequired(h.PaymentsList))
	r.GET("/payments/new", h.authRequired(h.PaymentNewPage))
	r.POST("/payments/new", h.authRequired(h.CreatePayment))
	r.POST("/payments/:id/confirm", h.authRequired(h.ConfirmPayment))

	r.GET("/analyst", h.analystRequired(h.AnalystPage))
	r.GET("/analyst/payments/list", h.analystRequired(h.AnalystPaymentsList))
	r.GET("/analyst/payments/:id/flag-form", h.analystRequired(h.FlagForm))
	r.POST("/analyst/payments/:id/flag", h.analystRequired(h.FlagPayment))
	r.GET("/analyst/payments/:id/reject-form", h.analystRequired(h.RejectForm))
	r.POST("/analyst/payments/:id/reject", h.analystRequired(h.RejectPayment))
	r.GET("/analyst/audit/list", h.analystRequired(h.AuditList))
}

func (h *WebHandler) render(c *gin.Context, name string, data PageData) {
	data.User = h.getCurrentUser(c)
	c.Header("Content-Type", "text/html; charset=utf-8")

	var tmpl *template.Template
	var err error

	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}

	tmpl, err = template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/layout.html", "templates/"+name)
	if err != nil {
		c.String(http.StatusInternalServerError, "Template parse error: "+err.Error())
		return
	}

	err = tmpl.ExecuteTemplate(c.Writer, "layout.html", data)
	if err != nil {
		c.String(http.StatusInternalServerError, "Template exec error: "+err.Error())
	}
}

func (h *WebHandler) renderPartial(c *gin.Context, name string, data interface{}) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	// FIX: G104 (CWE-703) — ошибка ExecuteTemplate теперь обрабатывается явно.
	// Ранее ошибка рендеринга молча игнорировалась, что могло приводить к
	// отправке клиенту пустого или частично сформированного ответа без
	// каких-либо признаков сбоя на стороне сервера.
	// РАНЕЕ: h.templates.ExecuteTemplate(c.Writer, name, data)
	if err := h.templates.ExecuteTemplate(c.Writer, name, data); err != nil {
		c.String(http.StatusInternalServerError, "Template render error: "+err.Error())
	}
}

func (h *WebHandler) getCurrentUser(c *gin.Context) *services.Claims {
	cookie, err := c.Cookie("token")
	if err != nil || cookie == "" {
		return nil
	}

	claims, err := h.authService.ValidateToken(cookie)
	if err != nil {
		return nil
	}

	return claims
}

func (h *WebHandler) authRequired(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.getCurrentUser(c) == nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		handler(c)
	}
}

func (h *WebHandler) analystRequired(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := h.getCurrentUser(c)
		if user == nil {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		if user.Role != models.RoleFraudAnalyst {
			c.Redirect(http.StatusFound, "/")
			return
		}
		handler(c)
	}
}

func (h *WebHandler) Home(c *gin.Context) {
	h.render(c, "home.html", PageData{Title: "Home"})
}

func (h *WebHandler) LoginPage(c *gin.Context) {
	if h.getCurrentUser(c) != nil {
		c.Redirect(http.StatusFound, "/payments")
		return
	}
	h.render(c, "login.html", PageData{Title: "Login"})
}

func (h *WebHandler) Login(c *gin.Context) {
	email := strings.TrimSpace(c.PostForm("email"))
	password := c.PostForm("password")

	user, token, err := h.authService.Login(email, password)
	if err != nil {
		h.auditService.Log(nil, models.AuditActionLoginFailed, nil, "web login failed", c.ClientIP())
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Invalid email or password</article>`)
		return
	}

	h.auditService.Log(&user.ID, models.AuditActionLogin, nil, "web login", c.ClientIP())
	// FIX: CWE-614 — флаг Secure теперь управляется конфигурацией (COOKIE_SECURE=true).
	// Ранее был жёстко установлен в false, что допускало передачу cookie по HTTP.
	c.SetCookie("token", token, 900, "/", "", h.cookieSecure, true)
	c.Header("HX-Redirect", "/payments")
	c.Status(http.StatusOK)
}

func (h *WebHandler) RegisterPage(c *gin.Context) {
	if h.getCurrentUser(c) != nil {
		c.Redirect(http.StatusFound, "/payments")
		return
	}
	h.render(c, "register.html", PageData{Title: "Register"})
}

func (h *WebHandler) Register(c *gin.Context) {
	email := strings.TrimSpace(c.PostForm("email"))
	password := c.PostForm("password")
	passwordConfirm := c.PostForm("password_confirm")

	if password != passwordConfirm {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Passwords do not match</article>`)
		return
	}

	// FIX: CWE-521 — усиленная проверка сложности пароля.
	// Ранее проверялась только длина (>= 8 символов).
	// Теперь обязательны: заглавная, строчная буква, цифра и спецсимвол.
	if errMsg := validatePassword(password); errMsg != "" {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">`+errMsg+`</article>`)
		return
	}

	user, err := h.authService.Register(email, password, models.RoleUser)
	if err != nil {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Email already registered</article>`)
		return
	}

	h.auditService.Log(&user.ID, models.AuditActionRegister, nil, "web registration", c.ClientIP())

	_, token, _ := h.authService.Login(email, password)
	// FIX: CWE-614 — аналогично Login, флаг Secure из конфигурации.
	c.SetCookie("token", token, 900, "/", "", h.cookieSecure, true)
	c.Header("HX-Redirect", "/payments")
	c.Status(http.StatusOK)
}

func (h *WebHandler) Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true)
	c.Header("HX-Redirect", "/")
	c.Status(http.StatusOK)
}

func (h *WebHandler) PaymentsPage(c *gin.Context) {
	h.render(c, "payments.html", PageData{Title: "Payments"})
}

func (h *WebHandler) PaymentsList(c *gin.Context) {
	user := h.getCurrentUser(c)
	payments, _ := h.paymentService.GetUserPayments(user.UserID, 50, 0)

	h.renderPartial(c, "payments_list.html", gin.H{"Payments": payments})
}

func (h *WebHandler) PaymentNewPage(c *gin.Context) {
	h.render(c, "payment_new.html", PageData{Title: "New Payment"})
}

func (h *WebHandler) CreatePayment(c *gin.Context) {
	user := h.getCurrentUser(c)

	amountStr := c.PostForm("amount")
	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil || amount <= 0 || amount > 1000000 {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Invalid amount (0.01 - 1,000,000)</article>`)
		return
	}

	currency := models.Currency(c.PostForm("currency"))
	if !models.ValidCurrencies[currency] {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Invalid currency</article>`)
		return
	}

	recipientID := strings.ToUpper(strings.TrimSpace(c.PostForm("recipient_id")))
	// FIX: CWE-20 — allowlist-валидация recipientID через регулярное выражение.
	// Ранее проверялась только длина (8–20 символов), что допускало произвольные
	// символы (пробелы, спецсимволы, символы Unicode). Теперь применяется
	// тот же паттерн ^[A-Z0-9]{8,20}$, что и в API-валидаторе.
	if !recipientIDPattern.MatchString(recipientID) {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Recipient ID must be 8-20 uppercase alphanumeric characters</article>`)
		return
	}

	description := strings.TrimSpace(c.PostForm("description"))
	if len(description) > 500 {
		description = description[:500]
	}

	payment, err := h.paymentService.CreatePayment(user.UserID, amount, currency, recipientID, description)
	if err != nil {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Failed to create payment</article>`)
		return
	}

	h.auditService.Log(&user.UserID, models.AuditActionPaymentCreated, &payment.ID, "web payment", c.ClientIP())

	c.Header("HX-Redirect", "/payments")
	c.Status(http.StatusOK)
}

func (h *WebHandler) ConfirmPayment(c *gin.Context) {
	user := h.getCurrentUser(c)
	// FIX: CWE-703 — обработка ошибки разбора paymentID.
	// Ранее ошибка strconv.ParseInt молча игнорировалась, что при невалидном
	// параметре приводило к попытке подтвердить платёж с ID=0.
	paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || paymentID <= 0 {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusBadRequest, `<p class="error">Invalid payment ID</p>`)
		return
	}

	err = h.paymentService.ConfirmPayment(paymentID, user.UserID)
	if err != nil {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<p class="error">Cannot confirm this payment</p>`)
		return
	}

	h.auditService.Log(&user.UserID, models.AuditActionPaymentConfirm, &paymentID, "web confirm", c.ClientIP())

	payments, _ := h.paymentService.GetUserPayments(user.UserID, 50, 0)
	h.renderPartial(c, "payments_list.html", gin.H{"Payments": payments})
}

func (h *WebHandler) AnalystPage(c *gin.Context) {
	// FIX: CWE-400 — ограничение выборки при загрузке страницы аналитика.
	// Ранее загружалось до 100 записей без явного ограничения на уровне бизнес-логики.
	// Теперь используется безопасное значение по умолчанию (50).
	flagged, _ := h.paymentService.GetFlaggedPayments(50, 0)

	stats := AnalystStats{}
	for _, p := range flagged {
		if p.Status == models.PaymentStatusFlagged {
			stats.Flagged++
		}
		if p.FraudScore > 0.7 {
			stats.HighRisk++
		}
		if p.Status == models.PaymentStatusRejected {
			stats.Rejected++
		}
	}

	h.render(c, "analyst.html", PageData{
		Title: "Analyst Dashboard",
		Data:  gin.H{"Stats": stats},
	})
}

func (h *WebHandler) AnalystPaymentsList(c *gin.Context) {
	payments, _ := h.paymentService.GetFlaggedPayments(50, 0)
	h.renderPartial(c, "analyst_payments.html", gin.H{"Payments": payments})
}

func (h *WebHandler) FlagForm(c *gin.Context) {
	paymentID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	user := h.getCurrentUser(c)

	payment, err := h.paymentService.GetPayment(paymentID, user.UserID, user.Role)
	if err != nil {
		c.String(http.StatusNotFound, "Payment not found")
		return
	}

	h.renderPartial(c, "flag_form.html", gin.H{"Payment": payment})
}

func (h *WebHandler) FlagPayment(c *gin.Context) {
	user := h.getCurrentUser(c)
	paymentID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	reason := strings.TrimSpace(c.PostForm("reason"))

	if len(reason) < 10 {
		c.String(http.StatusBadRequest, "Reason must be at least 10 characters")
		return
	}
	// FIX: CWE-20 — ограничение максимальной длины поля reason.
	// Ранее отсутствовала верхняя граница, что допускало передачу произвольно
	// большого текста в базу данных и журнал аудита.
	if len(reason) > 1000 {
		c.String(http.StatusBadRequest, "Reason must not exceed 1000 characters")
		return
	}

	err := h.paymentService.FlagPayment(paymentID, user.UserID, reason)
	if err != nil {
		c.String(http.StatusBadRequest, "Cannot flag payment")
		return
	}

	h.auditService.Log(&user.UserID, models.AuditActionPaymentFlagged, &paymentID, "web flag", c.ClientIP())

	payments, _ := h.paymentService.GetFlaggedPayments(50, 0)
	h.renderPartial(c, "analyst_payments.html", gin.H{"Payments": payments})
}

func (h *WebHandler) RejectForm(c *gin.Context) {
	paymentID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	user := h.getCurrentUser(c)

	payment, err := h.paymentService.GetPayment(paymentID, user.UserID, user.Role)
	if err != nil {
		c.String(http.StatusNotFound, "Payment not found")
		return
	}

	h.renderPartial(c, "reject_form.html", gin.H{"Payment": payment})
}

func (h *WebHandler) RejectPayment(c *gin.Context) {
	user := h.getCurrentUser(c)
	paymentID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	reason := strings.TrimSpace(c.PostForm("reason"))

	if len(reason) < 10 {
		c.String(http.StatusBadRequest, "Reason must be at least 10 characters")
		return
	}
	// FIX: CWE-20 — ограничение максимальной длины поля reason (аналогично FlagPayment).
	if len(reason) > 1000 {
		c.String(http.StatusBadRequest, "Reason must not exceed 1000 characters")
		return
	}

	err := h.paymentService.RejectPayment(paymentID, user.UserID, reason)
	if err != nil {
		c.String(http.StatusBadRequest, "Cannot reject payment")
		return
	}

	h.auditService.Log(&user.UserID, models.AuditActionPaymentRejected, &paymentID, "web reject", c.ClientIP())

	payments, _ := h.paymentService.GetFlaggedPayments(50, 0)
	h.renderPartial(c, "analyst_payments.html", gin.H{"Payments": payments})
}

func (h *WebHandler) AuditList(c *gin.Context) {
	logs, _ := h.auditService.GetLogs(30, 0)
	h.renderPartial(c, "analyst_audit.html", gin.H{"Logs": logs})
}
