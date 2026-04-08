package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"fintech-payments-mvp/internal/database"
	"fintech-payments-mvp/internal/models"
	"fintech-payments-mvp/internal/services"
)

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

func NewWebHandler(authService *services.AuthService, paymentService *services.PaymentService, auditService *services.AuditService, db *database.DB) *WebHandler {
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
	h.templates.ExecuteTemplate(c.Writer, name, data)
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
	c.SetCookie("token", token, 900, "/", "", false, true)
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

	if len(password) < 8 {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Password must be at least 8 characters</article>`)
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
	c.SetCookie("token", token, 900, "/", "", false, true)
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
	if len(recipientID) < 8 || len(recipientID) > 20 {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `<article class="flash error">Recipient ID must be 8-20 characters</article>`)
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
	paymentID, _ := strconv.ParseInt(c.Param("id"), 10, 64)

	err := h.paymentService.ConfirmPayment(paymentID, user.UserID)
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
	flagged, _ := h.paymentService.GetFlaggedPayments(100, 0)

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
