package web

import (
"embed"
"encoding/base64"
"encoding/csv"
"fmt"
"html/template"
"io/fs"
"net/http"
"regexp"
"strconv"
"strings"
"time"
"unicode"

qrcode "github.com/skip2/go-qrcode"

"github.com/gin-gonic/gin"

"fintech-payments-mvp/internal/config"
"fintech-payments-mvp/internal/database"
"fintech-payments-mvp/internal/models"
"fintech-payments-mvp/internal/services"
)

var recipientIDPattern = regexp.MustCompile(`^[A-Z0-9]{8,20}$`)

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
otpService     *services.OTPService
db             *database.DB
cookieSecure   bool
}

type PageData struct {
Title     string
User      *services.Claims
Flash     string
FlashType string
Data      interface{}
CSRF      string
}

type AnalystStats struct {
Flagged  int
HighRisk int
Rejected int
}

func buildFuncMap() template.FuncMap {
	return template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
		"fmtAmount": func(amount float64, currency models.Currency) string {
			s := fmt.Sprintf("%.2f", amount)
			parts := strings.SplitN(s, ".", 2)
			intPart := parts[0]
			var out strings.Builder
			n := len(intPart)
			for i, ch := range intPart {
				if i > 0 && (n-i)%3 == 0 {
					out.WriteByte(',')
				}
				out.WriteRune(ch)
			}
			return out.String() + "." + parts[1] + "\u00a0" + string(currency)
		},
		"fmtDate": func(t time.Time) string {
			return t.Format("02 Jan 2006, 15:04")
		},
		"fmtStatus": func(s models.PaymentStatus) string {
			if len(s) == 0 {
				return ""
			}
			return strings.ToUpper(string(s[0])) + string(s[1:])
		},
	}
}

func NewWebHandler(authService *services.AuthService, paymentService *services.PaymentService, auditService *services.AuditService, otpService *services.OTPService, db *database.DB, cfg *config.Config) *WebHandler {
	tmpl := template.Must(template.New("").Funcs(buildFuncMap()).ParseFS(templateFS, "templates/*.html"))

	return &WebHandler{
		templates:      tmpl,
		authService:    authService,
paymentService: paymentService,
auditService:   auditService,
otpService:     otpService,
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

r.GET("/otp/verify", h.OTPVerifyPage)
r.POST("/otp/verify", h.OTPVerifySubmit)

r.GET("/payments", h.authRequired(h.PaymentsPage))
r.GET("/payments/list", h.authRequired(h.PaymentsList))
r.GET("/payments/new", h.authRequired(h.PaymentNewPage))
r.POST("/payments/new", h.authRequired(h.CreatePayment))
r.POST("/payments/:id/confirm", h.authRequired(h.ConfirmPayment))
r.GET("/payments/export.csv", h.authRequired(h.ExportPaymentsCSV))

r.GET("/profile", h.authRequired(h.ProfilePage))
r.GET("/profile/otp/setup", h.authRequired(h.OTPSetupPage))
r.POST("/profile/otp/setup", h.authRequired(h.OTPSetupSubmit))
r.POST("/profile/otp/disable", h.authRequired(h.OTPDisable))

r.GET("/analyst", h.analystRequired(h.AnalystPage))
r.GET("/analyst/payments/list", h.analystRequired(h.AnalystPaymentsList))
r.GET("/analyst/payments/:id/flag-form", h.analystRequired(h.FlagForm))
r.POST("/analyst/payments/:id/flag", h.analystRequired(h.FlagPayment))
r.GET("/analyst/payments/:id/reject-form", h.analystRequired(h.RejectForm))
r.POST("/analyst/payments/:id/reject", h.analystRequired(h.RejectPayment))
r.GET("/analyst/audit/list", h.analystRequired(h.AuditList))
}

func (h *WebHandler) csrfToken(c *gin.Context) string {
cookie, err := c.Cookie("token")
if err != nil || cookie == "" {
return ""
}
return h.authService.GenerateCSRFToken(cookie)
}

func (h *WebHandler) validateCSRF(c *gin.Context) bool {
cookie, err := c.Cookie("token")
if err != nil || cookie == "" {
return false
}
submitted := c.PostForm("_csrf")
return h.authService.ValidateCSRFToken(cookie, submitted)
}

func (h *WebHandler) render(c *gin.Context, name string, data PageData) {
data.User = h.getCurrentUser(c)
data.CSRF = h.csrfToken(c)
c.Header("Content-Type", "text/html; charset=utf-8")

tmpl, err := template.New("").Funcs(buildFuncMap()).ParseFS(templateFS, "templates/layout.html", "templates/"+name)
if err != nil {
c.String(http.StatusInternalServerError, "Internal server error")
return
}

err = tmpl.ExecuteTemplate(c.Writer, "layout.html", data)
if err != nil {
c.String(http.StatusInternalServerError, "Internal server error")
}
}

func (h *WebHandler) renderPartial(c *gin.Context, name string, data interface{}) {
c.Header("Content-Type", "text/html; charset=utf-8")
if err := h.templates.ExecuteTemplate(c.Writer, name, data); err != nil {
c.String(http.StatusInternalServerError, "Internal server error")
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
if err == services.ErrAccountLocked {
h.auditService.Log(nil, models.AuditActionLoginFailed, nil, "account locked", c.ClientIP())
c.Header("Content-Type", "text/html")
c.String(http.StatusOK, `<article class="flash error">Account temporarily locked. Try again in 15 minutes.</article>`)
return
}
h.auditService.Log(nil, models.AuditActionLoginFailed, nil, "web login failed", c.ClientIP())
c.Header("Content-Type", "text/html")
c.String(http.StatusOK, `<article class="flash error">Invalid email or password</article>`)
return
}

if token == "otp_required" {
pendingToken, err := h.otpService.CreatePendingToken(user.ID)
if err != nil {
c.Header("Content-Type", "text/html")
c.String(http.StatusOK, `<article class="flash error">Internal error</article>`)
return
}
h.auditService.Log(&user.ID, models.AuditActionLogin, nil, "otp required", c.ClientIP())
c.Header("HX-Redirect", "/otp/verify?token="+pendingToken)
c.Status(http.StatusOK)
return
}

h.auditService.Log(&user.ID, models.AuditActionLogin, nil, "web login", c.ClientIP())
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
c.SetCookie("token", token, 900, "/", "", h.cookieSecure, true)
c.Header("HX-Redirect", "/payments")
c.Status(http.StatusOK)
}

func (h *WebHandler) Logout(c *gin.Context) {
c.SetCookie("token", "", -1, "/", "", false, true)
c.Header("HX-Redirect", "/")
c.Status(http.StatusOK)
}

func (h *WebHandler) OTPVerifyPage(c *gin.Context) {
pendingToken := c.Query("token")
h.render(c, "otp_verify.html", PageData{Title: "Verify OTP", Data: gin.H{"PendingToken": pendingToken}})
}

func (h *WebHandler) OTPVerifySubmit(c *gin.Context) {
pendingToken := c.PostForm("pending_token")
code := c.PostForm("code")

userID, err := h.otpService.VerifyPendingToken(pendingToken)
if err != nil {
h.auditService.Log(nil, models.AuditActionOTPFailed, nil, "invalid pending token", c.ClientIP())
h.render(c, "otp_verify.html", PageData{
Title:     "Verify OTP",
Flash:     "Invalid or expired session",
FlashType: "error",
Data:      gin.H{"PendingToken": pendingToken},
})
return
}

user, err := h.authService.GetUserByID(userID)
if err != nil {
h.render(c, "otp_verify.html", PageData{Title: "Verify OTP", Flash: "User not found", FlashType: "error"})
return
}

if !h.otpService.Validate(user.OTPSecret, code) {
newToken, _ := h.otpService.CreatePendingToken(userID)
h.auditService.Log(&userID, models.AuditActionOTPFailed, nil, "wrong otp code", c.ClientIP())
h.render(c, "otp_verify.html", PageData{
Title:     "Verify OTP",
Flash:     "Invalid code, try again",
FlashType: "error",
Data:      gin.H{"PendingToken": newToken},
})
return
}

token, err := h.authService.GenerateTokenForUser(user)
if err != nil {
h.render(c, "otp_verify.html", PageData{Title: "Verify OTP", Flash: "Internal error", FlashType: "error"})
return
}

h.auditService.Log(&userID, models.AuditActionOTPVerified, nil, "otp verified", c.ClientIP())
c.SetCookie("token", token, 900, "/", "", h.cookieSecure, true)
c.Redirect(http.StatusFound, "/payments")
}

func (h *WebHandler) ProfilePage(c *gin.Context) {
userClaims := h.getCurrentUser(c)
user, _ := h.authService.GetUserByID(userClaims.UserID)
h.render(c, "profile.html", PageData{Title: "Profile", Data: gin.H{"UserDetail": user}})
}

func (h *WebHandler) OTPSetupPage(c *gin.Context) {
userClaims := h.getCurrentUser(c)
secret, otpURL, err := h.otpService.GenerateSecret(userClaims.Email)
if err != nil {
h.render(c, "otp_setup.html", PageData{Title: "Setup OTP", Flash: "Failed to generate secret", FlashType: "error"})
return
}

var qrDataURI string
if pngBytes, qrErr := qrcode.Encode(otpURL, qrcode.Medium, 256); qrErr == nil {
qrDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)
}

h.render(c, "otp_setup.html", PageData{
Title: "Setup OTP",
Data:  gin.H{"Secret": secret, "URL": otpURL, "QR": qrDataURI},
CSRF:  h.csrfToken(c),
})
}

func (h *WebHandler) OTPSetupSubmit(c *gin.Context) {
if !h.validateCSRF(c) {
c.String(http.StatusForbidden, "Invalid CSRF token")
return
}
userClaims := h.getCurrentUser(c)
secret := c.PostForm("secret")
code := c.PostForm("code")

if !h.otpService.Validate(secret, code) {
h.render(c, "otp_setup.html", PageData{
Title:     "Setup OTP",
Flash:     "Invalid code. Please scan QR and enter the 6-digit code.",
FlashType: "error",
Data:      gin.H{"Secret": secret, "URL": ""},
})
return
}

if err := h.otpService.Enable(userClaims.UserID, secret); err != nil {
h.render(c, "otp_setup.html", PageData{Title: "Setup OTP", Flash: "Failed to enable OTP", FlashType: "error"})
return
}

h.auditService.Log(&userClaims.UserID, models.AuditActionOTPEnabled, nil, "otp enabled via web", c.ClientIP())
c.Redirect(http.StatusFound, "/profile?otp=enabled")
}

func (h *WebHandler) OTPDisable(c *gin.Context) {
if !h.validateCSRF(c) {
c.String(http.StatusForbidden, "Invalid CSRF token")
return
}
userClaims := h.getCurrentUser(c)
h.otpService.Disable(userClaims.UserID)
h.auditService.Log(&userClaims.UserID, models.AuditActionOTPDisabled, nil, "otp disabled via web", c.ClientIP())
c.Redirect(http.StatusFound, "/profile?otp=disabled")
}

func (h *WebHandler) PaymentsPage(c *gin.Context) {
h.render(c, "payments.html", PageData{Title: "Payments"})
}

func (h *WebHandler) PaymentsList(c *gin.Context) {
user := h.getCurrentUser(c)
payments, _ := h.paymentService.GetUserPayments(user.UserID, 50, 0)
h.renderPartial(c, "payments_list.html", gin.H{"Payments": payments, "CSRF": h.csrfToken(c)})
}

func (h *WebHandler) PaymentNewPage(c *gin.Context) {
h.render(c, "payment_new.html", PageData{Title: "New Payment"})
}

func (h *WebHandler) CreatePayment(c *gin.Context) {
if !h.validateCSRF(c) {
c.Header("Content-Type", "text/html")
c.String(http.StatusForbidden, `<article class="flash error">Invalid CSRF token</article>`)
return
}
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

h.renderPartial(c, "payment_receipt.html", payment)
}

func (h *WebHandler) ConfirmPayment(c *gin.Context) {
if !h.validateCSRF(c) {
c.Header("Content-Type", "text/html")
c.String(http.StatusForbidden, `<p class="error">Invalid CSRF token</p>`)
return
}
user := h.getCurrentUser(c)
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
h.renderPartial(c, "payments_list.html", gin.H{"Payments": payments, "CSRF": h.csrfToken(c)})
}

func (h *WebHandler) ExportPaymentsCSV(c *gin.Context) {
user := h.getCurrentUser(c)
payments, err := h.paymentService.GetUserPayments(user.UserID, 1000, 0)
if err != nil {
c.Status(http.StatusInternalServerError)
return
}

c.Header("Content-Disposition", `attachment; filename="payments.csv"`)
c.Header("Content-Type", "text/csv; charset=utf-8")

w := csv.NewWriter(c.Writer)
w.Write([]string{"ReceiptID", "ID", "Amount", "Currency", "RecipientID", "Description", "Status", "CreatedAt"})
for _, p := range payments {
w.Write([]string{
p.ReceiptID,
strconv.FormatInt(p.ID, 10),
strconv.FormatFloat(p.Amount, 'f', 2, 64),
string(p.Currency),
p.RecipientID,
p.Description,
string(p.Status),
p.CreatedAt.Format(time.RFC3339),
})
}
w.Flush()

h.auditService.Log(&user.UserID, models.AuditActionCSVExported, nil, "payments exported", c.ClientIP())
}

func (h *WebHandler) AnalystPage(c *gin.Context) {
flagged, _ := h.paymentService.GetFlaggedPayments(50, 0)

stats := AnalystStats{}
for _, p := range flagged {
if p.Status == models.PaymentStatusFlagged {
stats.Flagged++
}
if p.FraudScore > 0.5 {
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
paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
if err != nil || paymentID <= 0 {
c.String(http.StatusBadRequest, "Invalid payment ID")
return
}
user := h.getCurrentUser(c)

payment, err := h.paymentService.GetPayment(paymentID, user.UserID, user.Role)
if err != nil {
c.String(http.StatusNotFound, "Payment not found")
return
}

h.renderPartial(c, "flag_form.html", gin.H{"Payment": payment, "CSRF": h.csrfToken(c)})
}

func (h *WebHandler) FlagPayment(c *gin.Context) {
if !h.validateCSRF(c) {
c.String(http.StatusForbidden, "Invalid CSRF token")
return
}
user := h.getCurrentUser(c)
paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
if err != nil || paymentID <= 0 {
c.String(http.StatusBadRequest, "Invalid payment ID")
return
}
reason := strings.TrimSpace(c.PostForm("reason"))

if len(reason) < 10 {
c.String(http.StatusBadRequest, "Reason must be at least 10 characters")
return
}
if len(reason) > 1000 {
c.String(http.StatusBadRequest, "Reason must not exceed 1000 characters")
return
}

err = h.paymentService.FlagPayment(paymentID, user.UserID, reason)
if err != nil {
c.String(http.StatusBadRequest, "Cannot flag payment")
return
}

h.auditService.Log(&user.UserID, models.AuditActionPaymentFlagged, &paymentID, "web flag", c.ClientIP())

payments, _ := h.paymentService.GetFlaggedPayments(50, 0)
h.renderPartial(c, "analyst_payments.html", gin.H{"Payments": payments})
}

func (h *WebHandler) RejectForm(c *gin.Context) {
paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
if err != nil || paymentID <= 0 {
c.String(http.StatusBadRequest, "Invalid payment ID")
return
}
user := h.getCurrentUser(c)

payment, err := h.paymentService.GetPayment(paymentID, user.UserID, user.Role)
if err != nil {
c.String(http.StatusNotFound, "Payment not found")
return
}

h.renderPartial(c, "reject_form.html", gin.H{"Payment": payment, "CSRF": h.csrfToken(c)})
}

func (h *WebHandler) RejectPayment(c *gin.Context) {
if !h.validateCSRF(c) {
c.String(http.StatusForbidden, "Invalid CSRF token")
return
}
user := h.getCurrentUser(c)
paymentID, err := strconv.ParseInt(c.Param("id"), 10, 64)
if err != nil || paymentID <= 0 {
c.String(http.StatusBadRequest, "Invalid payment ID")
return
}
reason := strings.TrimSpace(c.PostForm("reason"))

if len(reason) < 10 {
c.String(http.StatusBadRequest, "Reason must be at least 10 characters")
return
}
if len(reason) > 1000 {
c.String(http.StatusBadRequest, "Reason must not exceed 1000 characters")
return
}

err = h.paymentService.RejectPayment(paymentID, user.UserID, reason)
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
