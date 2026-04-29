package main

import (
"log"
"os"

"github.com/gin-gonic/gin"
"github.com/joho/godotenv"

"fintech-payments-mvp/internal/config"
"fintech-payments-mvp/internal/database"
"fintech-payments-mvp/internal/handlers"
"fintech-payments-mvp/internal/middleware"
"fintech-payments-mvp/internal/models"
"fintech-payments-mvp/internal/services"
"fintech-payments-mvp/internal/web"
)

func main() {
if err := godotenv.Load(); err != nil {
log.Println("No .env file found, using environment variables")
}

cfg := config.Load()
if err := cfg.Validate(); err != nil {
log.Fatalf("Configuration error: %v", err)
}

db, err := database.New(cfg.DatabasePath)
if err != nil {
log.Fatalf("Database error: %v", err)
}
defer db.Close()

authService := services.NewAuthService(db, cfg)
paymentService := services.NewPaymentService(db)
auditService := services.NewAuditService(db)
otpService := services.NewOTPService(db, cfg.OTPIssuer)

authHandler := handlers.NewAuthHandler(authService, auditService, otpService)
paymentHandler := handlers.NewPaymentHandler(paymentService, auditService)
auditHandler := handlers.NewAuditHandler(auditService)

webHandler := web.NewWebHandler(authService, paymentService, auditService, otpService, db, cfg)

gin.SetMode(gin.ReleaseMode)
r := gin.New()
r.Use(gin.Recovery())
r.Use(middleware.SecurityHeaders())
r.Use(middleware.MaxBodySizeMiddleware(1 << 20)) // 1 MB
r.Use(middleware.RateLimitMiddleware(cfg))

_ = r.SetTrustedProxies(nil)

webHandler.RegisterRoutes(r)

api := r.Group("/api/v1")
{
auth := api.Group("/auth")
{
auth.POST("/register", authHandler.Register)
auth.POST("/login", authHandler.Login)
auth.POST("/otp/verify", authHandler.OTPVerifyAPI)
}

protected := api.Group("")
protected.Use(middleware.AuthMiddleware(authService))
{
protected.GET("/me", authHandler.Me)
protected.POST("/profile/otp/setup", authHandler.OTPSetup)
protected.POST("/profile/otp/verify-setup", authHandler.OTPVerifySetup)
protected.DELETE("/profile/otp", authHandler.OTPDisableAPI)

payments := protected.Group("/payments")
{
payments.POST("", paymentHandler.CreatePayment)
payments.GET("", paymentHandler.GetMyPayments)
payments.GET("/:id", paymentHandler.GetPayment)
payments.POST("/:id/confirm", paymentHandler.ConfirmPayment)
}

analyst := protected.Group("/analyst")
analyst.Use(middleware.RoleMiddleware(models.RoleFraudAnalyst))
{
analyst.GET("/payments/flagged", paymentHandler.GetFlaggedPayments)
analyst.POST("/payments/:id/flag", paymentHandler.FlagPayment)
analyst.POST("/payments/:id/reject", paymentHandler.RejectPayment)
analyst.GET("/audit", auditHandler.GetAuditLogs)
}
}
}

r.GET("/health", func(c *gin.Context) {
c.JSON(200, gin.H{"status": "ok"})
})

log.Printf("Starting server on port %s", cfg.ServerPort)
log.Println("Web UI: http://localhost:" + cfg.ServerPort)
log.Println("API: http://localhost:" + cfg.ServerPort + "/api/v1")
if err := r.Run(":" + cfg.ServerPort); err != nil {
log.Fatalf("Server error: %v", err)
os.Exit(1)
}
}
