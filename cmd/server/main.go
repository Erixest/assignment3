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

	authHandler := handlers.NewAuthHandler(authService, auditService)
	paymentHandler := handlers.NewPaymentHandler(paymentService, auditService)
	auditHandler := handlers.NewAuditHandler(auditService)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.RateLimitMiddleware(cfg))

	r.SetTrustedProxies(nil)

	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
		}

		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(authService))
		{
			protected.GET("/me", authHandler.Me)

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
	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("Server error: %v", err)
		os.Exit(1)
	}
}
