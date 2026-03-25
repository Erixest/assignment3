package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	JWTSecret          string
	DatabasePath       string
	ServerPort         string
	JWTExpiry          time.Duration
	RateLimitRequests  int
	RateLimitWindow    time.Duration
}

func Load() *Config {
	jwtExpiry, _ := strconv.Atoi(getEnv("JWT_EXPIRY_MINUTES", "15"))
	rateLimitReqs, _ := strconv.Atoi(getEnv("RATE_LIMIT_REQUESTS", "100"))
	rateLimitWindow, _ := strconv.Atoi(getEnv("RATE_LIMIT_WINDOW_SECONDS", "60"))

	return &Config{
		JWTSecret:          getEnv("JWT_SECRET", ""),
		DatabasePath:       getEnv("DATABASE_PATH", "./payments.db"),
		ServerPort:         getEnv("SERVER_PORT", "8080"),
		JWTExpiry:          time.Duration(jwtExpiry) * time.Minute,
		RateLimitRequests:  rateLimitReqs,
		RateLimitWindow:    time.Duration(rateLimitWindow) * time.Second,
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func (c *Config) Validate() error {
	if c.JWTSecret == "" || len(c.JWTSecret) < 32 {
		return &ConfigError{Field: "JWT_SECRET", Message: "must be at least 32 characters"}
	}
	return nil
}

type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Message
}
