package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

// MaxBodySizeMiddleware limits the size of incoming request bodies to maxBytes
// to prevent DoS via memory exhaustion (CWE-400).
// If the body exceeds the limit, the request is rejected with 413.
func MaxBodySizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
