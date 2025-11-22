package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// secureCookies is set in main() based on env COOKIE_SECURE=1
var secureCookies bool

// generateCSRFToken returns a random base64 token
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setCSRFCookie issues a SameSite cookie (Secure optional)
func setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: token, Path: "/", HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(2 * time.Hour)})
}

// refreshCSRFCookie extends expiration without changing the token
func refreshCSRFCookie(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("csrf")
	if err != nil || c == nil || c.Value == "" {
		return
	}
	// Only refresh if remaining lifetime < 30m
	if time.Until(c.Expires) < 30*time.Minute {
		setCSRFCookie(w, c.Value)
	}
}

// validateCSRF reads token from cookie & header
func validateCSRF(r *http.Request) bool {
	c, err := r.Cookie("csrf")
	if err != nil || c.Value == "" {
		return false
	}
	return r.Header.Get("X-CSRF-Token") == c.Value
}
