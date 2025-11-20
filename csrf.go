package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// generateCSRFToken returns a random base64 token
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setCSRFCookie issues a SameSite cookie
func setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: token, Path: "/", HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(2 * time.Hour)})
}

// validateCSRF reads token from cookie & header
func validateCSRF(r *http.Request) bool {
	c, err := r.Cookie("csrf")
	if err != nil || c.Value == "" {
		return false
	}
	return r.Header.Get("X-CSRF-Token") == c.Value
}
