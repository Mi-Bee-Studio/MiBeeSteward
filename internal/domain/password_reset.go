package domain

import "time"

// Request types

type ResetTokenRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// Response types

type ResetTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
}
