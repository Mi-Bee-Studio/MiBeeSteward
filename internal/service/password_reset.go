package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service/notification"
)

var (
	ErrResetTokenInvalid = errors.New("invalid or expired reset token")
	ErrResetTokenUsed    = errors.New("reset token has already been used")
	ErrResetTokenExpired = errors.New("reset token has expired")
)

// PasswordResetService handles password reset token generation, validation, and password updates.
type PasswordResetService struct {
	queries    *db.Queries
	dispatcher *notification.Dispatcher
	cfg        *config.SMTPConfig
	auditRepo  *repository.AuditRepository
	logger     *slog.Logger
}

// NewPasswordResetService creates a new PasswordResetService.
func NewPasswordResetService(queries *db.Queries, dispatcher *notification.Dispatcher, cfg *config.SMTPConfig, auditRepo *repository.AuditRepository) *PasswordResetService {
	return &PasswordResetService{
		queries:    queries,
		dispatcher: dispatcher,
		cfg:        cfg,
		auditRepo:  auditRepo,
		logger:     slog.Default(),
	}
}

// RequestReset generates a reset token and optionally sends an email.
// ALWAYS returns nil regardless of whether the email exists (prevents user enumeration).
func (s *PasswordResetService) RequestReset(ctx context.Context, email string) error {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Silently return — no user enumeration
			return nil
		}
		return fmt.Errorf("failed to look up user: %w", err)
	}

	// Generate 32-byte random hex token
	token, err := generateResetToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Create token record (expires in 1 hour)
	_, err = s.queries.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		return fmt.Errorf("failed to create reset token: %w", err)
	}

	// Send email if SMTP is configured and dispatcher is available
	if s.dispatcher != nil && s.cfg != nil && s.cfg.Host != "" {
		s.sendResetEmail(ctx, user.Email, token)
	}

	return nil
}

// ResetPassword validates a token and updates the user's password.
func (s *PasswordResetService) ResetPassword(ctx context.Context, token, newPassword string) error {
	resetToken, err := s.queries.GetPasswordResetByToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrResetTokenInvalid
		}
		return fmt.Errorf("failed to get reset token: %w", err)
	}

	// Check if already used
	if resetToken.UsedAt != nil {
		return ErrResetTokenUsed
	}

	// Check expiry
	if time.Now().After(resetToken.ExpiresAt) {
		return ErrResetTokenExpired
	}

	// Get user
	user, err := s.queries.GetUserByID(ctx, resetToken.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Validate new password
	if err := validatePassword(newPassword, user.Username); err != nil {
		return err
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	_, err = s.queries.UpdateUser(ctx, db.UpdateUserParams{
		Username:            user.Username,
		Email:               user.Email,
		PasswordHash:        string(hash),
		Role:                user.Role,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		MustChangePassword:  user.MustChangePassword,
		PasswordChangedAt:   user.PasswordChangedAt,
		ID:                  user.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	if err := s.queries.MarkPasswordResetUsed(ctx, token); err != nil {
		s.logger.Error("failed to mark reset token as used", "error", err)
	}

	// Audit log
	if s.auditRepo != nil {
		s.auditRepo.Log(ctx, repository.AuditLog{
			UserID:       &user.ID,
			Action:       "auth.password.reset",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", user.ID),
			Details:      "password reset via token",
		})
	}

	return nil
}

// ValidateToken checks if a token is valid (exists, not expired, not used).
func (s *PasswordResetService) ValidateToken(ctx context.Context, token string) error {
	resetToken, err := s.queries.GetPasswordResetByToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrResetTokenInvalid
		}
		return fmt.Errorf("failed to get reset token: %w", err)
	}

	if resetToken.UsedAt != nil {
		return ErrResetTokenUsed
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return ErrResetTokenExpired
	}

	return nil
}

// generateResetToken generates a 32-byte random hex token using crypto/rand.
func generateResetToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sendResetEmail sends a password reset email via the dispatcher.
func (s *PasswordResetService) sendResetEmail(ctx context.Context, email, token string) {
	smtpConfig := map[string]interface{}{
		"host":     s.cfg.Host,
		"port":     s.cfg.Port,
		"username": s.cfg.Username,
		"password": s.cfg.Password,
		"from":     s.cfg.FromAddress,
	}

	configJSON, err := json.Marshal(smtpConfig)
	if err != nil {
		s.logger.Error("failed to marshal SMTP config for reset email", "error", err)
		return
	}

	payload := notification.NotificationPayload{
		Subject:   "Password Reset Request",
		Body:      fmt.Sprintf("You requested a password reset. Use this token to reset your password: %s\n\nThis token expires in 1 hour.", token),
		Recipient: email,
	}

	s.dispatcher.Dispatch(ctx, domain.ChannelTypeEmail, configJSON, payload, nil, 0)
}
