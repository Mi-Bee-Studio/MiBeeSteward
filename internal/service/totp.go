// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// TOTPIssuer is the issuer name used in TOTP URIs.
const TOTPIssuer = "MiBee Steward"

var (
	ErrTOTPNotFound         = errors.New("TOTP not configured for user")
	ErrTOTPAlreadyEnabled   = errors.New("TOTP is already enabled")
	ErrTOTPNotEnabled       = errors.New("TOTP is not enabled")
	ErrInvalidTOTPCode      = errors.New("invalid TOTP code")
	ErrInvalidBackupCode    = errors.New("invalid backup code")
	ErrTOTPInvalidPassword  = errors.New("invalid password")
	ErrTOTPChallengeInvalid = errors.New("invalid or expired 2FA challenge")
)

// TOTPService handles TOTP enrollment, verification, and management.
type TOTPService struct {
	queries   *db.Queries
	userDB    db.DBTX
	auditRepo *AuditRepository

	challengeMu sync.Mutex
	challenges  map[string]totpChallenge
}

const (
	totpChallengeTTL         = 5 * time.Minute
	totpChallengeMaxAttempts = 5
)

type totpChallenge struct {
	userID    int64
	expiresAt time.Time
	attempts  int
}

// NewTOTPService creates a new TOTPService.
func NewTOTPService(dbConn db.DBTX, auditRepo *AuditRepository) *TOTPService {
	return &TOTPService{
		queries:    db.New(dbConn),
		userDB:     dbConn,
		auditRepo:  auditRepo,
		challenges: make(map[string]totpChallenge),
	}
}

// Setup generates a new TOTP secret and backup codes for the user.
// It upserts the TOTP record (resets verified/enabled if re-setup).
func (s *TOTPService) Setup(ctx context.Context, userID int64, username string) (*domain.TOTPSetupResponse, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: username,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		slog.Error("failed to generate TOTP key", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to generate TOTP key")
	}

	backupCodes := generateBackupCodes(10)
	backupJSON, err := json.Marshal(backupCodes)
	if err != nil {
		slog.Error("failed to marshal backup codes", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to generate backup codes")
	}

	_, err = s.queries.SetTOTPSecret(ctx, db.SetTOTPSecretParams{
		UserID:      userID,
		Secret:      key.Secret(),
		BackupCodes: string(backupJSON),
	})
	if err != nil {
		slog.Error("failed to store TOTP secret", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to store TOTP secret")
	}

	return &domain.TOTPSetupResponse{
		Secret:      key.Secret(),
		BackupCodes: backupJSON,
		QRCodeURL:   key.URL(),
	}, nil
}

// Enable validates the TOTP code, marks the record as verified and enabled.
func (s *TOTPService) Enable(ctx context.Context, userID int64, code string) error {
	totpRecord, err := s.queries.GetTOTPByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTOTPNotFound
		}
		slog.Error("failed to get TOTP record", "user_id", userID, "error", err)
		return fmt.Errorf("failed to get TOTP record")
	}

	valid := totp.Validate(code, totpRecord.Secret)
	if !valid {
		return ErrInvalidTOTPCode
	}

	_, err = s.queries.UpdateTOTPVerified(ctx, db.UpdateTOTPVerifiedParams{
		Verified: 1,
		UserID:   userID,
	})
	if err != nil {
		slog.Error("failed to update TOTP verified", "user_id", userID, "error", err)
		return fmt.Errorf("failed to update TOTP verified")
	}

	_, err = s.queries.UpdateTOTPEnabled(ctx, db.UpdateTOTPEnabledParams{
		Enabled: 1,
		UserID:  userID,
	})
	if err != nil {
		slog.Error("failed to update TOTP enabled", "user_id", userID, "error", err)
		return fmt.Errorf("failed to update TOTP enabled")
	}

	// Audit log
	if s.auditRepo != nil {
		s.auditRepo.Log(ctx, AuditLog{
			UserID:       &userID,
			Action:       "admin.user.2fa.enable",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", userID),
			Details:      "2FA enabled via TOTP",
		})
	}

	return nil
}

// IssueChallenge creates a short-lived, single-factor-completed login challenge.
// The raw token is returned once; only its SHA-256 hash is kept in memory. The
// challenge is bound to the user that passed password authentication and can be
// used for at most totpChallengeMaxAttempts code checks.
func (s *TOTPService) IssueChallenge(userID int64) (string, time.Duration, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, fmt.Errorf("generate 2FA challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	key := challengeKey(token)

	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	now := time.Now()
	for k, c := range s.challenges {
		if !now.Before(c.expiresAt) {
			delete(s.challenges, k)
		}
	}
	s.challenges[key] = totpChallenge{userID: userID, expiresAt: now.Add(totpChallengeTTL)}
	return token, totpChallengeTTL, nil
}

// VerifyChallenge validates the one-time login challenge and its TOTP/backup
// code. The challenge lock serializes verification so concurrent requests cannot
// consume the same challenge twice. A successful verification removes it; a
// failed code consumes one of the bounded attempts.
func (s *TOTPService) VerifyChallenge(ctx context.Context, challenge, code string) (int64, error) {
	if challenge == "" || code == "" {
		return 0, ErrTOTPChallengeInvalid
	}
	key := challengeKey(challenge)

	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	c, ok := s.challenges[key]
	if !ok {
		return 0, ErrTOTPChallengeInvalid
	}
	if !time.Now().Before(c.expiresAt) {
		delete(s.challenges, key)
		return 0, ErrTOTPChallengeInvalid
	}

	user, err := s.queries.GetUserByID(ctx, c.userID)
	if err != nil {
		delete(s.challenges, key)
		return 0, ErrTOTPChallengeInvalid
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		delete(s.challenges, key)
		return 0, ErrAccountLocked
	}

	if err := s.Verify(ctx, c.userID, code); err != nil {
		c.attempts++
		if c.attempts >= totpChallengeMaxAttempts {
			delete(s.challenges, key)
		} else {
			s.challenges[key] = c
		}
		return 0, err
	}
	delete(s.challenges, key)
	return c.userID, nil
}

func challengeKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Verify checks a TOTP code or backup code during login.
// If a backup code is used, it is consumed (removed).
func (s *TOTPService) Verify(ctx context.Context, userID int64, code string) error {
	totpRecord, err := s.queries.GetTOTPByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTOTPNotFound
		}
		slog.Error("failed to get TOTP record", "user_id", userID, "error", err)
		return fmt.Errorf("failed to get TOTP record")
	}

	if totpRecord.Enabled != 1 {
		return ErrTOTPNotEnabled
	}

	// Try TOTP code first
	if totp.Validate(code, totpRecord.Secret) {
		return nil
	}

	// Try backup code
	code = strings.TrimSpace(code)
	var backupCodes []string
	if err := json.Unmarshal([]byte(totpRecord.BackupCodes), &backupCodes); err != nil {
		slog.Error("failed to parse backup codes", "user_id", userID, "error", err)
		return fmt.Errorf("failed to verify code")
	}

	for i, bc := range backupCodes {
		if strings.TrimSpace(bc) == code {
			// Consume: remove this code from the array
			backupCodes = append(backupCodes[:i], backupCodes[i+1:]...)
			updatedJSON, err := json.Marshal(backupCodes)
			if err != nil {
				slog.Error("failed to marshal backup codes after consume", "user_id", userID, "error", err)
				return fmt.Errorf("failed to consume backup code")
			}
			_, err = s.queries.ConsumeBackupCode(ctx, db.ConsumeBackupCodeParams{
				BackupCodes: string(updatedJSON),
				UserID:      userID,
			})
			if err != nil {
				slog.Error("failed to consume backup code", "user_id", userID, "error", err)
				return fmt.Errorf("failed to consume backup code")
			}
			return nil
		}
	}

	return ErrInvalidTOTPCode
}

// Disable removes TOTP for the user after verifying the password.
func (s *TOTPService) Disable(ctx context.Context, userID int64, password string) error {
	// Verify password
	var user db.User
	row := s.userDB.QueryRowContext(ctx, `SELECT id, password_hash FROM users WHERE id = ?`, userID)
	if err := row.Scan(&user.ID, &user.PasswordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		slog.Error("failed to get user for 2FA disable", "user_id", userID, "error", err)
		return fmt.Errorf("failed to verify password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return ErrTOTPInvalidPassword
	}

	if err := s.queries.DeleteTOTP(ctx, userID); err != nil {
		slog.Error("failed to delete TOTP", "user_id", userID, "error", err)
		return fmt.Errorf("failed to disable TOTP")
	}

	// Audit log
	if s.auditRepo != nil {
		s.auditRepo.Log(ctx, AuditLog{
			UserID:       &userID,
			Action:       "admin.user.2fa.disable",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", userID),
			Details:      "2FA disabled",
		})
	}

	return nil
}

// IsEnabled checks whether a user has TOTP enabled.
func (s *TOTPService) IsEnabled(ctx context.Context, userID int64) (bool, error) {
	totpRecord, err := s.queries.GetTOTPByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check TOTP status")
	}
	return totpRecord.Enabled == 1, nil
}

// GetStatus returns the TOTP status for a user.
func (s *TOTPService) GetStatus(ctx context.Context, userID int64) (*domain.TOTPStatusResponse, error) {
	totpRecord, err := s.queries.GetTOTPByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &domain.TOTPStatusResponse{
				Enabled:  false,
				Verified: false,
			}, nil
		}
		return nil, fmt.Errorf("failed to get TOTP status")
	}
	return &domain.TOTPStatusResponse{
		Enabled:   totpRecord.Enabled == 1,
		Verified:  totpRecord.Verified == 1,
		CreateAt:  totpRecord.CreatedAt,
		UpdatedAt: totpRecord.UpdatedAt,
	}, nil
}

// ValidateBackupCode checks if a code matches any unconsumed backup code.
// This is a read-only check, does NOT consume the code.
func (s *TOTPService) ValidateBackupCode(ctx context.Context, userID int64, code string) (bool, error) {
	totpRecord, err := s.queries.GetTOTPByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrTOTPNotFound
		}
		return false, fmt.Errorf("failed to get TOTP record")
	}

	var backupCodes []string
	if err := json.Unmarshal([]byte(totpRecord.BackupCodes), &backupCodes); err != nil {
		return false, fmt.Errorf("failed to parse backup codes")
	}

	code = strings.TrimSpace(code)
	for _, bc := range backupCodes {
		if strings.TrimSpace(bc) == code {
			return true, nil
		}
	}
	return false, nil
}

// generateBackupCodes generates n random alphanumeric codes of 8 characters each.
func generateBackupCodes(n int) []string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		code := make([]byte, 8)
		for j := range code {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				// Fallback should never happen with crypto/rand
				continue
			}
			code[j] = charset[num.Int64()]
		}
		codes = append(codes, string(code))
	}
	return codes
}
