package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
)

// TOTPIssuer is the issuer name used in TOTP URIs.
const TOTPIssuer = "MiBee Steward"

var (
	ErrTOTPNotFound        = errors.New("TOTP not configured for user")
	ErrTOTPAlreadyEnabled  = errors.New("TOTP is already enabled")
	ErrTOTPNotEnabled      = errors.New("TOTP is not enabled")
	ErrInvalidTOTPCode     = errors.New("invalid TOTP code")
	ErrInvalidBackupCode   = errors.New("invalid backup code")
	ErrTOTPInvalidPassword = errors.New("invalid password")
)

// TOTPService handles TOTP enrollment, verification, and management.
type TOTPService struct {
	queries   *db.Queries
	userDB    db.DBTX
	auditRepo *repository.AuditRepository
}

// NewTOTPService creates a new TOTPService.
func NewTOTPService(dbConn db.DBTX, auditRepo *repository.AuditRepository) *TOTPService {
	return &TOTPService{
		queries:   db.New(dbConn),
		userDB:    dbConn,
		auditRepo: auditRepo,
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
		s.auditRepo.Log(ctx, repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.user.2fa.enable",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", userID),
			Details:      "2FA enabled via TOTP",
		})
	}

	return nil
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
	_ = user.ID // assigned by Scan
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return ErrTOTPInvalidPassword
	}

	if err := s.queries.DeleteTOTP(ctx, userID); err != nil {
		slog.Error("failed to delete TOTP", "user_id", userID, "error", err)
		return fmt.Errorf("failed to disable TOTP")
	}

	// Audit log
	if s.auditRepo != nil {
		s.auditRepo.Log(ctx, repository.AuditLog{
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
// This is a read-only check — does NOT consume the code.
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
