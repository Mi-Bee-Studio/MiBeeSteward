// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package domain

import (
	"encoding/json"
	"time"
)

// Request types

type TOTPSetupRequest struct {
	UserID int64 `json:"user_id"`
}

type TOTPVerifyRequest struct {
	UserID int64  `json:"user_id"`
	Code   string `json:"code"`
}

type TOTPEnableRequest struct {
	UserID int64  `json:"user_id"`
	Code   string `json:"code"`
}

type TOTPDisableRequest struct {
	UserID   int64  `json:"user_id"`
	Password string `json:"password"`
}

// Response types

type TOTPSetupResponse struct {
	Secret      string          `json:"secret"`
	BackupCodes json.RawMessage `json:"backup_codes"`
	QRCodeURL   string          `json:"qr_code_url"`
}

type TOTPStatusResponse struct {
	Enabled   bool      `json:"enabled"`
	Verified  bool      `json:"verified"`
	CreateAt  time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TOTPLoginChallengeResponse is returned when 2FA is required after login.
// It does NOT contain the JWT token.
type TOTPLoginChallengeResponse struct {
	Require2FA bool         `json:"require_2fa"`
	User       UserResponse `json:"user"`
}
