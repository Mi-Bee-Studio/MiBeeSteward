// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/crypto"
	credresolver "mibee-steward/internal/service/scannerv2/credresolver"
)

// CredentialHandler handles HTTP requests for SNMP credential CRUD
// (POST/GET/PUT/DELETE /api/v1/snmp-credentials). It encrypts passphrases on
// write (via crypto.Cipher) and NEVER returns plaintext — list/get responses
// carry only protocol names + has_auth/has_priv booleans.
type CredentialHandler struct {
	db     *sql.DB
	cipher *crypto.Cipher
	// resolver is shared with the engine; the handler uses it only to invalidate
	// the credential cache after an update/delete so a subsequent scan sees the
	// new values immediately (not the 30s-stale decrypted copy).
	resolver *credresolver.Resolver
}

// NewCredentialHandler creates a handler. cipher/resolver may BOTH be nil when
// no master key is configured; in that state Create/Update return 503 (v3
// disabled) but List/Get/Delete still work (read-only over existing rows, if any).
func NewCredentialHandler(db *sql.DB, cipher *crypto.Cipher, resolver *credresolver.Resolver) *CredentialHandler {
	return &CredentialHandler{db: db, cipher: cipher, resolver: resolver}
}

// snmpCredentialRequest is the create/update body. AuthPassphrase /
// PrivPassphrase arrive as PLAINTEXT from the client (over TLS) and are
// encrypted by the handler BEFORE any DB write — the plaintext never reaches
// the DB layer or logs. On update, an empty passphrase field is treated as
// "leave unchanged" so an edit of e.g. just the name doesn't force the operator
// to retype the passphrase; see Update for the sentinel.
type snmpCredentialRequest struct {
	Name           string `json:"name"`
	SecurityLevel  string `json:"security_level"`
	Community      string `json:"community,omitempty"`
	Username       string `json:"username,omitempty"`
	AuthProtocol   string `json:"auth_protocol,omitempty"`
	AuthPassphrase string `json:"auth_passphrase,omitempty"`
	PrivProtocol   string `json:"priv_protocol,omitempty"`
	PrivPassphrase string `json:"priv_passphrase,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

// snmpCredentialResponse is the masked projection: NO passphrases (encrypted
// or plaintext). The frontend renders auth/priv as booleans derived from the
// protocol fields, so an admin can confirm "this is a SHA/AES authPriv cred"
// without ever seeing the secret.
type snmpCredentialResponse struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	SecurityLevel string `json:"security_level"`
	Community     string `json:"community,omitempty"`
	Username      string `json:"username,omitempty"`
	AuthProtocol  string `json:"auth_protocol,omitempty"`
	HasAuth       bool   `json:"has_auth"`
	PrivProtocol  string `json:"priv_protocol,omitempty"`
	HasPriv       bool   `json:"has_priv"`
	Notes         string `json:"notes,omitempty"`
}

// Create handles POST /api/v1/snmp-credentials
func (h *CredentialHandler) Create(w http.ResponseWriter, r *http.Request) {
	if h.cipher == nil {
		Error(w, http.StatusServiceUnavailable, "SNMPv3 credential storage disabled (security.master_key not configured)")
		return
	}
	var req snmpCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateCredentialRequest(&req); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	authEnc, privEnc, err := h.encryptPassphrases(&req, "", "")
	if err != nil {
		slog.Error("encrypt passphrases", "error", err)
		Error(w, http.StatusInternalServerError, "failed to encrypt passphrases")
		return
	}

	id, err := credresolver.CreateSNMPCredential(r.Context(), h.db, credresolver.SNMPCredentialWriteParams{
		Name:              req.Name,
		SecurityLevel:     req.SecurityLevel,
		Community:         req.Community,
		Username:          req.Username,
		AuthProtocol:      req.AuthProtocol,
		AuthPassphraseEnc: authEnc,
		PrivProtocol:      req.PrivProtocol,
		PrivPassphraseEnc: privEnc,
		Notes:             req.Notes,
	})
	if err != nil {
		// SQLite UNIQUE constraint on name → a clearer 409 than the raw driver text.
		if isUniqueViolation(err) {
			Error(w, http.StatusConflict, "a credential with this name already exists")
			return
		}
		slog.Error("create credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to create credential")
		return
	}
	// Re-fetch to populate timestamps for the response.
	row, err := credresolver.GetSNMPCredential(r.Context(), h.db, id)
	if err != nil {
		slog.Error("fetch created credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to fetch created credential")
		return
	}
	Created(w, toCredentialResponse(row))
}

// List handles GET /api/v1/snmp-credentials
func (h *CredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset := parseListPaging(r)
	rows, err := credresolver.ListSNMPCredentials(r.Context(), h.db, limit, offset)
	if err != nil {
		slog.Error("list credentials", "error", err)
		Error(w, http.StatusInternalServerError, "failed to list credentials")
		return
	}
	out := make([]snmpCredentialResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, maskedRowToResponse(row))
	}
	total, _ := credresolver.CountSNMPCredentials(r.Context(), h.db)
	Success(w, map[string]any{"credentials": out, "total": total})
}

// Get handles GET /api/v1/snmp-credentials/{id}
func (h *CredentialHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseCredentialID(w, r)
	if !ok {
		return
	}
	row, err := credresolver.GetSNMPCredential(r.Context(), h.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		Error(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		slog.Error("fetch credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to fetch credential")
		return
	}
	Success(w, toCredentialResponse(row))
}

// Update handles PUT /api/v1/snmp-credentials/{id}
func (h *CredentialHandler) Update(w http.ResponseWriter, r *http.Request) {
	if h.cipher == nil {
		Error(w, http.StatusServiceUnavailable, "SNMPv3 credential storage disabled (security.master_key not configured)")
		return
	}
	id, ok := parseCredentialID(w, r)
	if !ok {
		return
	}
	var req snmpCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateCredentialRequest(&req); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	// Fetch the existing row so an empty passphrase field means "leave
	// unchanged" — an operator editing only the name shouldn't have to retype
	// (or even know) the passphrase. We re-encrypt the existing ciphertext's
	// decrypted plaintext under the same key (idempotent) when the field is
	// blank in the request.
	existing, err := credresolver.GetSNMPCredential(r.Context(), h.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		Error(w, http.StatusNotFound, "credential not found")
		return
	}
	if err != nil {
		slog.Error("fetch credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to fetch credential")
		return
	}
	authEnc, privEnc, err := h.encryptPassphrases(&req, existing.AuthPassphraseEnc, existing.PrivPassphraseEnc)
	if err != nil {
		slog.Error("encrypt passphrases", "error", err)
		Error(w, http.StatusInternalServerError, "failed to encrypt passphrases")
		return
	}

	if err := credresolver.UpdateSNMPCredential(r.Context(), h.db, id, credresolver.SNMPCredentialWriteParams{
		Name:              req.Name,
		SecurityLevel:     req.SecurityLevel,
		Community:         req.Community,
		Username:          req.Username,
		AuthProtocol:      req.AuthProtocol,
		AuthPassphraseEnc: authEnc,
		PrivProtocol:      req.PrivProtocol,
		PrivPassphraseEnc: privEnc,
		Notes:             req.Notes,
	}); err != nil {
		if isUniqueViolation(err) {
			Error(w, http.StatusConflict, "a credential with this name already exists")
			return
		}
		slog.Error("update credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to update credential")
		return
	}
	// Invalidate the resolver cache so the next scan sees the new values
	// immediately rather than up to 30s later.
	if h.resolver != nil {
		h.resolver.Invalidate(id)
	}
	// Re-fetch for the response.
	row, err := credresolver.GetSNMPCredential(r.Context(), h.db, id)
	if err != nil {
		slog.Error("fetch updated credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to fetch updated credential")
		return
	}
	Success(w, toCredentialResponse(row))
}

// Delete handles DELETE /api/v1/snmp-credentials/{id}
func (h *CredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseCredentialID(w, r)
	if !ok {
		return
	}
	affected, err := credresolver.DeleteSNMPCredential(r.Context(), h.db, id)
	if err != nil {
		slog.Error("delete credential", "error", err)
		Error(w, http.StatusInternalServerError, "failed to delete credential")
		return
	}
	if affected == 0 {
		Error(w, http.StatusNotFound, "credential not found")
		return
	}
	if h.resolver != nil {
		h.resolver.Invalidate(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// encryptPassphrases encrypts the request's plaintext auth/priv passphrases.
// When a request passphrase field is empty, the corresponding existingEnc value
// is preserved (re-encrypted from its decrypted form, or passed through if
// already a valid blob). This implements the "leave unchanged on update"
// behavior for credential edits.
//
// The security-level / protocol validation (authPriv requires both protocols,
// etc.) is done up-front by validateCredentialRequest; this function only
// handles the encrypt-or-preserve decision per field.
func (h *CredentialHandler) encryptPassphrases(req *snmpCredentialRequest, existingAuthEnc, existingPrivEnc string) (string, string, error) {
	authEnc, err := h.encryptOne(req.AuthPassphrase, existingAuthEnc)
	if err != nil {
		return "", "", err
	}
	privEnc, err := h.encryptOne(req.PrivPassphrase, existingPrivEnc)
	if err != nil {
		return "", "", err
	}
	return authEnc, privEnc, nil
}

// encryptOne handles one passphrase field. Non-empty plaintext → encrypt it.
// Empty plaintext + existing ciphertext → preserve (leave-unchanged on update).
// Empty plaintext + no existing value → store empty (the noAuth/noPriv
// convention; validateCredentialRequest has already enforced that the security
// level permits an empty field here).
func (h *CredentialHandler) encryptOne(plaintext, existingEnc string) (string, error) {
	if plaintext != "" {
		return h.cipher.Encrypt(plaintext)
	}
	if existingEnc != "" {
		return existingEnc, nil
	}
	return "", nil
}

// validateCredentialRequest enforces the security-level / field-presence rules
// (mirrors the credresolver rules but at the API boundary for clear errors).
func validateCredentialRequest(req *snmpCredentialRequest) error {
	if req.Name == "" {
		return errors.New("name is required")
	}
	switch req.SecurityLevel {
	case "v1v2c":
		if req.Community == "" {
			return errors.New("community is required for security_level v1v2c")
		}
	case "noAuthNoPriv":
		// No auth/priv required; username recommended but not enforced.
	case "authNoPriv":
		if req.Username == "" {
			return errors.New("username is required for v3 security levels")
		}
		if req.AuthProtocol == "" {
			return errors.New("auth_protocol is required for authNoPriv")
		}
		// AuthPassphrase is validated in save(): required on CREATE, optional on
		// UPDATE (empty = leave-unchanged, resolved after fetching the existing row).
	case "authPriv":
		if req.Username == "" {
			return errors.New("username is required for v3 security levels")
		}
		if req.AuthProtocol == "" {
			return errors.New("auth_protocol is required for authPriv")
		}
		if req.PrivProtocol == "" {
			return errors.New("priv_protocol is required for authPriv")
		}
	default:
		return errors.New("security_level must be one of: v1v2c, noAuthNoPriv, authNoPriv, authPriv")
	}
	return nil
}

// toCredentialResponse builds a masked response from a full row (used by
// Create/Get/Update, which fetch the full row including ciphertext but only
// project the safe fields into the response).
func toCredentialResponse(row credresolver.SNMPCredentialRow) snmpCredentialResponse {
	return snmpCredentialResponse{
		ID:            row.ID,
		Name:          row.Name,
		SecurityLevel: row.SecurityLevel,
		Community:     row.Community,
		Username:      row.Username,
		AuthProtocol:  row.AuthProtocol,
		HasAuth:       row.AuthProtocol != "",
		PrivProtocol:  row.PrivProtocol,
		HasPriv:       row.PrivProtocol != "",
		Notes:         row.Notes,
	}
}

// maskedRowToResponse builds a response from a masked row (the ListSNMPCredentials
// projection, which already omits the *_enc columns).
func maskedRowToResponse(row credresolver.MaskedCredentialRow) snmpCredentialResponse {
	return snmpCredentialResponse{
		ID:            row.ID,
		Name:          row.Name,
		SecurityLevel: row.SecurityLevel,
		Community:     row.Community,
		Username:      row.Username,
		AuthProtocol:  row.AuthProtocol,
		HasAuth:       row.AuthProtocol != "",
		PrivProtocol:  row.PrivProtocol,
		HasPriv:       row.PrivProtocol != "",
		Notes:         row.Notes,
	}
}

func parseCredentialID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid credential id")
		return 0, false
	}
	return id, true
}

func parseListPaging(r *http.Request) (int64, int64) {
	limit := int64(100)
	offset := int64(0)
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// isUniqueViolation reports whether err is SQLite's UNIQUE constraint failure.
// modernc/sqlite surfaces it with this substring; matching on the string keeps
// the handler free of a driver-specific error-type import.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed: UNIQUE")
}
