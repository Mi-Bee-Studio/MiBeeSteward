// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

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
	"mibee-steward/internal/service/scannerv2/sshcred"
)

// SSHCredentialHandler serves the SSH credential registry for the device config-
// backup probe (#137). It mirrors the SNMP credential handler: plaintext is
// encrypted at WRITE time via the shared crypto.Cipher and the response ALWAYS
// redacts the ciphertext (only a has_secret boolean surfaces). A nil cipher (no
// master_key) disables the mutating endpoints with 503, exactly as SNMP creds.
type SSHCredentialHandler struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

// NewSSHCredentialHandler constructs the handler. cipher may be nil (mutating
// endpoints then return 503); reads still work (the ciphertext is never decrypted here).
func NewSSHCredentialHandler(db *sql.DB, cipher *crypto.Cipher) *SSHCredentialHandler {
	return &SSHCredentialHandler{db: db, cipher: cipher}
}

// sshCredentialRequest is the body for POST/PUT /api/v1/ssh-credentials. Secret
// is the PLAINTEXT password or PEM private key (encrypted by the handler before
// it reaches the store); Passphrase is the plaintext passphrase for an encrypted
// key (optional). Neither is ever returned by the API.
type sshCredentialRequest struct {
	Name       string `json:"name"`        // required, unique
	AuthMethod string `json:"auth_method"` // "password" | "key", required
	Username   string `json:"username"`
	Secret     string `json:"secret"`     // plaintext password | PEM key (write-only)
	Passphrase string `json:"passphrase"` // plaintext key passphrase (write-only, optional)
	HostKeyFP  string `json:"host_key_fp"`
	Enabled    *bool  `json:"enabled"` // nil = default true (a new cred is usable)
	Notes      string `json:"notes"`
}

// sshCredentialResponse redacts the secret entirely: it surfaces metadata +
// whether a secret is set (has_secret), never the ciphertext or plaintext.
type sshCredentialResponse struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	AuthMethod    string `json:"auth_method"`
	Username      string `json:"username,omitempty"`
	HostKeyFP     string `json:"host_key_fp,omitempty"`
	HasSecret     bool   `json:"has_secret"`
	HasPassphrase bool   `json:"has_passphrase"`
	Enabled       bool   `json:"enabled"`
	Notes         string `json:"notes,omitempty"`
}

func toSSHCredentialResponse(r sshcred.Row) sshCredentialResponse {
	return sshCredentialResponse{
		ID: r.ID, Name: r.Name, AuthMethod: r.AuthMethod, Username: r.Username,
		HostKeyFP:     r.HostKeyFP,
		HasSecret:     r.SecretEnc != "",
		HasPassphrase: r.PassphraseEnc != "",
		Enabled:       r.Enabled,
		Notes:         r.Notes,
	}
}

func toSSHListResponse(r sshcred.ListRow) sshCredentialResponse {
	return sshCredentialResponse{
		ID: r.ID, Name: r.Name, AuthMethod: r.AuthMethod, Username: r.Username,
		HostKeyFP: r.HostKeyFP,
		HasSecret: true, // a stored credential always has a secret; the list omits the blob
		Enabled:   r.Enabled,
		Notes:     r.Notes,
	}
}

// Create handles POST /api/v1/ssh-credentials.
func (h *SSHCredentialHandler) Create(w http.ResponseWriter, r *http.Request) {
	if h.cipher == nil {
		Error(w, http.StatusServiceUnavailable, "SSH credential storage disabled (security.master_key not configured)")
		return
	}
	var req sshCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateSSHCredentialRequest(&req); err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	secretEnc, err := h.cipher.Encrypt(strings.TrimSpace(req.Secret))
	if err != nil {
		slog.Error("ssh credential: encrypt secret", "error", err)
		Error(w, http.StatusInternalServerError, "failed to encrypt secret")
		return
	}
	passphraseEnc := ""
	if pp := strings.TrimSpace(req.Passphrase); pp != "" {
		passphraseEnc, err = h.cipher.Encrypt(pp)
		if err != nil {
			slog.Error("ssh credential: encrypt passphrase", "error", err)
			Error(w, http.StatusInternalServerError, "failed to encrypt passphrase")
			return
		}
	}
	id, err := sshcred.Create(r.Context(), h.db, sshcred.WriteParams{
		Name: strings.TrimSpace(req.Name), AuthMethod: req.AuthMethod, Username: req.Username,
		SecretEnc: secretEnc, PassphraseEnc: passphraseEnc, HostKeyFP: strings.TrimSpace(req.HostKeyFP),
		Enabled: req.Enabled == nil || *req.Enabled,
		Notes:   req.Notes,
	})
	if err != nil {
		if isUniqueConstraintErr(err) {
			Error(w, http.StatusConflict, "an SSH credential with this name already exists")
			return
		}
		slog.Error("ssh credential: create", "error", err)
		Error(w, http.StatusInternalServerError, "failed to create SSH credential")
		return
	}
	row, err := sshcred.Get(r.Context(), h.db, id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to fetch created SSH credential")
		return
	}
	Created(w, toSSHCredentialResponse(row))
}

// List handles GET /api/v1/ssh-credentials — metadata only (ciphertext omitted).
func (h *SSHCredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset := parseListPaging(r)
	rows, err := sshcred.List(r.Context(), h.db, limit, offset)
	if err != nil {
		slog.Error("ssh credential: list", "error", err)
		Error(w, http.StatusInternalServerError, "failed to list SSH credentials")
		return
	}
	out := make([]sshCredentialResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSSHListResponse(row))
	}
	Success(w, out)
}

// Get handles GET /api/v1/ssh-credentials/{id} — redacted (no ciphertext).
func (h *SSHCredentialHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSSHCredID(w, r)
	if !ok {
		return
	}
	row, err := sshcred.Get(r.Context(), h.db, id)
	if errors.Is(err, sshcred.ErrNotFound) {
		Error(w, http.StatusNotFound, "SSH credential not found")
		return
	}
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to fetch SSH credential")
		return
	}
	Success(w, toSSHCredentialResponse(row))
}

// Update handles PUT /api/v1/ssh-credentials/{id}. A blank Secret means "keep
// the existing ciphertext" (so an admin can rename/toggle without re-entering);
// a non-blank Secret re-encrypts.
func (h *SSHCredentialHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSSHCredID(w, r)
	if !ok {
		return
	}
	if h.cipher == nil {
		Error(w, http.StatusServiceUnavailable, "SSH credential storage disabled (security.master_key not configured)")
		return
	}
	var req sshCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Update validates name + auth_method but allows a BLANK secret (meaning
	// "keep the existing ciphertext" — so an admin can rename/toggle without
	// re-entering the secret). Create uses validateSSHCredentialRequest which
	// additionally requires a non-empty secret.
	if strings.TrimSpace(req.Name) == "" {
		Error(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.AuthMethod != "password" && req.AuthMethod != "key" {
		Error(w, http.StatusBadRequest, "auth_method must be 'password' or 'key'")
		return
	}
	existing, err := sshcred.Get(r.Context(), h.db, id)
	if errors.Is(err, sshcred.ErrNotFound) {
		Error(w, http.StatusNotFound, "SSH credential not found")
		return
	}
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to fetch SSH credential")
		return
	}
	secretEnc := existing.SecretEnc // keep existing when Secret blank
	if strings.TrimSpace(req.Secret) != "" {
		secretEnc, err = h.cipher.Encrypt(strings.TrimSpace(req.Secret))
		if err != nil {
			Error(w, http.StatusInternalServerError, "failed to encrypt secret")
			return
		}
	}
	passphraseEnc := existing.PassphraseEnc
	if pp := strings.TrimSpace(req.Passphrase); pp != "" {
		passphraseEnc, err = h.cipher.Encrypt(pp)
		if err != nil {
			Error(w, http.StatusInternalServerError, "failed to encrypt passphrase")
			return
		}
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if err := sshcred.Update(r.Context(), h.db, id, sshcred.WriteParams{
		Name: strings.TrimSpace(req.Name), AuthMethod: req.AuthMethod, Username: req.Username,
		SecretEnc: secretEnc, PassphraseEnc: passphraseEnc, HostKeyFP: strings.TrimSpace(req.HostKeyFP),
		Enabled: enabled, Notes: req.Notes,
	}); err != nil {
		if errors.Is(err, sshcred.ErrNotFound) {
			Error(w, http.StatusNotFound, "SSH credential not found")
			return
		}
		if isUniqueConstraintErr(err) {
			Error(w, http.StatusConflict, "an SSH credential with this name already exists")
			return
		}
		slog.Error("ssh credential: update", "error", err)
		Error(w, http.StatusInternalServerError, "failed to update SSH credential")
		return
	}
	row, _ := sshcred.Get(r.Context(), h.db, id)
	Success(w, toSSHCredentialResponse(row))
}

// Delete handles DELETE /api/v1/ssh-credentials/{id}.
func (h *SSHCredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSSHCredID(w, r)
	if !ok {
		return
	}
	n, err := sshcred.Delete(r.Context(), h.db, id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete SSH credential")
		return
	}
	if n == 0 {
		Error(w, http.StatusNotFound, "SSH credential not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateSSHCredentialRequest checks the required fields + auth_method domain.
func validateSSHCredentialRequest(req *sshCredentialRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name is required")
	}
	if req.AuthMethod != "password" && req.AuthMethod != "key" {
		return errors.New("auth_method must be 'password' or 'key'")
	}
	if strings.TrimSpace(req.Secret) == "" {
		return errors.New("secret is required")
	}
	return nil
}

// parseSSHCredID extracts the {id} URL param. Mirrors parseCredentialID.
func parseSSHCredID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}
