// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"mibee-steward/internal/config"
	"mibee-steward/internal/crypto"
	"mibee-steward/internal/service/scannerv2/credresolver"
	"mibee-steward/internal/version"
)

// buildAgentCredentialResolver assembles the agent-local SNMP credential
// resolver (#241). The vault is optional: no security.master_key (or a
// wrong-length one) returns nil and scans keep using the global v1/v2c
// community, the same degrade semantics as the center's buildCredentialCipher.
// The key protects ONLY this agent's own snmp_credentials rows; it is
// independent of the center's master key so the two trust domains
// never share key material.
func buildAgentCredentialResolver(dbConn *sql.DB, cfg *config.Config) *credresolver.Resolver {
	if cfg.Security.MasterKey == "" {
		slog.Info("agent snmp credential vault disabled (security.master_key not set; scans use scanner.snmp_community)")
		return nil
	}
	if len(cfg.Security.MasterKey) != crypto.MasterKeyLen {
		slog.Error("agent snmp credential vault disabled: security.master_key must be exactly 32 bytes",
			"len", len(cfg.Security.MasterKey))
		return nil
	}
	c, err := crypto.NewCipher([]byte(cfg.Security.MasterKey))
	if err != nil {
		slog.Error("agent snmp credential vault disabled: bad master key", "error", err)
		return nil
	}
	return credresolver.New(dbConn, c)
}

// resolveAgentCredentialID degrades a stale local credential reference to a
// community scan (0) instead of letting the engine abort the run: the engine
// treats a resolver error as fatal, which is right on the center (where FKs
// keep references valid) but too strict for an operator-maintained agent
// mini-DB whose rows can vanish between task creation and execution.
func resolveAgentCredentialID(ctx context.Context, r *credresolver.Resolver, id int64) int64 {
	if id == 0 || r == nil {
		return 0
	}
	if cred, err := r.ResolveByID(ctx, id); err != nil || cred == nil {
		slog.Warn("agent scan: local snmp credential not usable, falling back to scanner.snmp_community",
			"credential_id", id, "error", err)
		return 0
	}
	return id
}

// resolveAgentCredentialName maps a center-referenced credential NAME to a
// local vault ID (#241). Center and agent vault IDs are independent (separate
// tables), so the scan command payload carries the name, the stable
// cross-system key. Unknown name → community fallback with a warning.
func resolveAgentCredentialName(ctx context.Context, dbConn *sql.DB, r *credresolver.Resolver, name string) int64 {
	if name == "" || r == nil || dbConn == nil {
		return 0
	}
	row, err := credresolver.GetSNMPCredentialByName(ctx, dbConn, name)
	if err != nil {
		slog.Warn("agent scan: credential_name not found in local vault, falling back to scanner.snmp_community",
			"credential_name", name, "error", err)
		return 0
	}
	return resolveAgentCredentialID(ctx, r, row.ID)
}

// snmpCredentialSubcommand implements `mibee-agent snmp-credential`, the
// provisioning path for the agent-local SNMP credential vault (#241). The
// agent has no HTTP surface, so the operator manages its vault from the shell
// (the same trust model as editing agent.yaml). Passphrases are read flag >
// env > stdin prompt, encrypted with the AGENT's security.master_key before
// touching disk, and never echoed back, `list` shows the masked projection.
//
// Usage:
//
//	mibee-agent snmp-credential -config configs/agent.yaml -action add \
//	  -name switch-v3 -security-level authPriv -username snmpadmin \
//	  -auth-protocol SHA -priv-protocol AES
//	mibee-agent snmp-credential -config configs/agent.yaml -action list
//	mibee-agent snmp-credential -config configs/agent.yaml -action remove -name switch-v3
func snmpCredentialSubcommand(args []string) {
	fs := flag.NewFlagSet("snmp-credential", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/agent.yaml", "Path to agent config file")
	action := fs.String("action", "list", "add | list | remove")
	name := fs.String("name", "", "Credential name (unique)")
	securityLevel := fs.String("security-level", "", "v1v2c | noAuthNoPriv | authNoPriv | authPriv")
	community := fs.String("community", "", "SNMP v1/v2c community (security_level v1v2c)")
	username := fs.String("username", "", "SNMPv3 USM username")
	authProtocol := fs.String("auth-protocol", "", "SNMPv3 auth protocol: MD5|SHA|SHA224|SHA256|SHA384|SHA512")
	authPassphrase := fs.String("auth-passphrase", "", "SNMPv3 auth passphrase (prefer env/stdin to avoid shell history)")
	privProtocol := fs.String("priv-protocol", "", "SNMPv3 priv protocol: DES|AES|AES192|AES256|AES192C|AES256C")
	privPassphrase := fs.String("priv-passphrase", "", "SNMPv3 priv passphrase (prefer env/stdin)")
	notes := fs.String("notes", "", "Free-form note")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "mibee-agent %s: snmp credential vault\n", version.Version)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// The vault lives in the agent's mini-DB next to the config file, the
	// same path main() derives. openAgentDB applies the full mini schema, so
	// a fresh install (agent never started) gets the snmp_credentials table
	// here too.
	dbPath := filepath.Join(filepath.Dir(*cfgPath), "agent.db")
	conn, err := openAgentDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open agent db %s: %v\n", dbPath, err)
		os.Exit(1)
	}

	// runAction wraps the DB-touching logic so defer conn.Close() still runs
	// on the os.Exit path (same exitAfterDefer pattern as reset-admin-password).
	exitCode := func() int {
		defer conn.Close()

		// Every action except `list` needs the master key to encrypt.
		if cfg.Security.MasterKey == "" {
			fmt.Fprintln(os.Stderr, "security.master_key is not configured: the credential vault is disabled.")
			fmt.Fprintln(os.Stderr, "Set a 32-byte master key in the agent config (or MIBEE_SECURITY_MASTER_KEY) to use it.")
			if *action != "list" {
				return 1
			}
		} else if len(cfg.Security.MasterKey) != crypto.MasterKeyLen {
			fmt.Fprintf(os.Stderr, "security.master_key must be exactly %d bytes (got %d)\n",
				crypto.MasterKeyLen, len(cfg.Security.MasterKey))
			return 1
		}
		var cipher *crypto.Cipher
		if cfg.Security.MasterKey != "" {
			c, cerr := crypto.NewCipher([]byte(cfg.Security.MasterKey))
			if cerr != nil {
				fmt.Fprintf(os.Stderr, "Bad master key: %v\n", cerr)
				return 1
			}
			cipher = c
		}

		ctx := context.Background()
		switch *action {
		case "add":
			return addAgentCredential(ctx, conn, cipher, credWriteFlags{
				Name:           *name,
				SecurityLevel:  *securityLevel,
				Community:      *community,
				Username:       *username,
				AuthProtocol:   *authProtocol,
				AuthPassphrase: *authPassphrase,
				PrivProtocol:   *privProtocol,
				PrivPassphrase: *privPassphrase,
				Notes:          *notes,
			})
		case "list":
			return listAgentCredentials(ctx, conn)
		case "remove":
			return removeAgentCredential(ctx, conn, *name)
		default:
			fmt.Fprintf(os.Stderr, "unknown -action %q (use add | list | remove)\n", *action)
			return 2
		}
	}()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// credWriteFlags is the flattened flag set of `snmp-credential -action add`.
type credWriteFlags struct {
	Name           string
	SecurityLevel  string
	Community      string
	Username       string
	AuthProtocol   string
	AuthPassphrase string
	PrivProtocol   string
	PrivPassphrase string
	Notes          string
}

func addAgentCredential(ctx context.Context, conn *sql.DB, cipher *crypto.Cipher, f credWriteFlags) int {
	if cipher == nil {
		// Guard: unreachable via the CLI flow (exits earlier without a key),
		// keeps this function safe for future callers.
		fmt.Fprintln(os.Stderr, "credential vault disabled (no master key)")
		return 1
	}
	if f.Name == "" {
		fmt.Fprintln(os.Stderr, "-name is required")
		return 2
	}
	// Same validation semantics as the center handler (validateCredentialRequest).
	switch f.SecurityLevel {
	case "v1v2c":
		if f.Community == "" {
			fmt.Fprintln(os.Stderr, "-community is required for security_level v1v2c")
			return 2
		}
	case "noAuthNoPriv":
	case "authNoPriv":
		if f.Username == "" || f.AuthProtocol == "" {
			fmt.Fprintln(os.Stderr, "-username and -auth-protocol are required for authNoPriv")
			return 2
		}
	case "authPriv":
		if f.Username == "" || f.AuthProtocol == "" || f.PrivProtocol == "" {
			fmt.Fprintln(os.Stderr, "-username, -auth-protocol and -priv-protocol are required for authPriv")
			return 2
		}
	default:
		fmt.Fprintln(os.Stderr, "-security-level must be one of: v1v2c, noAuthNoPriv, authNoPriv, authPriv")
		return 2
	}
	// Passphrase input: flag > env > stdin prompt (the reset-admin-password
	// pattern; no echo suppression, headless boxes).
	if f.AuthPassphrase == "" && (f.SecurityLevel == "authNoPriv" || f.SecurityLevel == "authPriv") {
		f.AuthPassphrase = os.Getenv("MIBEE_AGENT_AUTH_PASSPHRASE")
	}
	if f.PrivPassphrase == "" && f.SecurityLevel == "authPriv" {
		f.PrivPassphrase = os.Getenv("MIBEE_AGENT_PRIV_PASSPHRASE")
	}
	if f.AuthPassphrase == "" && (f.SecurityLevel == "authNoPriv" || f.SecurityLevel == "authPriv") {
		fmt.Fprint(os.Stderr, "Enter auth passphrase: ")
		f.AuthPassphrase = readLineFromStdin()
		fmt.Fprintln(os.Stderr)
	}
	if f.PrivPassphrase == "" && f.SecurityLevel == "authPriv" {
		fmt.Fprint(os.Stderr, "Enter priv passphrase: ")
		f.PrivPassphrase = readLineFromStdin()
		fmt.Fprintln(os.Stderr)
	}

	authEnc, encErr := cipher.Encrypt(f.AuthPassphrase)
	if encErr != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt auth passphrase: %v\n", encErr)
		return 1
	}
	privEnc, encErr := cipher.Encrypt(f.PrivPassphrase)
	if encErr != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt priv passphrase: %v\n", encErr)
		return 1
	}
	id, err := credresolver.CreateSNMPCredential(ctx, conn, credresolver.SNMPCredentialWriteParams{
		Name:              f.Name,
		SecurityLevel:     f.SecurityLevel,
		Community:         f.Community,
		Username:          f.Username,
		AuthProtocol:      f.AuthProtocol,
		AuthPassphraseEnc: authEnc,
		PrivProtocol:      f.PrivProtocol,
		PrivPassphraseEnc: privEnc,
		Notes:             f.Notes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create credential: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "created credential %q (id=%d) in the agent-local vault\n", f.Name, id)
	fmt.Fprintln(os.Stderr, "bind scans via credential_id on the agent's scan_tasks, or by name from the center's dispatch payload")
	return 0
}

func listAgentCredentials(ctx context.Context, conn *sql.DB) int {
	rows, err := credresolver.ListSNMPCredentials(ctx, conn, 1000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to list credentials: %v\n", err)
		return 1
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no credentials in the local vault")
		return 0
	}
	fmt.Printf("%-4s %-24s %-14s %-18s %-10s %-8s %s\n", "ID", "NAME", "LEVEL", "USERNAME", "AUTH", "PRIV", "NOTES")
	for _, r := range rows {
		fmt.Printf("%-4d %-24s %-14s %-18s %-10s %-8s %s\n",
			r.ID, r.Name, r.SecurityLevel, r.Username,
			orDash(r.AuthProtocol), orDash(r.PrivProtocol), r.Notes)
	}
	return 0
}

func removeAgentCredential(ctx context.Context, conn *sql.DB, name string) int {
	if name == "" {
		fmt.Fprintln(os.Stderr, "-name is required for remove")
		return 2
	}
	row, err := credresolver.GetSNMPCredentialByName(ctx, conn, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "credential %q not found\n", name)
		return 1
	}
	if _, err := credresolver.DeleteSNMPCredential(ctx, conn, row.ID); err != nil {
		fmt.Fprintf(os.Stderr, "failed to delete credential: %v\n", err)
		return 1
	}
	// The mini-DB's scan_tasks.credential_id has no FK to snmp_credentials
	// (the table postdates it), so mirror the center's ON DELETE SET NULL by
	// hand: tasks bound to the removed credential fall back to the community.
	if _, err := conn.ExecContext(ctx,
		`UPDATE scan_tasks SET credential_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE credential_id = ?`,
		row.ID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: credential deleted but unbinding scan_tasks failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "removed credential %q (id=%d); bound scan tasks fall back to scanner.snmp_community\n", name, row.ID)
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// readLineFromStdin reads a single line, trimming the trailing newline (same
// non-echo-suppressing headless pattern as cmd/server's reset_password.go).
func readLineFromStdin() string {
	buf := make([]byte, 0, 256)
	for {
		var b [1]byte
		n, err := os.Stdin.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			if b[0] == '\r' {
				continue
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return strings.TrimSpace(string(buf))
		}
	}
	return strings.TrimSpace(string(buf))
}
