// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
)

// TLSCertHandler serves the TLS certificate chain data collected by the
// scannerv2 TLS-wrapped service handlers (https/ldaps/imaps/pop3s/smtps/ftps/
// ircs/telnets). Used by the device-detail "TLS Certificates" sub-panel and the
// certificate Modal that shows the full chain + PEM.
//
// Like NeighborHandler it depends on *db.Queries directly (sub-resource,
// read-only) rather than going through a Service — this matches the AGENTS.md
// sanctioned exception for sub-resource reads.
type TLSCertHandler struct {
	queries *db.Queries
}

// NewTLSCertHandler constructs the handler. queries is the center's *db.Queries.
func NewTLSCertHandler(queries *db.Queries) *TLSCertHandler {
	return &TLSCertHandler{queries: queries}
}

// certificateInfo is one certificate in a port's chain. Mirrors the columns of
// host_tls_certs but with ints/bools coerced from the SQLite INTEGER encoding
// (0/1) so the frontend doesn't have to.
type certificateInfo struct {
	CertIndex         int    `json:"cert_index"`
	SubjectCN         string `json:"subject_cn"`
	SubjectOrg        string `json:"subject_org"`
	Subject           string `json:"subject"`
	IssuerCN          string `json:"issuer_cn"`
	IssuerOrg         string `json:"issuer_org"`
	Issuer            string `json:"issuer"`
	SanDNS            string `json:"san_dns"`
	SanIP             string `json:"san_ip"`
	SanEmail          string `json:"san_email"`
	Serial            string `json:"serial"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	SigAlgorithm      string `json:"sig_algorithm"`
	KeyAlgorithm      string `json:"key_algorithm"`
	KeyBits           int    `json:"key_bits"`
	IsCA              bool   `json:"is_ca"`
	SelfSigned        bool   `json:"self_signed"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	PEM               string `json:"pem"`
}

// tlsPortCerts bundles every cert for one port with the handshake metadata
// (negotiated TLS version + cipher, trust verdict, error). The leaf
// (cert_index=0) is surfaced separately for the panel's at-a-glance summary;
// `chain` is the full ordered list (leaf first) for the Modal.
type tlsPortCerts struct {
	Port        int               `json:"port"`
	TLSVersion  string            `json:"tls_version"`
	CipherSuite string            `json:"cipher_suite"`
	Trusted     bool              `json:"trusted"`
	Error       string            `json:"error,omitempty"`
	UpdatedAt   string            `json:"updated_at"`
	Leaf        *certificateInfo  `json:"leaf,omitempty"`
	Chain       []certificateInfo `json:"chain"`
}

// ListByDevice handles GET /api/v1/devices/{id}/certificates — the TLS
// certificate chains collected from every TLS-speaking port on the device.
// Grouped by port (one entry per port). Any logged-in user may read.
//
// Returns 200 with an empty `certificates` array (not 404) when the device has
// no recorded certs — the frontend renders an "No certificates" empty state.
func (h *TLSCertHandler) ListByDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	rows, err := h.queries.ListTLSCertsByDeviceID(r.Context(), id)
	if err != nil {
		if errors.Is(err, errDeviceMissing) { // future: 404 if device doesn't exist
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to query certificates")
		return
	}

	// Group rows by port (rows come ordered by port, cert_index).
	byPort := make(map[int]*tlsPortCerts)
	var ordered []*tlsPortCerts
	for _, row := range rows {
		entry, exists := byPort[int(row.Port)]
		if !exists {
			entry = &tlsPortCerts{
				Port:        int(row.Port),
				TLSVersion:  row.TlsVersion,
				CipherSuite: row.CipherSuite,
				Trusted:     row.Trusted == 1,
				Error:       row.Error,
				UpdatedAt:   row.UpdatedAt.UTC().Format(time.RFC3339),
				Chain:       []certificateInfo{},
			}
			byPort[int(row.Port)] = entry
			ordered = append(ordered, entry)
		}
		ci := certificateInfo{
			CertIndex:         int(row.CertIndex),
			SubjectCN:         row.SubjectCn,
			SubjectOrg:        row.SubjectOrg,
			Subject:           row.Subject,
			IssuerCN:          row.IssuerCn,
			IssuerOrg:         row.IssuerOrg,
			Issuer:            row.Issuer,
			SanDNS:            row.SanDns,
			SanIP:             row.SanIp,
			SanEmail:          row.SanEmail,
			Serial:            row.Serial,
			NotBefore:         row.NotBefore,
			NotAfter:          row.NotAfter,
			SigAlgorithm:      row.SigAlgorithm,
			KeyAlgorithm:      row.KeyAlgorithm,
			KeyBits:           int(row.KeyBits),
			IsCA:              row.IsCa == 1,
			SelfSigned:        row.SelfSigned == 1,
			FingerprintSHA256: row.FingerprintSha256,
			PEM:               row.Pem,
		}
		entry.Chain = append(entry.Chain, ci)
		if ci.CertIndex == 0 {
			leaf := ci
			entry.Leaf = &leaf
		}
	}

	out := make([]tlsPortCerts, 0, len(ordered))
	for _, e := range ordered {
		out = append(out, *e)
	}
	Success(w, map[string]any{"certificates": out, "total": len(out)})
}

// errDeviceMissing is reserved for a future explicit "device does not exist"
// distinction (ListTLSCertsByDeviceID currently returns an empty slice for an
// unknown device, same as for a real device with no certs). Kept here so the
// 404 branch above compiles today without dead-code warnings.
var errDeviceMissing = errors.New("device not found")
