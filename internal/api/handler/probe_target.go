// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probetarget"
)

// ProbeTargetHandler handles HTTP requests for synthetic probing (拨测)
// targets: CRUD + trigger + result history + certificate chain. Mutations go
// through the Service; the certificates sub-resource is a read-only
// *db.Queries passthrough (the sanctioned TLSCertHandler pattern).
type ProbeTargetHandler struct {
	service *probetarget.Service
	queries *db.Queries
}

// NewProbeTargetHandler constructs a ProbeTargetHandler.
func NewProbeTargetHandler(service *probetarget.Service, queries *db.Queries) *ProbeTargetHandler {
	return &ProbeTargetHandler{service: service, queries: queries}
}

// CreateTarget handles POST /api/v1/probe-targets
func (h *ProbeTargetHandler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	var req domain.ProbeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.service.Create(r.Context(), req)
	if err != nil {
		if errors.Is(err, probetarget.ErrDuplicateName) {
			Error(w, http.StatusConflict, "a probe target with this name already exists")
			return
		}
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	Created(w, resp)
}

// ListTargets handles GET /api/v1/probe-targets
func (h *ProbeTargetHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	search := q.Get("search")

	targets, total, err := h.service.List(r.Context(), search, int(limit), int(offset))
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list probe targets")
		return
	}
	Success(w, domain.ProbeTargetListResponse{Targets: targets, Total: int(total)})
}

// GetTarget handles GET /api/v1/probe-targets/{id}
func (h *ProbeTargetHandler) GetTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parseProbeID(w, r)
	if err != nil {
		return
	}
	resp, err := h.service.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, probetarget.ErrProbeTargetNotFound) {
			Error(w, http.StatusNotFound, "probe target not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get probe target")
		return
	}
	Success(w, resp)
}

// UpdateTarget handles PUT /api/v1/probe-targets/{id}
func (h *ProbeTargetHandler) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parseProbeID(w, r)
	if err != nil {
		return
	}
	var req domain.UpdateProbeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.service.Update(r.Context(), id, req)
	if err != nil {
		switch {
		case errors.Is(err, probetarget.ErrProbeTargetNotFound):
			Error(w, http.StatusNotFound, "probe target not found")
		case errors.Is(err, probetarget.ErrDuplicateName):
			Error(w, http.StatusConflict, "a probe target with this name already exists")
		default:
			Error(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	Success(w, resp)
}

// DeleteTarget handles DELETE /api/v1/probe-targets/{id}
func (h *ProbeTargetHandler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parseProbeID(w, r)
	if err != nil {
		return
	}
	if err := h.service.Delete(r.Context(), id); err != nil {
		if errors.Is(err, probetarget.ErrProbeTargetNotFound) {
			Error(w, http.StatusNotFound, "probe target not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete probe target")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TriggerTarget handles POST /api/v1/probe-targets/{id}/trigger. Synchronous
// by design: the response carries the just-recorded result (bounded by the
// target's timeout), so the UI can refresh with real data instead of polling.
func (h *ProbeTargetHandler) TriggerTarget(w http.ResponseWriter, r *http.Request) {
	id, err := parseProbeID(w, r)
	if err != nil {
		return
	}
	resp, err := h.service.Trigger(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, probetarget.ErrProbeTargetNotFound):
			Error(w, http.StatusNotFound, "probe target not found")
		case errors.Is(err, probetarget.ErrProbeTargetDisabled):
			Error(w, http.StatusConflict, "probe target is disabled; enable it before triggering")
		case errors.Is(err, probetarget.ErrProbeBusy):
			Error(w, http.StatusConflict, "a probe of this target is already in flight")
		case errors.Is(err, probetarget.ErrProbeVantageNotLocal):
			Error(w, http.StatusConflict, "target vantage assigns execution to an agent; trigger it from the agent's vantage")
		case errors.Is(err, probetarget.ErrEngineNotAvailable):
			Error(w, http.StatusServiceUnavailable, "probe engine is not available")
		default:
			Error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	Success(w, resp)
}

// GetTargetResults handles GET /api/v1/probe-targets/{id}/results
func (h *ProbeTargetHandler) GetTargetResults(w http.ResponseWriter, r *http.Request) {
	id, err := parseProbeID(w, r)
	if err != nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	vantage := strings.TrimSpace(q.Get("vantage"))
	if vantage != "" {
		if v, err := domain.NormalizeProbeVantage(vantage); err != nil {
			Error(w, http.StatusBadRequest, err.Error())
			return
		} else if v == domain.ProbeVantageAll {
			Error(w, http.StatusBadRequest, "vantage filter must be \"center\" or \"agent:{agent_id}\", not \"all\"")
			return
		}
	}

	results, total, err := h.service.Results(r.Context(), id, vantage, int(limit), int(offset))
	if err != nil {
		if errors.Is(err, probetarget.ErrProbeTargetNotFound) {
			Error(w, http.StatusNotFound, "probe target not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to list probe results")
		return
	}
	Success(w, domain.ProbeResultListResponse{Results: results, Total: int(total)})
}

// GetTargetCertificates handles GET /api/v1/probe-targets/{id}/certificates —
// the target's current certificate chain. Returns the SAME tlsPortCerts shape
// as the device certificates endpoint, so the frontend reuses
// CertificateModal unmodified (one entry: a target probes one port).
func (h *ProbeTargetHandler) GetTargetCertificates(w http.ResponseWriter, r *http.Request) {
	id, err := parseProbeID(w, r)
	if err != nil {
		return
	}
	rows, err := h.queries.ListProbeTLSCertsByTarget(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query certificates")
		return
	}

	out := make([]tlsPortCerts, 0, 1)
	if len(rows) > 0 {
		entry := tlsPortCerts{
			Port:        int(rows[0].Port),
			TLSVersion:  rows[0].TlsVersion,
			CipherSuite: rows[0].CipherSuite,
			Trusted:     rows[0].Trusted == 1,
			Error:       rows[0].Error,
			UpdatedAt:   rows[0].UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Chain:       []certificateInfo{},
		}
		for _, row := range rows {
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
		out = append(out, entry)
	}
	Success(w, map[string]any{"certificates": out, "total": len(out)})
}

// parseProbeID extracts and validates the {id} path parameter.
func parseProbeID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid ID")
		return 0, err
	}
	return id, nil
}
