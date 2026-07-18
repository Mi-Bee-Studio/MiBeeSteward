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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/engine"
	"mibee-steward/internal/service/scannerv2/runner"
)

// ScannerHandler handles the synchronous scan + add-devices endpoints,
// backed by the v2 detection engine.
type ScannerHandler struct {
	engine *engine.Engine
	runner *runner.Runner // used by AddDevices to persist manually-added devices
}

// NewScannerHandler creates a ScannerHandler. engine drives /scan; runner is
// used by /add-devices to write device rows via its device-bridge path.
func NewScannerHandler(eng *engine.Engine, rn *runner.Runner) *ScannerHandler {
	return &ScannerHandler{engine: eng, runner: rn}
}

// Scan handles POST /api/v1/scanner/scan.
// Runs the v2 engine synchronously over the requested targets and returns the
// per-host results (with v2-inferred type/brand/services). The synchronous scan
// does not persist; cron-driven scans (task scheduler) and manual device
// additions (AddDevices) go through the persistence path.
func (h *ScannerHandler) Scan(w http.ResponseWriter, r *http.Request) {
	var req domain.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Targets == "" {
		Error(w, http.StatusBadRequest, "targets is required")
		return
	}
	if req.Timeout <= 0 {
		req.Timeout = 2
	}
	if req.Community == "" {
		req.Community = "public"
	}

	// Synchronous scans are bounded: estimate the target count up front and
	// reject ranges too large to complete within the server's WriteTimeout.
	// Callers scanning large CIDRs should use the async task API instead
	// (POST /scanner/tasks + /scanner/tasks/{id}/trigger + GET .../runs).
	count, err := h.engine.EstimateTargetCount(req.Targets)
	if err != nil {
		if isInvalidTargetError(err.Error()) {
			Error(w, http.StatusBadRequest, "invalid IP address or CIDR range")
			return
		}
		Error(w, http.StatusBadRequest, "invalid targets: "+err.Error())
		return
	}
	// Worst-case wall time ≈ ceil(count / concurrency) × perHost. With the
	// default floor of 10s/host and concurrency 50, 256 hosts ≈ 60s. Cap sync
	// scans at a safe count that fits a typical 5-min WriteTimeout.
	const maxSyncTargets = 1024
	if count > maxSyncTargets {
		Error(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("target range too large for synchronous scan (%d IPs; max %d). Use POST /api/v1/scanner/tasks to run asynchronously.", count, maxSyncTargets))
		return
	}

	perHost := time.Duration(req.Timeout) * time.Second
	if perHost < 5*time.Second {
		perHost = 10 * time.Second // floor for the multi-probe pipeline
	}
	h.engine.Orchestrator.SetTimeouts(perHost, h.engine.Orchestrator.MaxConcurrentHosts())

	start := time.Now()
	reports, err := h.engine.ScanTargets(r.Context(), req.Targets, false)
	duration := time.Since(start)
	if err != nil {
		if isInvalidTargetError(err.Error()) {
			Error(w, http.StatusBadRequest, "invalid IP address or CIDR range")
			return
		}
		// A context.DeadlineExceeded means the server WriteTimeout fired mid-scan
		// (shouldn't happen given the pre-check, but defend against config drift).
		if errors.Is(err, context.DeadlineExceeded) {
			Error(w, http.StatusGatewayTimeout, "scan exceeded server timeout; reduce the target range or use the async task API")
			return
		}
		Error(w, http.StatusInternalServerError, "scan failed")
		return
	}

	hosts := make([]domain.ScanHost, 0, len(reports))
	aliveCount := 0
	for _, rep := range reports {
		if rep.Alive {
			aliveCount++
		}
		hosts = append(hosts, reportToHost(rep))
	}

	resp := domain.ScanResponse{
		Hosts:      hosts,
		Total:      len(reports),
		Alive:      aliveCount,
		DurationMs: duration.Milliseconds(),
	}
	Success(w, resp)
}

// AddDevices handles POST /api/v1/scanner/add-devices.
// Manually-added devices bypass detection; we synthesize a HostReport from the
// request and run it through the runner's device bridge so the same create/
// update + heartbeat-seeding path is reused.
func (h *ScannerHandler) AddDevices(w http.ResponseWriter, r *http.Request) {
	var req domain.AddDevicesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Devices) == 0 {
		Error(w, http.StatusBadRequest, "devices array must not be empty")
		return
	}

	added := 0
	var errs []string
	for _, item := range req.Devices {
		rep := addDeviceItemToReport(item)
		if _, err := h.runner.PersistManualDevice(r.Context(), rep); err != nil {
			errs = append(errs, item.IP+": "+err.Error())
			continue
		}
		added++
	}

	// If every device failed to persist, surface a non-200 status so clients
	// checking the status code don't mistake it for success. 422 (Unprocessable)
	// signals "request was valid but the operation couldn't be applied".
	resp := domain.AddDevicesResponse{Added: added, Errors: errs}
	if added == 0 && len(errs) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	Success(w, resp)
}

// isInvalidTargetError recognizes target-parse failures from the engine so the
// handler can map them to HTTP 400.
func isInvalidTargetError(errMsg string) bool {
	if errMsg == "" {
		return false
	}
	lower := strings.ToLower(errMsg)
	for _, frag := range []string{"invalid target", "no targets", "invalid ip", "invalid cidr", "invalid ip range", "invalid targets format", "invalid end ip", "invalid start ip"} {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// reportToHost converts a v2 HostReport into the API's domain.ScanHost,
// surfacing the v2-inferred type/brand/description and the SNMP varbinds.
func reportToHost(rep scannerv2.HostReport) domain.ScanHost {
	host := domain.ScanHost{
		IP:    rep.IP,
		Alive: rep.Alive,
		RTTMs: rep.RTTMs,
	}
	// Prefer the ICMP echo evidence's measured RTT (orchestrator stores RTT on
	// the echo evidence, not on HostReport directly).
	for _, e := range rep.Evidence {
		if e.Kind == "echo" && e.RawData != nil {
			if v := e.RawData["rtt_ms"]; v != "" {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					host.RTTMs = n
				}
			}
			break
		}
	}
	for _, e := range rep.Evidence {
		if e.Kind == "snmp" && e.RawData != nil {
			host.SNMPSuccess = true
			host.SNMPDescr = e.RawData["sys_descr"]
			host.SNMPObjID = e.RawData["sys_object_id"]
			host.SNMPLocation = e.RawData["sys_location"]
			host.SNMPContact = e.RawData["sys_contact"]
			host.SNMPName = e.RawData["sys_name"]
			if v, ok := e.RawData["sys_up_time"]; ok {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					host.SNMPUptime = n
				}
			}
			if v, ok := e.RawData["sys_services"]; ok {
				if n, err := strconv.Atoi(v); err == nil {
					host.SNMPServices = n
				}
			}
			if v, ok := e.RawData["if_number"]; ok {
				if n, err := strconv.Atoi(v); err == nil {
					host.SNMPIfCount = n
				}
			}
			break
		}
	}
	if rep.Device.Fields != nil {
		host.InferredType = rep.Device.Fields["inferred_type"]
		host.InferredBrand = rep.Device.Fields["inferred_brand"]
		host.InferredDescription = rep.Device.Fields["inferred_description"]
		host.InferredLocation = rep.Device.Fields["inferred_location"]
	}
	return host
}

// addDeviceItemToReport synthesizes a HostReport from a manual AddDeviceItem so
// the runner's device bridge can persist it.
func addDeviceItemToReport(item domain.AddDeviceItem) scannerv2.HostReport {
	rep := scannerv2.HostReport{
		IP:    item.IP,
		Alive: true,
		RTTMs: item.RTTMs,
		Device: scannerv2.DeviceRef{
			IP:    item.IP,
			Name:  item.Name,
			Type:  item.Type,
			Brand: item.Brand,
			Model: item.Model,
			Fields: map[string]string{
				"inferred_type":        item.Type,
				"inferred_brand":       item.Brand,
				"inferred_description": item.Description,
				"inferred_location":    item.Location,
			},
		},
	}
	if item.PromURL != "" {
		rep.Device.Fields["prometheus_url"] = item.PromURL
	}
	if item.NEURL != "" {
		rep.Device.Fields["node_exporter_url"] = item.NEURL
	}
	if len(item.Ports) > 0 {
		ports := make([]int, 0, len(item.Ports))
		for _, p := range item.Ports {
			ports = append(ports, p.Port)
		}
		if b, err := json.Marshal(ports); err == nil {
			rep.Device.Fields["open_ports"] = string(b)
		}
	}
	if len(item.Services) > 0 {
		svcs := make([]string, 0, len(item.Services))
		for _, s := range item.Services {
			svcs = append(svcs, s.Name)
		}
		if b, err := json.Marshal(svcs); err == nil {
			rep.Device.Fields["detected_services"] = string(b)
		}
	}
	return rep
}

var _ = errors.New
