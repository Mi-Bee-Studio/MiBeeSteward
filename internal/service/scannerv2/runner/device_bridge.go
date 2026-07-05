package runner

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// applyDeviceBridge mirrors v1's DeviceManager.CreateOrUpdate: for an alive
// host, create or update the devices row (filling only empty/"unknown" fields
// on update) and — for newly-created devices — seed heartbeat configs derived
// from the report's heartbeats. Returns (isNew, wasUpdated).
//
// The v2 HostReport already carries enriched device fields (set by
// ServiceHandlers) and generated heartbeats, so this function is a thin
// adapter from the in-memory report to the devices/heartbeat_configs tables.
func (rn *Runner) applyDeviceBridge(ctx context.Context, rep scannerv2.HostReport) (bool, bool) {
	inferredType := rep.Device.Fields["inferred_type"]
	if inferredType == "" {
		inferredType = "other"
	}
	inferredBrand := rep.Device.Fields["inferred_brand"]
	inferredDescr := rep.Device.Fields["inferred_description"]
	inferredLoc := rep.Device.Fields["inferred_location"]

	// Look up existing device by IP.
	var existingID int64
	err := rn.dbConn.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE ip_address = ? LIMIT 1`, rep.IP).Scan(&existingID)

	switch {
	case err == sql.ErrNoRows:
		devID, derr := rn.createDevice(ctx, inferredType, inferredBrand, inferredDescr, inferredLoc, rep)
		if derr != nil {
			rn.logger.Warn("device bridge: create device failed", "ip", rep.IP, "error", derr)
			return false, false
		}
		// Seed heartbeat configs (new devices only, matching v1 behavior).
		if rn.heartbeat != nil && len(rep.Heartbeats) > 0 {
			if herr := rn.heartbeat.CreateConfigs(ctx, devID, rep.Heartbeats); herr != nil {
				rn.logger.Warn("device bridge: seed heartbeats failed", "ip", rep.IP, "error", herr)
			}
		}
		return true, false

	case err == nil:
		if _, uerr := rn.dbConn.ExecContext(ctx, buildExistingUpdate(inferredType, inferredBrand, inferredDescr, inferredLoc, rep),
			existingUpdateArgs(existingID, inferredType, inferredBrand, inferredDescr, inferredLoc, rep)...); uerr != nil {
			rn.logger.Warn("device bridge: update device failed", "ip", rep.IP, "error", uerr)
		}
		// Always set status=online for alive hosts (matches v1).
		now := time.Now().UTC()
		_, _ = rn.dbConn.ExecContext(ctx, `UPDATE devices SET status='online', last_scanned_at=?, updated_at=? WHERE id=?`,
			now, now, existingID)
		return false, true

	default:
		rn.logger.Warn("device bridge: lookup failed", "ip", rep.IP, "error", err)
		return false, false
	}
}

// createDevice inserts a new device row derived from the report.
func (rn *Runner) createDevice(ctx context.Context, devType, brand, descr, location string, rep scannerv2.HostReport) (int64, error) {
	name := rep.IP
	if h := rep.Device.Fields["node_hostname"]; h != "" {
		name = h
	} else if h := rep.Device.Fields["sys_name"]; h != "" {
		name = h
	}
	if devType == "" {
		devType = "other"
	}
	ports, services := deviceScanInfoJSON(rep)
	promURL := rep.Device.Fields["prometheus_url"]
	neURL := rep.Device.Fields["node_exporter_url"]
	tags := buildDeviceTags(devType, brand, rep)
	now := time.Now().UTC()
	res, err := rn.dbConn.ExecContext(ctx, `
		INSERT INTO devices (name, type, brand, ip_address, status, scan_source, description, location,
		                     open_ports, detected_services, prometheus_url, node_exporter_url,
		                     tags, last_scan_rtt_ms, last_scanned_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'online', 'scanner_v2', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, devType, brand, rep.IP, descr, location, ports, services, promURL, neURL, tags, rep.RTTMs, now, now, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// buildExistingUpdate returns an UPDATE statement that fills only empty/
// "unknown" fields on the existing device, then always refreshes scan metadata.
func buildExistingUpdate(inferredType, brand, descr, location string, rep scannerv2.HostReport) string {
	return `
		UPDATE devices SET
		    name = CASE WHEN (name = '' OR name = ip_address) THEN ? ELSE name END,
		    type = CASE WHEN (type = '' OR type = 'unknown' OR type = 'other') AND ? != '' THEN ? ELSE type END,
		    brand = CASE WHEN (brand = '' OR brand = 'unknown') AND ? != '' THEN ? ELSE brand END,
		    description = CASE WHEN (description = '' OR description = 'unknown') AND ? != '' THEN ? ELSE description END,
		    location = CASE WHEN (location = '' OR location = 'unknown') AND ? != '' THEN ? ELSE location END,
		    open_ports = ?,
		    detected_services = ?,
		    prometheus_url = CASE WHEN ? != '' THEN ? ELSE prometheus_url END,
		    node_exporter_url = CASE WHEN ? != '' THEN ? ELSE node_exporter_url END,
		    last_scan_rtt_ms = ?,
		    last_scanned_at = ?,
		    updated_at = ?
		WHERE id = ?`
}

// existingUpdateArgs builds the positional args matching buildExistingUpdate's
// placeholder order.
func existingUpdateArgs(id int64, inferredType, brand, descr, location string, rep scannerv2.HostReport) []any {
	ports, services := deviceScanInfoJSON(rep)
	promURL := rep.Device.Fields["prometheus_url"]
	neURL := rep.Device.Fields["node_exporter_url"]
	now := time.Now().UTC()
	return []any{
		rep.IP, inferredType, inferredType,
		brand, brand,
		descr, descr,
		location, location,
		ports, services,
		promURL, promURL,
		neURL, neURL,
		rep.RTTMs, now, now, id,
	}
}

func isUnknown(s string) bool {
	return s == "" || strings.EqualFold(s, "unknown")
}

// deviceScanInfoJSON returns the open_ports + detected_services JSON for the
// devices row.
//
// Format contract (must match the device detail page's parser, which casts
// each element to {port, name?,/service?}):
//   - open_ports:        [{ "port": int, "service": string }]
//   - detected_services: [{ "port": int, "name": string, "protocol": string }]
//
// The previous implementation emitted a bare int array ([80,554,8000]) and a
// bare string array (["camera","onvif","rtsp"]). The frontend's
// parseJsonArray(... as Array<{port,name,protocol}>) then read svc.port as
// undefined for every element, so the Scan Info panel rendered nothing — the
// scan had enriched the device but the user couldn't see it on the web.
func deviceScanInfoJSON(rep scannerv2.HostReport) (string, string) {
	// open_ports: deduped port list, each annotated with the matching service
	// name (if any classifier identified a service on that port).
	portToService := map[int]string{}
	for _, s := range rep.Services {
		if s.Port > 0 && s.Service != "" {
			if _, ok := portToService[s.Port]; !ok {
				portToService[s.Port] = s.Service
			}
		}
	}
	ports := uniqueOpenPorts(rep.Evidence)
	type portEntry struct {
		Port    int    `json:"port"`
		Service string `json:"service,omitempty"`
	}
	portEntries := make([]portEntry, 0, len(ports))
	for _, p := range ports {
		portEntries = append(portEntries, portEntry{Port: p, Service: portToService[p]})
	}
	portsJSON := "[]"
	if b, err := json.Marshal(portEntries); err == nil {
		portsJSON = string(b)
	}

	// detected_services: one entry per classified ServiceIdentity, carrying
	// port + canonical name + protocol so the UI can render "80/http" style
	// badges instead of bare strings with no port context.
	type svcEntry struct {
		Port     int    `json:"port"`
		Name     string `json:"name"`
		Protocol string `json:"protocol,omitempty"`
	}
	svcEntries := make([]svcEntry, 0, len(rep.Services))
	for _, s := range rep.Services {
		svcEntries = append(svcEntries, svcEntry{
			Port:     s.Port,
			Name:     s.Service,
			Protocol: s.Protocol,
		})
	}
	svcJSON := "[]"
	if b, err := json.Marshal(svcEntries); err == nil {
		svcJSON = string(b)
	}
	return portsJSON, svcJSON
}

// buildDeviceTags constructs a JSON tag array from type + brand + services.
func buildDeviceTags(devType, brand string, rep scannerv2.HostReport) string {
	tags := map[string]bool{devType: true}
	if brand != "" {
		tags[brand] = true
	}
	for _, s := range rep.Services {
		tags[s.Service] = true
	}
	out := make([]string, 0, len(tags))
	for t := range tags {
		if t != "" {
			out = append(out, t)
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// keep slog referenced for the warn logs above when this file is the only user
var _ = slog.Default
