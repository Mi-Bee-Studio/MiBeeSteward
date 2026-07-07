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
	// A service handler may have set a generic "server"/"pc" type from a single
	// open port (ssh, smb, mysql, …). That's a weak signal — routers, NAS, and
	// cameras all run ssh/smb too. If the hostname/vendor carries a STRONGER,
	// device-specific signal (an explicit router/camera/nas/printer/embedded
	// model name), let the heuristic override the generic verdict. We still
	// trust handler-set specialized types (camera/router/switch/…) as-is: those
	// come from SNMP sysObjectID or protocol detection and are authoritative.
	if inferredType == "" || inferredType == "server" || inferredType == "pc" {
		if t := heuristicDeviceType(rep); t != "" && t != "server" && t != "pc" {
			// Specialized heuristic verdict (router/camera/nas/…) beats the
			// generic handler verdict.
			inferredType = t
		} else if inferredType == "" {
			// No handler verdict and no specialized heuristic — take whatever
			// the heuristic offers (including "" → falls to "other" below, or a
			// heuristic "server" from ssh+exporter).
			inferredType = t
		}
	}
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

	switch err {
	case sql.ErrNoRows:
		devID, derr := rn.createDevice(ctx, inferredType, inferredBrand, inferredDescr, inferredLoc, rep)
		if derr != nil {
			rn.logger.Warn("device bridge: create device failed", "ip", rep.IP, "error", derr)
			return false, false
		}
		// A freshly-discovered alive host starts online; make sure the heartbeat
		// service holds no stale failure state for it before configs are seeded.
		if rn.heartbeat != nil {
			rn.heartbeat.ResetFailures(devID)
		}
		// Seed heartbeat configs (new devices only, matching v1 behavior).
		if rn.heartbeat != nil {
			if len(rep.Heartbeats) > 0 {
				if herr := rn.heartbeat.CreateConfigs(ctx, devID, rep.Heartbeats); herr != nil {
					rn.logger.Warn("device bridge: seed heartbeats failed", "ip", rep.IP, "error", herr)
				}
			} else {
				// No service was identified (no open ports, or ports the classifiers
				// don't recognize). Without a heartbeat config this device would be
				// discovered once and then never probed again — it would show
				// "no heartbeat" forever even though we just proved it's alive.
				// Fall back to an ICMP config so every discovered host gets at least
				// liveness monitoring. The device already has an IP (rep.IP) and was
				// reached by the scan, so ICMP is always a valid probe target.
				if herr := rn.heartbeat.CreateDefaultConfig(ctx, devID, rep.IP); herr != nil {
					rn.logger.Warn("device bridge: seed ICMP fallback heartbeat failed", "ip", rep.IP, "error", herr)
				}
			}
		}
		return true, false

	case nil:
		if _, uerr := rn.dbConn.ExecContext(ctx, buildExistingUpdate(inferredType, inferredBrand, inferredDescr, inferredLoc, rep),
			existingUpdateArgs(existingID, inferredType, inferredBrand, inferredDescr, inferredLoc, rep)...); uerr != nil {
			rn.logger.Warn("device bridge: update device failed", "ip", rep.IP, "error", uerr)
		}
		// Always set status=online for alive hosts (matches v1).
		now := time.Now().UTC()
		_, _ = rn.dbConn.ExecContext(ctx, `UPDATE devices SET status='online', last_scanned_at=?, updated_at=? WHERE id=?`,
			now, now, existingID)
		// Clear the heartbeat service's failure counter for this device: the
		// scan just proved it's alive, so a stale counter from a prior flapping
		// window must not pull it back to offline on the next heartbeat tick.
		if rn.heartbeat != nil {
			rn.heartbeat.ResetFailures(existingID)
			// Backfill heartbeat configs for pre-existing devices that were
			// discovered before the "always seed at least ICMP" fallback existed.
			// These hosts have been scanned repeatedly but never got a config
			// (because no service was identified on any scan), so they show
			// "no heartbeat" forever. Only act when the device has ZERO configs
			// to avoid duplicating configs on devices that already have some.
			if rn.deviceHasHeartbeatConfig(ctx, existingID) {
				// already monitored — nothing to backfill
			} else if len(rep.Heartbeats) > 0 {
				if herr := rn.heartbeat.CreateConfigs(ctx, existingID, rep.Heartbeats); herr != nil {
					rn.logger.Warn("device bridge: backfill heartbeats failed", "ip", rep.IP, "error", herr)
				}
			} else {
				if herr := rn.heartbeat.CreateDefaultConfig(ctx, existingID, rep.IP); herr != nil {
					rn.logger.Warn("device bridge: backfill ICMP fallback heartbeat failed", "ip", rep.IP, "error", herr)
				}
			}
		}
		return false, true

	default:
		rn.logger.Warn("device bridge: lookup failed", "ip", rep.IP, "error", err)
		return false, false
	}
}

// deviceHasHeartbeatConfig reports whether the device already has any row in
// heartbeat_configs. Used by the existing-device branch to decide whether to
// backfill a config: only seed when zero exist, so we never duplicate.
func (rn *Runner) deviceHasHeartbeatConfig(ctx context.Context, deviceID int64) bool {
	var n int
	err := rn.dbConn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM heartbeat_configs WHERE device_id = ?`, deviceID).Scan(&n)
	if err != nil {
		// On query error, assume it has configs so we don't risk duplicating.
		rn.logger.Warn("device bridge: heartbeat_configs count failed", "device_id", deviceID, "error", err)
		return true
	}
	return n > 0
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
	scanAttrs := marshalScanAttributes(buildScanAttributes(rep))
	now := time.Now().UTC()
	res, err := rn.dbConn.ExecContext(ctx, `
		INSERT INTO devices (name, type, brand, ip_address, status, scan_source, description, location,
		                     open_ports, detected_services, prometheus_url, node_exporter_url,
		                     scan_attributes,
		                     tags, last_scan_rtt_ms, last_scanned_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'online', 'scanner_v2', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, devType, brand, rep.IP, descr, location, ports, services, promURL, neURL, scanAttrs, tags, rep.RTTMs, now, now, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// buildExistingUpdate returns an UPDATE statement that fills only empty/
// "unknown" fields on the existing device, then always refreshes scan metadata.
// buildExistingUpdate returns the static UPDATE statement for an existing
// device. The positional args are assembled separately in existingUpdateArgs;
// the parameters here are kept for signature symmetry/readability but unused
// in the (static) SQL body.
func buildExistingUpdate(_, _, _, _ string, _ scannerv2.HostReport) string {
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
		    scan_attributes = ?,
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
	scanAttrs := marshalScanAttributes(buildScanAttributes(rep))
	now := time.Now().UTC()
	return []any{
		rep.IP, inferredType, inferredType,
		brand, brand,
		descr, descr,
		location, location,
		ports, services,
		promURL, promURL,
		neURL, neURL,
		scanAttrs,
		rep.RTTMs, now, now, id,
	}
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

// heuristicDeviceType is the last-resort type inference run in the device
// bridge when no ServiceHandler set inferred_type. It uses signals that are
// host-level rather than service-level:
//   - hostname (rDNS/mDNS/NetBIOS/SNMP sysName) — single-board hosts often
//     name themselves "rpi4b-4g", "nanopineo2", "bananapi...".
//   - MAC-OUI vendor (inferred_brand) — Espressif/Tuya/Realtek → IoT chips;
//     Raspberry Pi Trading → embedded; Proxmox/server vendors → server.
//   - open-port shape — 22+9100 (ssh+exporter) without web ⇒ server-class host.
//
// Returns "" when no hint matches (caller falls back to "other").
func heuristicDeviceType(rep scannerv2.HostReport) string {
	host := strings.ToLower(rep.Device.Fields["node_hostname"])
	if host == "" {
		host = strings.ToLower(rep.Device.Fields["sys_name"])
	}
	brand := strings.ToLower(rep.Device.Fields["inferred_brand"])
	osType := strings.ToLower(rep.Device.Fields["os_type"])
	hint := host + " " + brand + " " + osType

	switch {
	// Single-board / embedded Linux (Raspberry Pi, NanoPi, BananaPi, OrangePi).
	case containsAny(hint, "rasp", "rpi", "nanopi", "bananapi", "orangepi",
		"rockpi", "radxa", "pine64"):
		return "embedded"
	// IoT chips / smart-home vendors (Espressif = ESP32, Tuya, Xiaomi gateways).
	case containsAny(hint, "espressif", "tuya", "lumi-gateway", "xiaomi",
		"shelly", "sonoff", "tasmota", "gledopto", "ikea"):
		return "iot"
	// Cameras by hostname/brand/model keyword. Covers Hikvision (DS-/Z4S-/IPC-),
	// Dahua, and generic "cam"/"ipc"/"dvr"/"nvr" naming. Many cameras expose a
	// hostname like "Z4S-2PSE" or "IPC-123" via rDNS even when SNMP/ONVIF are
	// blocked cross-subnet.
	case containsAny(host, "ipc", "-cam", "cam-", "camera", "hik", "hikvision",
		"dahua", "dvr", "nvr", "z4s", "ds-2", "ipcam") ||
		containsAny(brand, "hikvision", "dahua", "axis", "reolink", "foscam", "vivotek"):
		return "camera"
	// NAS appliances by hostname/brand. Synology uses "DS-"/"DiskStation", QNAP
	// "TS-", plus the OUI vendor names.
	case containsAny(host, "nas", "synology", "diskstation", "ds-", "qnap", "ts-",
		"teramaster", "readynas", "asustor") ||
		containsAny(brand, "synology", "qnap", "asustor"):
		return "nas"
	// Printers by hostname/brand.
	case containsAny(host, "printer", "hp-", "canon-", "epson-", "brother-",
		"ricoh-", "xerox-") ||
		containsAny(brand, "epson", "canon", "brother", "ricoh"):
		return "printer"
	// Routers / APs by hostname or vendor. Covers the Softether/FriendlyARM
	// NanoPi-R2S/R4S/R6S/R68S family, OpenWrt, RouterOS/Mikrotik, and common
	// consumer router hostnames (miwifi, asus, tplink, huawei). These names
	// show up in rDNS even cross-subnet, so this catches a lot of gateways.
	case containsAny(host, "router", "gateway", "openwrt", "padavan", "asuswrt",
		"routeros", "mikrotik", "r2s", "r4s", "r6s", "r68s", "nanopi-r",
		"miwifi", "xiaomi-router", "tplink", "tp-link", "ap-", "-ap", "ac68",
		"ac88", "ax1800", "ax3000", "ax6000", "k2p", "unifi", "edgeos") ||
		containsAny(brand, "mikrotik", "ubiquiti", "tp-link", "tplink"):
		return "router"
	// Hostname explicitly says server/iot/proxmox.
	case strings.Contains(host, "server") || strings.Contains(host, "proxmox"):
		return "server"
	case strings.Contains(host, "iot"):
		return "iot"
	// NAS vendors by MAC OUI without other signal.
	case containsAny(brand, "synology", "qnap"):
		return "nas"
	// OS indicates a general-purpose host.
	case strings.Contains(osType, "windows"):
		return "pc"
	case strings.Contains(osType, "linux") || strings.Contains(osType, "freebsd"):
		return "server"
	}

	// Port-shape fallback when no hostname/brand/os signal matched. This is the
	// common case cross-subnet (ARP/mDNS/SSDP all fail, leaving only ICMP + rDNS
	// + whatever TCP ports survived the scan). We infer from the port set:
	//   - RTSP (554/8554) without a clearer signal  ⇒ camera
	//   - raw 9100 (JetDirect/IPP)                  ⇒ printer
	//   - ssh + node_exporter/prometheus            ⇒ monitored server
	//   - ssh alone (22)                            ⇒ server-class host
	// These are deliberately conservative — a single ambiguous web port (80/443)
	// is NOT enough to guess, since it's on almost everything.
	svcSet := make(map[string]bool, len(rep.Services))
	for _, s := range rep.Services {
		svcSet[s.Service] = true
	}
	switch {
	case svcSet["rtsp"] || svcSet["onvif"] || svcSet["camera"]:
		return "camera"
	case svcSet["ssh"] && (svcSet["node_exporter"] || svcSet["prometheus"]):
		return "server"
	}
	// Final port-number fallback (services may not have been classified even
	// when the port was seen open, e.g. banner timed out cross-subnet).
	hasPort := func(ports ...int) bool {
		for _, s := range rep.Services {
			for _, p := range ports {
				if s.Port == p {
					return true
				}
			}
		}
		return false
	}
	switch {
	case hasPort(554, 8554, 3702):
		return "camera"
	case hasPort(9100):
		return "printer"
	case hasPort(22) && !hasPort(80, 443):
		// SSH with no web — likely a server/appliance shell.
		return "server"
	}
	return ""
}

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// keep slog referenced for the warn logs above when this file is the only user
var _ = slog.Default
