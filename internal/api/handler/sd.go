package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"mibee-steward/internal/db"
	"mibee-steward/internal/repository"
)

// SDTarget represents a single Prometheus HTTP Service Discovery target.
type SDTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// SDHandler serves Prometheus HTTP Service Discovery endpoints.
type SDHandler struct {
	queries    *db.Queries
	systemRepo *repository.DeviceSystemRepository
}

// NewSDHandler creates a new SDHandler.
func NewSDHandler(dbtx db.DBTX, systemRepo *repository.DeviceSystemRepository) *SDHandler {
	return &SDHandler{queries: db.New(dbtx), systemRepo: systemRepo}
}

// ServeHTTP handles GET /sd — returns Prometheus HTTP SD JSON.
func (h *SDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	statusFilter := r.URL.Query().Get("status")

	// List all devices (no filter on type, large limit to get all).
	devices, err := h.queries.ListDevices(ctx, db.ListDevicesParams{
		Column1: "",
		Status:  statusFilter,
		Column3: "",
		Type:    "",
		Limit:   10000,
		Offset:  0,
	})
	if err != nil {
		http.Error(w, "failed to list devices", http.StatusInternalServerError)
		return
	}

	targets := make([]SDTarget, 0)

	for _, d := range devices {
		// Only include devices with heartbeat configs.
		configs, err := h.queries.ListHeartbeatConfigsByDevice(ctx, d.ID)
		if err != nil || len(configs) == 0 {
			continue
		}

		// Build one SD target per heartbeat config for this device.
		for _, cfg := range configs {
			// Build target address: use device IP + target port/path from config.
			// For HTTP/TCP methods, the target field typically contains the full address.
			// For ICMP/SNMP, we use the IP directly.
			addr := buildSDAddress(d.IpAddress, cfg.Target, cfg.Method)
			if addr == "" {
				continue
			}

			t := SDTarget{
				Targets: []string{addr},
				Labels: map[string]string{
					"device_name": d.Name,
					"device_type": d.Type,
					"location":    d.Location,
				},
			}
			targets = append(targets, t)
		}
	}

	// Also include device systems with metrics enabled
	if h.systemRepo != nil {
		systemRows, err := h.systemRepo.ListForSD(ctx)
		if err != nil {
			slog.Warn("failed to list device systems for SD", "error", err)
		} else {
			for _, sys := range systemRows {
				if sys.MetricsUrl == "" {
					continue
				}
				t := SDTarget{
					Targets: []string{sys.MetricsUrl},
					Labels: map[string]string{
						"device_name": sys.DeviceName,
						"system_name": sys.Name,
						"category":    sys.Category,
						"device_type": sys.DeviceType,
						"location":    sys.DeviceLocation,
					},
				}
				targets = append(targets, t)
			}
		}
	}
	// Include scanner-discovered devices with prometheus_detected=1.
	scannerTargets := BuildScannerTargets(ctx, h.queries)
	targets = append(targets, scannerTargets...)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(targets); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// buildSDAddress constructs the target address for Prometheus SD.
func buildSDAddress(ip, target, method string) string {
	// If target already looks like host:port, use it directly.
	if target != "" && (method == "http" || method == "tcp") {
		return target
	}
	// For ICMP/SNMP or empty target, fall back to the device IP.
	if ip != "" {
		return ip
	}
	return target
}

// MergeLabels combines three label layers with priority: perDevice > dynamic > static.
func MergeLabels(static, dynamic, perDevice map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range static {
		result[k] = v
	}
	for k, v := range dynamic {
		result[k] = v
	}
	for k, v := range perDevice {
		result[k] = v
	}
	return result
}

// ParseJSONLabels parses a JSON string into a map[string]string.
// Returns nil (not an error) for empty or invalid JSON.
func ParseJSONLabels(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}

// ExtractDiscoveredServices parses the services JSON string and returns
// a comma-separated list of service names (e.g., "ssh,http,prometheus").
func ExtractDiscoveredServices(servicesJSON string) string {
	if servicesJSON == "" {
		return ""
	}
	var infos []struct {
		Service string `json:"service"`
	}
	if err := json.Unmarshal([]byte(servicesJSON), &infos); err != nil {
		return ""
	}
	var names []string
	for _, info := range infos {
		if info.Service != "" {
			names = append(names, info.Service)
		}
	}
	return strings.Join(names, ",")
}

// BuildScannerTargets queries scan_results for prometheus_detected=1 devices
// and builds SDTargets with 3-layer merged labels.
func BuildScannerTargets(ctx context.Context, queries *db.Queries) []SDTarget {
	// Get all scan results, filter prometheus_detected=1 in Go
	// (no dedicated sqlc query for this filter). Column5=-1 disables the alive
	// filter (sentinel: ? < 0 ⇒ no clause) — without it the zero-value Alive
	// field would silently restrict to dead hosts only.
	results, err := queries.ListScanResults(ctx, db.ListScanResultsParams{
		Column1: 0, // no task filter
		TaskID:  0,
		Column3: "", // no IP filter
		Ip:      "",
		Column5: -1, // no alive filter
		Alive:   0,
		Limit:   10000,
		Offset:  0,
	})
	if err != nil {
		slog.Warn("failed to list scan results for SD", "error", err)
		return nil
	}

	// Deduplicate by IP, keeping latest result per IP.
	seen := make(map[string]db.ScanResult)
	for _, r := range results {
		if r.PrometheusDetected != 1 {
			continue
		}
		if _, exists := seen[r.Ip]; !exists {
			seen[r.Ip] = r
		}
	}

	targets := make([]SDTarget, 0, len(seen))
	for ip, result := range seen {
		// Determine target address from prometheus_url or fall back to IP.
		addr := result.PrometheusUrl
		if addr == "" {
			// Try to extract port from ports JSON.
			addr = ip
		}

		// Layer 1: static labels from scan_task global_labels.
		var staticLabels map[string]string
		taskName := ""
		task, taskErr := queries.GetScanTask(ctx, result.TaskID)
		if taskErr != nil {
			slog.Warn("failed to get scan task for SD labels", "task_id", result.TaskID, "error", taskErr)
		} else {
			staticLabels = ParseJSONLabels(task.GlobalLabels)
			taskName = task.Name
		}

		// Layer 2: dynamic labels from scan data.
		dynamicLabels := map[string]string{
			"scan_task_name": taskName,
			"__source":       "scanner",
		}
		if result.NodeExporterDetected == 1 {
			dynamicLabels["has_node_exporter"] = "true"
		}
		if svcs := ExtractDiscoveredServices(result.Services); svcs != "" {
			dynamicLabels["discovered_services"] = svcs
		}

		// Layer 3: per-device override labels from devices.prometheus_labels.
		// Device-not-found is OK — the scanner may have discovered unregistered devices.
		var perDeviceLabels map[string]string
		if device, devErr := queries.GetDeviceByIP(ctx, ip); devErr == nil {
			perDeviceLabels = ParseJSONLabels(device.PrometheusLabels)
			// Enrich dynamic with device_type if available.
			if device.Type != "" {
				dynamicLabels["device_type"] = device.Type
			}
			if device.Name != "" {
				dynamicLabels["device_name"] = device.Name
			}
		}

		labels := MergeLabels(staticLabels, dynamicLabels, perDeviceLabels)

		targets = append(targets, SDTarget{
			Targets: []string{addr},
			Labels:  labels,
		})
	}
	return targets
}
