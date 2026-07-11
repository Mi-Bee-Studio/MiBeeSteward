package handler

import (
	"encoding/json"
	"net/http"

	scannerv2discovery "mibee-steward/internal/service/scannerv2/discovery"
)

// DiscoveryStatusHandler returns the passive-discovery service's runtime state
// (active sources, cumulative counters, recent discoveries). The service is
// optional — when discovery is disabled (or the binary predates it), svc is nil
// and the endpoint reports enabled=false rather than 404, so the UI can show a
// consistent "disabled" state.
func DiscoveryStatusHandler(svc *scannerv2discovery.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := scannerv2discovery.StatusResponse{Enabled: false}
		if svc != nil {
			resp = svc.Status()
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			// Non-fatal: the client either gets partial JSON or an empty body.
			http.Error(w, "failed to encode discovery status", http.StatusInternalServerError)
		}
	}
}
