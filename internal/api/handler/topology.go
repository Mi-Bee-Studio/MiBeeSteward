package handler

import (
	"net/http"
	"strconv"

	"mibee-steward/internal/db"
)

// TopologyHandler serves the network-level topology graph: device nodes + L2
// neighbor edges. Used by the /topology page.
type TopologyHandler struct {
	queries *db.Queries
}

// NewTopologyHandler constructs the handler.
func NewTopologyHandler(queries *db.Queries) *TopologyHandler {
	return &TopologyHandler{queries: queries}
}

// topoNode is one device in the graph. InferredType/Brand come from scan_*
// generated columns (the engine's identification), falling back to the
// hand-set type column.
type topoNode struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	IPAddress    string `json:"ip_address"`
	MACAddress   string `json:"mac_address"`
	Type         string `json:"type"`          // hand-set or 'other'
	Status       string `json:"status"`        // online/offline/unknown
	InferredType string `json:"inferred_type"` // from scan_vendor/scan_os — richer than type
	Brand        string `json:"brand"`
}

// topoEdge is one L2 adjacency: a device sees a neighbor (by MAC) via a
// discovery protocol. ToDeviceID is non-nil when the neighbor MAC matches a
// scanned device (solid edge); nil = unidentified neighbor (dashed edge).
type topoEdge struct {
	FromDeviceID int64   `json:"from_device_id"`
	ToDeviceID   *int64  `json:"to_device_id"`
	ToMAC        string  `json:"to_mac"`
	Protocol     string  `json:"protocol"` // LLDP / CDP / Bridge-MIB / ARP
	LocalPort    *string `json:"local_port"`
}

// Graph handles GET /api/v1/topology?network_id=X — the full node + edge set
// for one network (or all networks when network_id is omitted/0). Any logged-in
// user may read.
func (h *TopologyHandler) Graph(w http.ResponseWriter, r *http.Request) {
	networkID, _ := strconv.ParseInt(r.URL.Query().Get("network_id"), 10, 64)

	devRows, err := h.queries.ListTopologyDevices(r.Context(), db.ListTopologyDevicesParams{
		Column1:   networkID, // ? <= 0 → all networks
		NetworkID: &networkID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query topology nodes")
		return
	}
	nodes := make([]topoNode, 0, len(devRows))
	for _, d := range devRows {
		nodes = append(nodes, topoNode{
			ID:           d.ID,
			Name:         d.Name,
			IPAddress:    d.IpAddress,
			MACAddress:   d.MacAddress,
			Type:         d.Type,
			Status:       d.Status,
			InferredType: ptrString(d.ScanVendor),
			Brand:        ptrString(d.ScanVendor),
		})
	}

	edgeRows, err := h.queries.ListTopologyEdges(r.Context(), db.ListTopologyEdgesParams{
		Column1:   networkID, // ? <= 0 → all networks
		NetworkID: &networkID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query topology edges")
		return
	}
	edges := make([]topoEdge, 0, len(edgeRows))
	for _, e := range edgeRows {
		edges = append(edges, topoEdge{
			FromDeviceID: e.DeviceID,
			ToDeviceID:   e.ToDeviceID,
			ToMAC:        e.NeighborMac,
			Protocol:     e.Protocol,
			LocalPort:    e.LocalPort,
		})
	}

	Success(w, map[string]any{
		"nodes": nodes,
		"edges": edges,
	})
}

// ptrString dereferences a *string, returning "" for nil.
func ptrString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
