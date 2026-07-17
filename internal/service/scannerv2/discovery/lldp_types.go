// Shared types for the LLDP frame source, used by both the stub (default) and
// real (WITH_LLDP) builds. No build tag — always compiled.

package discovery

// lldpEdge is one neighbor adjacency extracted from a captured LLDPDU. The
// fields mirror scannerv2.NeighborSpec but stay local to this package to avoid
// an import cycle (discovery → scannerv2 would cycle). The real listener
// (lldp_frame_real.go, WITH_LLDP) builds these; the caller's neighborSink
// consumes them.
type lldpEdge struct {
	NeighborMAC string // canonical aa:bb:cc:dd:ee:ff (subtype-4 chassis id, or the Ethernet src MAC)
	Protocol    string // always "LLDP"
	LocalMAC    string // the surveyed interface's MAC (the listener host)
	LocalPort   string // the interface name the LLDPDU was received on
	RemotePort  string // from the Port ID TLV
}
