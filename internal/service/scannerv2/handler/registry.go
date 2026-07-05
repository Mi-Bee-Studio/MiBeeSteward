package handler

import "mibee-steward/internal/service/scannerv2"

// DefaultHandlers returns the standard set of ServiceHandlers, ready to
// register into a scannerv2.Registry. Each handler maps 1:1 to a service name
// emitted by a classifier in package classify.
func DefaultHandlers() []scannerv2.ServiceHandler {
	return []scannerv2.ServiceHandler{
		SSHHandler{},
		HTTPHandler{},
		PrometheusHandler{},
		NodeExporterHandler{},
		RTSPHandler{},
		ONVIFHandler{},
		SNMPHandler{},
		CameraHandler{},
	}
}
