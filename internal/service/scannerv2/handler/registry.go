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
		// Services that classifiers identify but previously had no handler, so
		// hosts whose only service was one of these dropped to type "other".
		// Each marks the host as a server (see handler/services.go).
		MySQLHandler{}, PostgreSQLHandler{}, RedisHandler{}, MongoDBHandler{},
		MSSQLHandler{}, MemcachedHandler{},
		SMTPHandler{}, POP3Handler{}, IMAPHandler{},
		VNCHandler{}, RDPHandler{},
		LDAPHandler{}, SMBHandler{},
		// TLS-wrapped service handlers — each performs the full certificate
		// chain grab (leaf + issuers) in Collect() and persists via the
		// orchestrator's RecordTLSCerts path. https covers any TLS port the
		// TLSClassifier flags; the rest are the well-known TLS-wrapped service
		// ports asserted by MiscClassifier.
		NewHTTPSHandler(),
		NewLDAPSHandler(),
		NewSMTPSHandler(),
		NewIMAPSHandler(),
		NewPOP3SHandler(),
		NewFTPSHandler(),
		NewIRCSSHandler(),
		NewTelnetSSHandler(),
	}
}
