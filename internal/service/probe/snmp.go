package probe

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMPProber performs SNMP v2c basic connectivity checks.
type SNMPProber struct {
	Community string
	OID       string
}

// Probe connects to the target via SNMP v2c and performs a Get request on the configured OID.
func (p *SNMPProber) Probe(_ context.Context, target string, timeout time.Duration) (*Result, error) {
	community := p.Community
	if community == "" {
		community = "public"
	}

	oid := p.OID
	if oid == "" {
		oid = "1.3.6.1.2.1.1.3.0"
	}

	snmp := &gosnmp.GoSNMP{
		Target:    target,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
	}

	start := time.Now()
	err := snmp.Connect()
	if err != nil {
		elapsed := time.Since(start)
		slog.Error("probe failed", "method", "snmp", "target", target, "error", err)
		return &Result{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: fmt.Sprintf("SNMP connect failed: %v", err),
		}, nil
	}
	defer snmp.Conn.Close()

	_, err = snmp.Get([]string{oid})
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "snmp", "target", target, "error", err)
		return &Result{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: fmt.Sprintf("SNMP get failed: %v", err),
		}, nil
	}

	slog.Debug("probe executed", "method", "snmp", "target", target, "success", true, "latency", elapsed)
	return &Result{
		Success: true,
		Latency: elapsed,
	}, nil
}
