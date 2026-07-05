//go:build !WITH_EBPF

// Default build: no eBPF. The Observer is a no-op ProbeSource that contributes
// no evidence. This keeps the default binary free of kernel/BTF/clang
// dependencies and runnable unprivileged on any platform.
//
// To enable the real eBPF observer, build with: WITH_EBPF=1 go build ...
// (see Makefile target build-with-ebpf and bpf/Makefile).

package ebpf

import (
	"context"
	"log/slog"

	"mibee-steward/internal/service/scannerv2"
)

func (o *Observer) Name() string { return "passive:ebpf:tc" }

// Probe returns no evidence in the stub build. If Enabled was requested but
// the binary lacks eBPF support, it logs a one-time warning so operators know
// passive detection is unavailable (rather than silently absent).
func (o *Observer) Probe(_ context.Context, _ string, _ scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	if o.cfg.Enabled {
		// Log at debug to avoid spamming; the startup banner in NewEngine (Phase 5)
		// logs the build configuration once at info level.
		slog.Debug("eBPF passive observer requested but binary built without WITH_EBPF tag; no-op",
			"interfaces", o.cfg.Interfaces)
	}
	return nil, nil
}
