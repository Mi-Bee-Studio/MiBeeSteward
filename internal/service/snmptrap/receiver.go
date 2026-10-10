// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package snmptrap implements the SNMP trap receiver (#509): the one channel
// where devices speak unprompted. linkDown/linkUp are topology-change
// signals, coldStart is an onboarding report, authenticationFailure is a
// security whisper — all landing as `snmp_trap` evidence on the source
// device instead of waiting for the next scan round.
//
// Scope of the minimal loop: v2c (community-validated by the listener) and
// v1 traps, listen-only (the listener answers Inform ACKs itself, nothing
// else is ever sent). v3 traps (USM, credential-name references against the
// vault) are the designed follow-up — the config surface deliberately has
// no v3 keys yet so no one can enable a stub.
package snmptrap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// Config controls the receiver. Enabled defaults to false: an extra
// listening socket is an operational surface (UDP 162 firewalling,
// CAP_NET_BIND_SERVICE below 1024), so it is strictly opt-in.
type Config struct {
	Enabled bool
	// Bind is the UDP address to listen on (":162" to match the SNMP
	// standard). Ports below 1024 need root or
	// AmbientCapabilities=CAP_NET_BIND_SERVICE under systemd.
	Bind string
	// Community is the v2c community traps must carry ("public" default).
	Community string
}

// EvidenceStore is the persistence seam (satisfied by the scannerv2
// repository; RecordEvidence is gated by scanner.persist_raw_evidence).
type EvidenceStore interface {
	RecordEvidence(ctx context.Context, evs []scannerv2.Evidence) error
}

// Receiver listens for SNMP traps and records them as passive evidence.
type Receiver struct {
	cfg    Config
	store  EvidenceStore
	logger *slog.Logger
	// OnSighting, when set, fires once per accepted (non-throttled) trap —
	// routes.go bridges coldStart/linkUp into the discovery channel.
	OnSighting func(ip, trap string)

	listener *gosnmp.TrapListener
	throttle *throttle
	// ready is closed once the socket is bound (gosnmp's own signal is a
	// one-shot buffered channel — exactly one consumer may read it, so this
	// side is the only reader and everyone else waits on the close broadcast).
	ready chan struct{}
	once  sync.Once
}

// New constructs a receiver. Never starts listening (Start does).
func New(cfg Config, store EvidenceStore, logger *slog.Logger) *Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Bind == "" {
		cfg.Bind = ":162"
	}
	if cfg.Community == "" {
		cfg.Community = "public"
	}
	return &Receiver{
		cfg:      cfg,
		store:    store,
		logger:   logger,
		throttle: newThrottle(10 * time.Second),
		ready:    make(chan struct{}),
	}
}

// Start begins listening; it returns an error immediately when the socket
// cannot open (port in use, missing CAP_NET_BIND_SERVICE) so the caller can
// log it once — a disabled trap channel never blocks the server.
func (r *Receiver) Start() error {
	l := gosnmp.NewTrapListener()
	l.OnNewTrap = r.onTrap
	l.Params = &gosnmp.GoSNMP{
		Version:   gosnmp.Version2c, // also accepts v1 packets
		Community: r.cfg.Community,
	}
	r.listener = l
	errCh := make(chan error, 1)
	go func() {
		errCh <- l.Listen(r.cfg.Bind)
	}()
	select {
	case err := <-errCh:
		return fmt.Errorf("snmp trap listener: %w", err)
	case <-l.Listening():
		close(r.ready)
		r.logger.Info("snmp trap receiver listening", "bind", r.cfg.Bind, "community", "***")
		return nil
	}
}

// Listening reports readiness: the channel closes when the socket is bound
// (tests synchronize on it; production logs readiness in Start).
func (r *Receiver) Listening() <-chan struct{} { return r.ready }

// Stop closes the listener socket.
func (r *Receiver) Stop() {
	r.once.Do(func() {
		if r.listener != nil {
			r.listener.Close()
		}
	})
}

func (r *Receiver) onTrap(pkt *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	ip := addr.IP.String()
	ev := evidenceFromTrap(pkt, addr)
	if !r.throttle.allow(trapKey(ip, ev.RawData["trap"])) {
		return
	}
	if r.store != nil {
		if err := r.store.RecordEvidence(context.Background(), []scannerv2.Evidence{ev}); err != nil {
			r.logger.Warn("snmp trap: persist evidence failed", "ip", ip, "error", err)
		}
	}
	if r.OnSighting != nil {
		r.OnSighting(ip, ev.RawData["trap"])
	}
}

// standardTrapOIDs maps the RFC 1907 / SNMPv2-MIB standard trap OIDs to
// their names (also the v1 generic-trap numbering, which matches by design).
var standardTrapOIDs = map[string]string{
	"1.3.6.1.6.3.1.1.5.1": "coldStart",
	"1.3.6.1.6.3.1.1.5.2": "warmStart",
	"1.3.6.1.6.3.1.1.5.3": "linkDown",
	"1.3.6.1.6.3.1.1.5.4": "linkUp",
	"1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}

// v1GenericTraps names the v1 generic-trap numbers (0-5).
var v1GenericTraps = [6]string{
	"coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss",
}

// ifOperStatusNames maps IF-MIB ifOperStatus values.
var ifOperStatusNames = map[int]string{
	1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown",
}

// snmpTrapOID is the varbind that names a v2c trap.
const snmpTrapOID = ".1.3.6.1.6.3.1.1.4.1.0"

// ifIndexPrefix / ifOperStatusPrefix identify the interface varbinds of
// linkDown/linkUp traps (IF-MIB).
const (
	ifIndexPrefix      = ".1.3.6.1.2.1.2.2.1.1."
	ifOperStatusPrefix = ".1.3.6.1.2.1.2.2.1.8."
)

// evidenceFromTrap folds one trap PDU into passive evidence. String building
// happens here only; the handler stays cheap. gosnmp delivers v2c trap OIDs
// as raw OctetString bytes (the BER OID payload), so both the dotted-string
// and the raw-byte spellings of snmpTrapOID are handled.
func evidenceFromTrap(pkt *gosnmp.SnmpPacket, addr *net.UDPAddr) scannerv2.Evidence {
	rd := map[string]string{}
	trap := "unknown"

	if pkt.Version == gosnmp.Version1 {
		rd["snmp_version"] = "1"
		if pkt.GenericTrap >= 0 && pkt.GenericTrap < len(v1GenericTraps) {
			trap = v1GenericTraps[pkt.GenericTrap]
		} else {
			trap = "enterpriseSpecific"
		}
		if pkt.Enterprise != "" {
			rd["enterprise"] = strings.TrimPrefix(pkt.Enterprise, ".")
		}
		if trap == "enterpriseSpecific" {
			rd["specific"] = strconv.Itoa(pkt.SpecificTrap)
		}
		if pkt.AgentAddress != "" {
			rd["agent_address"] = pkt.AgentAddress
		}
	} else {
		rd["snmp_version"] = "2c"
	}

	var ifIndex string
	for _, v := range pkt.Variables {
		name := strings.TrimPrefix(v.Name, ".")
		switch {
		case name == "1.3.6.1.6.3.1.1.4.1.0" || v.Name == snmpTrapOID:
			oid := oidFromPDU(v)
			if n, ok := standardTrapOIDs[oid]; ok {
				trap = n
			} else if oid != "" {
				trap = "enterprise:" + oid
			}
		case strings.HasPrefix(name, strings.TrimPrefix(ifIndexPrefix, ".")):
			ifIndex = fmt.Sprintf("%v", v.Value)
		case strings.HasPrefix(name, strings.TrimPrefix(ifOperStatusPrefix, ".")):
			if n, ok := ifOperStatusNames[pduInt(v)]; ok {
				rd["if_oper_status"] = n
			} else {
				rd["if_oper_status"] = strconv.Itoa(pduInt(v))
			}
		}
	}
	if ifIndex != "" {
		rd["if_index"] = ifIndex
	}
	rd["trap"] = trap

	return scannerv2.Evidence{
		Source:     "passive:snmp-trap",
		Kind:       "snmp_trap",
		IP:         addr.IP.String(),
		Port:       addr.Port,
		Protocol:   "udp",
		RawData:    rd,
		Confidence: 0.9, // the device itself spoke, unprompted
		ObservedAt: time.Now(),
	}
}

// oidFromPDU renders a trap-OID varbind's value: v2c delivers the BER OID as
// raw bytes (first subid compressed 0x2b = 1.3), gosnmp tests may hand us a
// dotted string.
func oidFromPDU(v gosnmp.SnmpPDU) string {
	switch val := v.Value.(type) {
	case string:
		return strings.TrimPrefix(val, ".")
	case []byte:
		return decodeOIDBytes(val)
	default:
		return ""
	}
}

// decodeOIDBytes renders BER OID payload bytes (0x2b 6 1 ... → 1.3.6.1...).
func decodeOIDBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	first := int(b[0]) / 40
	second := int(b[0]) % 40
	fmt.Fprintf(&sb, "%d.%d", first, second)
	for _, x := range b[1:] {
		fmt.Fprintf(&sb, ".%d", x)
	}
	return sb.String()
}

func pduInt(v gosnmp.SnmpPDU) int {
	switch val := v.Value.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case uint64:
		return int(val)
	case uint32:
		return int(val)
	default:
		return -1
	}
}

// throttle collapses flapping storms: one evidence row per (source, trap)
// per window. A link bouncing every second still leaves one row per 10s.
type throttle struct {
	window time.Duration
	mu     sync.Mutex
	seen   map[string]time.Time
}

func newThrottle(window time.Duration) *throttle {
	return &throttle{window: window, seen: make(map[string]time.Time)}
}

func (t *throttle) allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if ts, ok := t.seen[key]; ok && now.Sub(ts) < t.window {
		return false
	}
	// opportunistic sweep keeps the map bounded without a background timer
	if len(t.seen) > 1024 {
		for k, ts := range t.seen {
			if now.Sub(ts) >= t.window {
				delete(t.seen, k)
			}
		}
	}
	t.seen[key] = now
	return true
}

func trapKey(ip, trap string) string { return ip + "|" + trap }
