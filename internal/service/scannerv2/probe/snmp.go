package probe

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// snmpOIDs are the scalar OIDs fetched in a single SNMPv2c Get. They cover the
// sysObject group needed for type/brand inference plus ifNumber.
var snmpOIDs = []string{
	"1.3.6.1.2.1.1.1.0", // sysDescr
	"1.3.6.1.2.1.1.2.0", // sysObjectID
	"1.3.6.1.2.1.1.3.0", // sysUpTime
	"1.3.6.1.2.1.1.4.0", // sysContact
	"1.3.6.1.2.1.1.5.0", // sysName
	"1.3.6.1.2.1.1.6.0", // sysLocation
	"1.3.6.1.2.1.1.7.0", // sysServices
	"1.3.6.1.2.1.2.1.0", // ifNumber
}

// snmpOIDKeys maps each OID (with leading dot, as gosnmp returns pdu.Name) to
// the RawData key used in the emitted Evidence.
var snmpOIDKeys = map[string]string{
	".1.3.6.1.2.1.1.1.0": "sys_descr",
	".1.3.6.1.2.1.1.2.0": "sys_object_id",
	".1.3.6.1.2.1.1.3.0": "sys_up_time",
	".1.3.6.1.2.1.1.4.0": "sys_contact",
	".1.3.6.1.2.1.1.5.0": "sys_name",
	".1.3.6.1.2.1.1.6.0": "sys_location",
	".1.3.6.1.2.1.1.7.0": "sys_services",
	".1.3.6.1.2.1.2.1.0": "if_number",
}

// SNMPProbe queries the SNMP sysObject group on UDP/161, trying SNMPv2c first
// then SNMPv1 as a fallback. Many embedded devices (older cameras, printers,
// consumer gear) speak only v1; the v2c Get returns a version-mismatch error
// on them. On success it emits one "snmp" Evidence whose RawData carries the
// varbind map plus a derived uptime_seconds. Classifiers turn
// sysDescr/sysServices into device type and brand.
//
// The probe retries up to 2 times per version with a short backoff: SNMP over
// UDP is lossy on busy networks, and a single dropped response should not
// produce a false "no SNMP" verdict.
//
// Name: "active:snmp".
type SNMPProbe struct{}

// NewSNMPProbe returns an SNMP probe.
func NewSNMPProbe() *SNMPProbe { return &SNMPProbe{} }

func (p *SNMPProbe) Name() string { return "active:snmp" }

// Probe queries ip:161. hint.Community overrides the default "public";
// hint.Timeout bounds each SNMP Get attempt.
func (p *SNMPProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	community := hint.Community
	if community == "" {
		community = "public"
	}
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// Try v2c first, then v1. Many embedded devices answer only v1.
	for _, version := range []gosnmp.SnmpVersion{gosnmp.Version2c, gosnmp.Version1} {
		raw, usedVersion := p.trySNMP(ctx, ip, community, version, timeout)
		if raw != nil {
			raw["snmp_version"] = snmpVersionLabel(usedVersion)
			if uptimeRaw := raw["sys_up_time"]; uptimeRaw != "" {
				if sec := parseSNMPUptime(uptimeRaw); sec > 0 {
					raw["uptime_seconds"] = strconv.FormatInt(sec, 10)
				}
			}
			return []scannerv2.Evidence{{
				Source:     "active:snmp",
				Kind:       "snmp",
				IP:         ip,
				Port:       161,
				Protocol:   "udp",
				RawData:    raw,
				Confidence: 0.95,
				ObservedAt: time.Now(),
			}}, nil
		}
		// Bail out early if the host is unreachable at L3 (no point retrying v1
		// if the UDP packets got ICMP-port-unreachable / timed out).
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}
	}
	return nil, nil
}

// trySNMP runs up to 2 attempts at the given SNMP version. Returns the parsed
// varbinds (non-nil) on success, or (nil, version) on failure.
func (p *SNMPProbe) trySNMP(ctx context.Context, ip, community string, version gosnmp.SnmpVersion, timeout time.Duration) (map[string]string, gosnmp.SnmpVersion) {
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt < 2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, version
		default:
		}
		raw, ok := snmpGetOnce(ip, community, version, timeout)
		if ok {
			return raw, version
		}
		// Brief backoff before retrying this version. Bounded by ctx deadline.
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, version
		case <-timer.C:
		}
		backoff *= 2
	}
	return nil, version
}

// snmpGetOnce opens a connection, runs a single Get, and parses varbinds.
func snmpGetOnce(ip, community string, version gosnmp.SnmpVersion, timeout time.Duration) (map[string]string, bool) {
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   version,
		Timeout:   timeout,
		Retries:   0, // we do our own retry loop above
	}
	if err := snmp.Connect(); err != nil {
		return nil, false // host may simply not run SNMP — no evidence
	}
	defer snmp.Conn.Close()

	result, err := snmp.Get(snmpOIDs)
	if err != nil {
		return nil, false
	}
	raw := parseSNMPVarbinds(result.Variables)
	if len(raw) == 0 {
		return nil, false
	}
	return raw, true
}

// snmpVersionLabel returns a human-friendly SNMP version label.
func snmpVersionLabel(v gosnmp.SnmpVersion) string {
	switch v {
	case gosnmp.Version1:
		return "1"
	case gosnmp.Version2c:
		return "2c"
	case gosnmp.Version3:
		return "3"
	default:
		return "unknown"
	}
}

// parseSNMPUptime converts a sysUpTime value (TimeTicks: hundredths of a second
// since agent boot) into whole seconds. The value can arrive as a numeric
// string from gosnmp's int conversion (handled by snmpValString) — divide by
// 100 and round down.
func parseSNMPUptime(raw string) int64 {
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n / 100
}

// parseSNMPVarbinds converts gosnmp PDUs into the RawData string map keyed by
// human names (sys_descr, sys_object_id, ...).
func parseSNMPVarbinds(vars []gosnmp.SnmpPDU) map[string]string {
	out := make(map[string]string)
	for _, pdu := range vars {
		key, ok := snmpOIDKeys[pdu.Name]
		if !ok {
			continue
		}
		val := snmpValString(pdu.Value)
		if val == "" {
			continue
		}
		out[key] = val
	}
	return out
}

func snmpValString(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}
