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

// SNMPProbe queries the SNMPv2c sysObject group on UDP/161. On success it emits
// one "snmp" Evidence whose RawData carries the varbind map. Classifiers turn
// sysDescr/sysServices into device type and brand.
//
// Name: "active:snmp".
type SNMPProbe struct{}

// NewSNMPProbe returns an SNMP probe.
func NewSNMPProbe() *SNMPProbe { return &SNMPProbe{} }

func (p *SNMPProbe) Name() string { return "active:snmp" }

// Probe queries ip:161. hint.Community overrides the default "public";
// hint.Timeout bounds the SNMP Get.
func (p *SNMPProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	community := hint.Community
	if community == "" {
		community = "public"
	}
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
	}
	if err := snmp.Connect(); err != nil {
		return nil, nil // host may simply not run SNMP — no evidence
	}
	defer snmp.Conn.Close()

	result, err := snmp.Get(snmpOIDs)
	if err != nil {
		return nil, nil
	}
	raw := parseSNMPVarbinds(result.Variables)
	if len(raw) == 0 {
		return nil, nil
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
