package probe

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestParseSNMPUptime(t *testing.T) {
	cases := []struct {
		raw     string
		wantSec int64
	}{
		{"123456789", 1234567}, // 123456789 hundredths → 1234567 seconds
		{"100", 1},
		{"99", 0}, // <1 second → rounds to 0
		{"0", 0},
		{"", 0},
		{"-1", 0}, // negative guards against underflow
		{"not-a-number", 0},
	}
	for _, c := range cases {
		if got := parseSNMPUptime(c.raw); got != c.wantSec {
			t.Errorf("parseSNMPUptime(%q) = %d, want %d", c.raw, got, c.wantSec)
		}
	}
}

func TestSNMPVersionLabel(t *testing.T) {
	cases := []struct {
		v    gosnmp.SnmpVersion
		want string
	}{
		{gosnmp.Version1, "1"},
		{gosnmp.Version2c, "2c"},
		{gosnmp.Version3, "3"},
	}
	for _, c := range cases {
		if got := snmpVersionLabel(c.v); got != c.want {
			t.Errorf("snmpVersionLabel(%v) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestParseSNMPVarbinds(t *testing.T) {
	vars := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.1.0", Value: "Linux devhost 6.19.0"},
		{Name: ".1.3.6.1.2.1.1.5.0", Value: "devhost"},
		{Name: ".1.3.6.1.2.1.1.3.0", Value: int64(1234567)},
		{Name: ".unknown.oid", Value: "ignored"}, // not in key map
	}
	raw := parseSNMPVarbinds(vars)
	if raw["sys_descr"] != "Linux devhost 6.19.0" {
		t.Errorf("sys_descr not parsed: %v", raw)
	}
	if raw["sys_name"] != "devhost" {
		t.Errorf("sys_name not parsed: %v", raw)
	}
	if raw["sys_up_time"] != "1234567" {
		t.Errorf("sys_up_time not converted to string: %v", raw)
	}
	if _, present := raw["unknown"]; present {
		t.Error("unknown OID should not appear in raw map")
	}
}
