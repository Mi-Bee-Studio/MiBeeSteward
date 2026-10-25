package notification

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertSeverity(t *testing.T) {
	cases := []struct {
		eventType string
		want      string
	}{
		{"device_lost", AlertSeverityError},
		{"device_recovered", AlertSeverityInfo},
		{"device_added", AlertSeverityInfo},
		{"device_changed", AlertSeverityWarning},
		{"speaks_with_new", AlertSeverityWarning},
		{"listen_port_added", AlertSeverityWarning},
		{"device_config_changed", AlertSeverityWarning},
		{"", AlertSeverityInfo},                 // test dispatch / no metadata
		{"something_new", AlertSeverityWarning}, // unmapped → conservative middle tier
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, alertSeverity(tc.eventType), "event_type=%q", tc.eventType)
	}
}

func TestBuildAlertEnvelope_DeviceLost(t *testing.T) {
	meta, _ := json.Marshal(map[string]any{
		"event_type":  "device_lost",
		"device_name": "nas-01",
		"ip_address":  "192.0.2.10",
		"mac_address": "aa:bb:cc:dd:ee:ff",
		"device_type": "nas",
		"rule_name":   "critical-devices",
		"network_id":  3,
		"detected_at": "2026-10-25T08:00:00Z",
	})
	env := buildAlertEnvelope(Payload{
		Subject:  "Device lost: nas-01",
		Body:     "Device: nas-01\nIP: 192.0.2.10",
		Metadata: meta,
	}, "")

	assert.Equal(t, "device_lost", env.Type)
	assert.Equal(t, AlertSeverityError, env.Severity)
	assert.Equal(t, "Device lost: nas-01", env.Title)
	assert.Equal(t, DefaultAlertSource, env.Source) // default source
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", env.SourceRef)
	assert.False(t, env.Resolved)
	assert.Equal(t, "mibee-steward/device_lost/aa:bb:cc:dd:ee:ff", env.DedupKey)
	assert.Equal(t, "2026-10-25T08:00:00Z", env.OccurredAt)
	assert.Equal(t, map[string]string{
		"device_name": "nas-01",
		"ip_address":  "192.0.2.10",
		"mac_address": "aa:bb:cc:dd:ee:ff",
		"device_type": "nas",
		"rule_name":   "critical-devices",
		"network_id":  "3", // numeric metadata stringified
	}, env.Tags)

	// JSON shape: the envelope must carry the alert fields, not the raw
	// Payload shape (no subject/recipient keys).
	raw, err := json.Marshal(env)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Contains(t, decoded, "type")
	assert.Contains(t, decoded, "severity")
	assert.Contains(t, decoded, "dedup_key")
	assert.NotContains(t, decoded, "subject")
	assert.NotContains(t, decoded, "recipient")
}

func TestBuildAlertEnvelope_RecoveredPairsWithFiringDedupKey(t *testing.T) {
	lost := buildAlertEnvelope(payloadWithEvent("device_lost", "aa:bb:cc:dd:ee:ff"), "")
	recovered := buildAlertEnvelope(payloadWithEvent("device_recovered", "aa:bb:cc:dd:ee:ff"), "")

	assert.True(t, recovered.Resolved)
	assert.False(t, lost.Resolved)
	assert.Equal(t, AlertSeverityInfo, recovered.Severity)
	// The recovery carries the SAME dedup key as the firing event so
	// receivers can pair them (Alertmanager groupKey semantics).
	assert.Equal(t, lost.DedupKey, recovered.DedupKey)
}

func TestBuildAlertEnvelope_TestDispatchWithoutMetadata(t *testing.T) {
	env := buildAlertEnvelope(Payload{
		Subject:   "Test Notification",
		Body:      "This is a test notification from MiBee Steward",
		Recipient: "test",
	}, "")

	assert.Equal(t, "test", env.Type)
	assert.Equal(t, AlertSeverityInfo, env.Severity)
	assert.Equal(t, DefaultAlertSource, env.Source)
	assert.False(t, env.Resolved)
	assert.Equal(t, "mibee-steward/test/", env.DedupKey)
	assert.Nil(t, env.Tags) // no metadata → no tags, omitted from JSON
}

func TestBuildAlertEnvelope_SourceOverridesAndFallbacks(t *testing.T) {
	// custom source lands in source + dedup prefix
	env := buildAlertEnvelope(payloadWithEvent("device_lost", "aa:bb:cc:dd:ee:ff"), "homelab-steward")
	assert.Equal(t, "homelab-steward", env.Source)
	assert.Equal(t, "homelab-steward/device_lost/aa:bb:cc:dd:ee:ff", env.DedupKey)

	// no MAC → IP fallback; no IP → device name fallback
	ipOnly, _ := json.Marshal(map[string]any{"event_type": "device_lost", "ip_address": "192.0.2.99"})
	env = buildAlertEnvelope(Payload{Metadata: ipOnly}, "")
	assert.Equal(t, "192.0.2.99", env.SourceRef)

	nameOnly, _ := json.Marshal(map[string]any{"event_type": "device_added", "device_name": "unknown device"})
	env = buildAlertEnvelope(Payload{Metadata: nameOnly}, "")
	assert.Equal(t, "unknown device", env.SourceRef)
}

func payloadWithEvent(eventType, mac string) Payload {
	meta, _ := json.Marshal(map[string]any{
		"event_type":  eventType,
		"mac_address": mac,
	})
	return Payload{Subject: eventType, Body: "body", Metadata: meta}
}

func TestBuildAlertEnvelope_ProbeEvents(t *testing.T) {
	// probe_failed: error severity, explicit probe/<id> source_ref wins over
	// the device-identity fallbacks, probe fields land in tags.
	meta, _ := json.Marshal(map[string]any{
		"event_type":     "probe_failed",
		"target_name":    "www-example",
		"module":         "http",
		"target_address": "https://www.example.com",
		"source_ref":     "probe/7",
		"rule_name":      "site-watch",
	})
	env := buildAlertEnvelope(Payload{Subject: "Probe failed: www-example", Metadata: meta}, "")
	assert.Equal(t, AlertSeverityError, env.Severity)
	assert.Equal(t, "probe/7", env.SourceRef)
	assert.Equal(t, "mibee-steward/probe_failed/probe/7", env.DedupKey)
	assert.Equal(t, map[string]string{
		"target_name":    "www-example",
		"module":         "http",
		"target_address": "https://www.example.com",
		"rule_name":      "site-watch",
	}, env.Tags)

	// probe_recovered pairs with probe_failed via the shared dedup key
	// (metadata source_ref keeps them aligned regardless of renames).
	recMeta, _ := json.Marshal(map[string]any{
		"event_type": "probe_recovered", "target_name": "www-example", "source_ref": "probe/7",
	})
	rec := buildAlertEnvelope(Payload{Subject: "Probe recovered: www-example", Metadata: recMeta}, "")
	assert.True(t, rec.Resolved)
	assert.Equal(t, AlertSeverityInfo, rec.Severity)
	assert.Equal(t, env.DedupKey, rec.DedupKey, "recovery must share the firing dedup key")
}
