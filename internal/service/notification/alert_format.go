// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package notification

import (
	"encoding/json"
	"fmt"
	"strings"

	"mibee-steward/internal/domain"
)

// Alert payload format for webhook channels. A webhook channel configured with
// format:"alert" POSTs a receiver-agnostic alert envelope instead of the raw
// Steward Payload JSON, so any external alert center (or generic webhook
// receiver) can consume severity/resolved/dedup semantics without knowing
// Steward's internal payload shape. format:"raw" (the default) keeps the
// historical behaviour byte-for-byte.
const (
	AlertFormatRaw   = "raw"
	AlertFormatAlert = "alert"

	// DefaultAlertSource identifies Steward as the event origin in the alert
	// envelope and inside dedup_key. Receivers that bind identity to an ingest
	// token (e.g. per-source tokens) may ignore it.
	DefaultAlertSource = "mibee-steward"
)

// Severity levels of the alert envelope. Intentionally the same closed set
// used by common alert receivers (info < warning < error < critical). Steward
// never emits "critical": escalation is the receiving alert center's job.
const (
	AlertSeverityInfo    = "info"
	AlertSeverityWarning = "warning"
	AlertSeverityError   = "error"
)

// alertEnvelope is the JSON body posted by webhook channels with
// format:"alert". Field set is the minimal universal alert shape
// (type/severity/title/body/source_ref/tags/resolved/dedup_key) plus
// source/occurred_at for receivers that want provenance. Unknown fields are
// ignored by receivers, so extra keys here stay non-breaking.
type alertEnvelope struct {
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Body       string            `json:"body"`
	Source     string            `json:"source"`
	SourceRef  string            `json:"source_ref,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Resolved   bool              `json:"resolved"`
	DedupKey   string            `json:"dedup_key"`
	OccurredAt string            `json:"occurred_at,omitempty"`
}

// recoveryDedupType maps a recovery event type to the firing event type it
// resolves. Both sides of a pair share one dedup_key (source/firing/ref).
var recoveryDedupType = map[string]string{
	domain.RuleEventTypeDeviceRecovered: domain.RuleEventTypeDeviceLost,
	domain.RuleEventTypeProbeRecovered:  domain.RuleEventTypeProbeFailed,
}

// alertSeverity maps a Steward change event type to an envelope severity.
// Unmapped non-empty event types default to warning (the conservative middle
// tier); payloads without an event type (test dispatch, manual sends) are info.
func alertSeverity(eventType string) string {
	switch eventType {
	case domain.RuleEventTypeDeviceLost, domain.RuleEventTypeProbeFailed:
		return AlertSeverityError
	case domain.RuleEventTypeDeviceRecovered, domain.RuleEventTypeDeviceAdded,
		domain.RuleEventTypeProbeRecovered:
		return AlertSeverityInfo
	case domain.RuleEventTypeDeviceChanged,
		domain.RuleEventTypeSpeaksWithNew,
		domain.RuleEventTypeListenPortAdded,
		"device_config_changed":
		return AlertSeverityWarning
	case "":
		return AlertSeverityInfo
	default:
		return AlertSeverityWarning
	}
}

// buildAlertEnvelope derives the alert envelope from a dispatch Payload. The
// structured fields come from Payload.Metadata (written by the rule engine's
// buildPayload); a payload without metadata (test dispatch) degrades to a
// type:"test" info event. Resolved is derived from the event type suffix so
// future *_recovered event kinds pair with their firing counterpart for free.
func buildAlertEnvelope(p Payload, source string) alertEnvelope {
	if source == "" {
		source = DefaultAlertSource
	}

	meta := map[string]any{}
	if len(p.Metadata) > 0 {
		_ = json.Unmarshal(p.Metadata, &meta)
	}

	eventType := metaString(meta, "event_type")
	envelopeType := eventType
	if envelopeType == "" {
		envelopeType = "test"
	}

	// source_ref: the stable entity identity for receiver-side cooldown and
	// firing/resolved pairing. Event sources may stamp it explicitly (probe
	// events use probe/<target_id>); device events rely on MAC, stable across
	// rescans and re-adds (the same property the rule engine cooldown keys
	// on); IP and name are fallbacks.
	sourceRef := metaString(meta, "source_ref")
	if sourceRef == "" {
		sourceRef = metaString(meta, "mac_address")
	}
	if sourceRef == "" {
		sourceRef = metaString(meta, "ip_address")
	}
	if sourceRef == "" {
		sourceRef = metaString(meta, "device_name")
	}

	resolved := strings.HasSuffix(eventType, "_recovered")

	// dedup_key identifies the PROBLEM, not the occurrence: a recovery must
	// carry the same key as the event it resolves, so receivers pair
	// firing/resolved (and cancel escalations) the way Alertmanager pairs
	// groupKey. The pairing is explicit because the names are not derivable
	// by suffix-stripping (device_recovered resolves device_lost). Envelope
	// Type above stays truthful to what happened.
	dedupType := envelopeType
	if firing, ok := recoveryDedupType[eventType]; ok {
		dedupType = firing
	}

	tags := map[string]string{}
	for _, key := range []string{
		"device_name", "ip_address", "mac_address", "device_type", // device events
		"target_name", "target_address", "module", // probe events
		"rule_name",
	} {
		if v := metaString(meta, key); v != "" {
			tags[key] = v
		}
	}
	if v, ok := meta["network_id"]; ok && v != nil {
		tags["network_id"] = fmt.Sprintf("%v", v)
	}
	if len(tags) == 0 {
		tags = nil
	}

	return alertEnvelope{
		Type:       envelopeType,
		Severity:   alertSeverity(eventType),
		Title:      p.Subject,
		Body:       p.Body,
		Source:     source,
		SourceRef:  sourceRef,
		Tags:       tags,
		Resolved:   resolved,
		DedupKey:   source + "/" + dedupType + "/" + sourceRef,
		OccurredAt: metaString(meta, "detected_at"),
	}
}

// metaString reads a string-valued key from a decoded metadata map, returning
// "" for absent/non-string values.
func metaString(meta map[string]any, key string) string {
	if v, ok := meta[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
