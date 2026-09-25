/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero
 * General Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

// ---------------------------------------------------------------------------
// Shared TypeScript types for MiBee Steward.
//
// #274 follow-up: the authoritative API types are GENERATED from
// docs/openapi.yaml (`npm run gen:api` → src/lib/api/schema.d.ts, drift-
// checked in CI). This module re-exports the generated schemas under their
// historical names so call sites stay stable: but the SHAPE is now the
// contract's truth, not a hand-maintained copy. Do not re-declare wire
// shapes here; enrich docs/openapi.yaml and regenerate instead.
//
// Kept handwritten BY DESIGN (no wire counterpart):
//   - view models composed client-side (DeviceHealth, DashboardListItem)
//   - write-only request bodies that openapi.yaml doesn't model yet
//     (SNMPCredentialRequest, NotificationRuleRequest)
// ---------------------------------------------------------------------------

import type { components } from '$lib/api/schema';

/** Generated schema table: every wire type below indexes into this. */
type Schemas = components['schemas'];

export type { components as ApiComponents, paths as ApiPaths } from '$lib/api/schema';

// ---------------------------------------------------------------------------
// Enums / Unions (derived from the generated entity schemas)
// ---------------------------------------------------------------------------

export type DeviceStatus = Schemas['Device']['status'];
/** Full 12-value set mirrors internal/domain validDeviceTypes (schema CHECK). */
export type DeviceType = Schemas['Device']['type'];
export type UserRole = Schemas['User']['role'];
export type ProbeMethod = Schemas['HeartbeatConfig']['method'];
export type ProbeResultStatus = Schemas['ProbeResult']['status'];
export type DocumentType = Schemas['Document']['type'];
export type ChangeType = Schemas['ChangeLogEntry']['change_type'];
export type AgentCommandStatus = Schemas['AgentCommand']['status'];

// ---------------------------------------------------------------------------
// Device (GET/PUT /devices, list envelope)
// ---------------------------------------------------------------------------

export type SNMPDiscovery = Schemas['SNMPDiscovery'];
export type OpenPortEntry = Schemas['OpenPortEntry'];
export type ServiceEntry = Schemas['ServiceEntry'];
export type PrometheusInfo = Schemas['PrometheusInfo'];
export type ScanAttributes = Schemas['ScanAttributes'];
export type Device = Schemas['Device'];
export type DeviceStats = Schemas['DeviceStats'];

// ---------------------------------------------------------------------------
// TLS certificates (host_tls_certs via GET /devices/{id}/certificates)
// ---------------------------------------------------------------------------

/** One certificate in a port's chain. cert_index 0 is the leaf/server cert. */
export type CertificateInfo = Schemas['CertificateInfo'];
/** One TLS-speaking port on a device: the handshake metadata + the chain. */
export type TLSPortCerts = Schemas['TLSPortCerts'];
/** Response envelope for GET /devices/{id}/certificates. */
export type DeviceCertificatesResponse = Schemas['CertificateList'];

// ---------------------------------------------------------------------------
// Synthetic probing (拨测)，user-configured external targets
// ---------------------------------------------------------------------------

export type ProbeTarget = Schemas['ProbeTarget'];
export type ProbeTargetListResponse = Schemas['ProbeTargetList'];
export type ProbeVantageLatest = Schemas['ProbeVantageLatest'];
export type ProbeResult = Schemas['ProbeResult'];
export type ProbeResultListResponse = Schemas['ProbeResultList'];
/** Synchronous trigger response (POST /probe-targets/{id}/trigger). */
export type ProbeTriggerResponse = Schemas['ProbeResult'];

// ---------------------------------------------------------------------------
// Linked Document (used in device-document linking modal)
// ---------------------------------------------------------------------------

export type LinkedDoc = Schemas['Document'];

// ---------------------------------------------------------------------------
// User / Profile
// ---------------------------------------------------------------------------

export type User = Schemas['User'];
/** Read-side projection of the logged-in user (/auth/profile). */
export type Profile = Pick<User, 'id' | 'username' | 'email' | 'role'>;

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

export type HeartbeatConfig = Schemas['HeartbeatConfig'];
export type HeartbeatResult = Schemas['HeartbeatResult'];
export type HeartbeatResultList = Schemas['HeartbeatResultList'];
export type HeartbeatStats = Schemas['HeartbeatStats'];

/** Client-side view model: device + its heartbeat data + loading flag. */
export interface DeviceHealth {
	device: Device;
	configs: HeartbeatConfig[];
	results: HeartbeatResult[];
	loading: boolean;
}

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

export type Document = Schemas['Document'];

// ---------------------------------------------------------------------------
// Topology / Neighbors (L2 adjacency: device_neighbors table)
// ---------------------------------------------------------------------------

/** One neighbor edge as returned by GET /devices/{id}/neighbors. */
export type DeviceNeighbor = Schemas['DeviceNeighbor'];
/** Topology graph node (one device) + edge (one L2 adjacency). */
export type TopoNode = Schemas['TopologyNode'];
export type TopoEdge = Schemas['TopologyEdge'];
export type TopologyGraph = Schemas['TopologyGraph'];

// Device subsystem entries (hardware/OS/license inventory)
export type System = Schemas['DeviceSystem'];

// ---------------------------------------------------------------------------
// API Response wrappers
// ---------------------------------------------------------------------------

// Generic list envelope of the API contract (#274): every paginated endpoint
// responds {<resource>: [...], total, limit, offset} (complete lists omit
// limit/offset).
export interface ListEnvelope {
	total: number;
	limit?: number;
	offset?: number;
}

export type LoginResponse = Schemas['LoginResponse'];

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

export type AuditLog = Schemas['AuditLog'];

// ---------------------------------------------------------------------------
// Scanner Pipeline Config (nested inside ScanTask.pipeline_config)
// ---------------------------------------------------------------------------

export type ICMPConfig = Schemas['PipelineConfig']['icmp'];
export type SNMPConfig = Schemas['PipelineConfig']['snmp'];
export type PortScanConfig = Schemas['PipelineConfig']['port_scan'];
export type ServiceDetectConfig = Schemas['PipelineConfig']['service_detect'];
export type PrometheusStageConfig = Schemas['PipelineConfig']['prometheus'];
export type NodeExporterConfig = Schemas['PipelineConfig']['node_exporter'];
export type PipelineConfig = Schemas['PipelineConfig'];

// ---------------------------------------------------------------------------
// SNMP Credential (issue #135: SNMPv3)
// ---------------------------------------------------------------------------
// SNMPCredential is the masked LIST/GET response: passphrases are NEVER
// included (not even ciphertext); has_auth/has_priv derive from the protocol
// fields. SNMPCredentialRequest is the CREATE/UPDATE body: passphrases are
// plaintext (sent over TLS) and encrypted server-side; on UPDATE an empty
// passphrase field means "leave unchanged" so an admin editing just the name
// doesn't need to retype the secret.

export type SNMPCredential = Schemas['SNMPCredential'];

export interface SNMPCredentialRequest {
	name: string;
	security_level: SNMPCredential['security_level'];
	community?: string;
	username?: string;
	auth_protocol?: string;
	auth_passphrase?: string;
	priv_protocol?: string;
	priv_passphrase?: string;
	notes?: string;
}

export type SNMPCredentialListResponse = Schemas['SNMPCredentialList'];

// ---------------------------------------------------------------------------
// Dashboard widgets (dashboard cards). The API shape (DashboardConfig) is
// shared across WidgetPicker (create/edit form), DashboardWidget (rendered
// card), and the dashboard route's widget state: aliased here once to avoid
// the three-way drift that existed when each file declared its own copy (#71).
// ---------------------------------------------------------------------------

export type DashboardWidgetConfig = Schemas['DashboardConfig'];

// A row rendered by a builtin list widget. Builtin chart widgets
// (pie/bar/gauge) build an ECharts option instead and leave items empty.
export interface DashboardListItem {
	// Primary line: device name / change summary / run label / probe target.
	title: string;
	// Optional secondary line (IP, sub-status…).
	subtitle?: string;
	// Optional status chip (online/offline/running/completed/...).
	status?: string;
	// Timestamp text, pre-formatted by the fetch layer.
	time?: string;
	// In-app link when the row is clickable (device list, probe page…).
	href?: string;
}

// ---------------------------------------------------------------------------
// Scanner Task / Run
// ---------------------------------------------------------------------------

export type ScannerTask = Schemas['ScanTask'];
export type ScanRun = Schemas['ScanRun'];

// ---------------------------------------------------------------------------
// Network (distributed: logical network an agent discovers for)
// ---------------------------------------------------------------------------

export type Network = Schemas['Network'];
export type VLAN = Schemas['VLAN'];

// ---------------------------------------------------------------------------
// Change Log (device_added / device_changed / device_lost events)
// ---------------------------------------------------------------------------

export type ChangeLogEntry = Schemas['ChangeLogEntry'];

// ---------------------------------------------------------------------------
// Discovery Status (passive discovery runtime counters + recent discoveries)
// ---------------------------------------------------------------------------

export type DiscoveryConfig = Schemas['DiscoveryStatus']['config'];
export type DiscoveryStats = Schemas['DiscoveryStatus']['stats'];
export type RecentDiscovery = Schemas['DiscoveryStatus']['recent_discoveries'][number];
export type DiscoveryStatus = Schemas['DiscoveryStatus'];

// ---------------------------------------------------------------------------
// Agent Token (distributed: discovery-agent bearer tokens)
// ---------------------------------------------------------------------------

export type AgentToken = Schemas['AgentToken'];
/** Returned only on token creation: includes the plaintext token (once). */
export type AgentTokenCreated = Schemas['AgentTokenCreated'];

// ---------------------------------------------------------------------------
// Agent Command (center → agent command queue)
// ---------------------------------------------------------------------------

export type AgentCommand = Schemas['AgentCommand'];

// ---------------------------------------------------------------------------
// Notification rule (notification_rules table: #139 event→channel bindings)
// ---------------------------------------------------------------------------

export type NotificationRule = Schemas['NotificationRule'];
export type NotificationChannel = Schemas['NotificationChannel'];

// Rule create/update body (write-only; not yet modeled in openapi.yaml).
export interface NotificationRuleRequest {
	name: string;
	event_type: string;
	scope_type: string;
	scope_network_id?: number | null;
	scope_device_uuid?: string;
	channel_id: number;
	cooldown_minutes: number;
}

export type NotificationRuleListResponse = Schemas['NotificationRuleList'];

// ---------------------------------------------------------------------------
// Notification log (notification_log table: outbound dispatch history)
// ---------------------------------------------------------------------------

export type NotificationLog = Schemas['NotificationLog'];
export type NotificationLogsResponse = Schemas['NotificationLogList'];
export type MarkAllReadResponse = Schemas['MarkAllReadResponse'];
