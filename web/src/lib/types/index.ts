/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

// ---------------------------------------------------------------------------
// Shared TypeScript types for MiBee Steward
// Merged from route files to eliminate duplication. This is the single source
// of truth for all domain types used across the frontend.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Enums / Unions
// ---------------------------------------------------------------------------

export type DeviceStatus = 'online' | 'offline' | 'unknown';
// Full set mirrors internal/domain validDeviceTypes (10 values). The type filter
// dropdown and the device form already surface all 10, so the type must too —
// the previous 4-value union silently mistyped 6 device categories.
export type DeviceType =
	| 'pc'
	| 'embedded'
	| 'iot'
	| 'server'
	| 'switch'
	| 'router'
	| 'firewall'
	| 'nas'
	| 'camera'
	| 'phone'
	| 'printer'
	| 'other';
export type UserRole = 'admin' | 'user';
export type ProbeMethod = 'ICMP' | 'TCP' | 'HTTP' | 'SNMP';
export type ProbeResultStatus = 'success' | 'fail' | 'unknown';
export type DocumentType = 'url' | 'file';

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

/** Structured view of the engine-written scan_attributes JSON document.
 *  Mirrors internal/domain.ScanAttributes. Fields are optional because the
 *  engine fills them progressively; an unknown field key should not break
 *  parsing — use [key: string]: unknown as the safety net. */
export interface SNMPDiscovery {
	sys_descr?: string;
	sys_object_id?: string;
	sys_name?: string;
	sys_location?: string;
	sys_contact?: string;
	sys_services?: number;
}

export interface OpenPortEntry {
	port: number;
	service?: string;
}

export interface ServiceEntry {
	port: number;
	name: string;
	protocol?: string;
	version?: string;
}

// ---------------------------------------------------------------------------
// TLS certificates (host_tls_certs via GET /devices/{id}/certificates)
// ---------------------------------------------------------------------------

/** One certificate in a port's chain. cert_index 0 is the leaf/server cert. */
export interface CertificateInfo {
	cert_index: number;
	subject_cn: string;
	subject_org: string;
	subject: string;
	issuer_cn: string;
	issuer_org: string;
	issuer: string;
	san_dns: string;
	san_ip: string;
	san_email: string;
	serial: string;
	/** ISO 8601 UTC, e.g. "2026-07-18T12:34:56Z" */
	not_before: string;
	/** ISO 8601 UTC */
	not_after: string;
	sig_algorithm: string;
	key_algorithm: string;
	key_bits: number;
	is_ca: boolean;
	self_signed: boolean;
	fingerprint_sha256: string;
	/** Full PEM (BEGIN CERTIFICATE / END CERTIFICATE). */
	pem: string;
}

/** One TLS-speaking port on a device: the handshake metadata + the chain. */
export interface TLSPortCerts {
	port: number;
	tls_version: string;
	cipher_suite: string;
	trusted: boolean;
	/** Non-empty when the handshake failed; leaf/chain are empty in that case. */
	error?: string;
	updated_at: string;
	/** Leaf (cert_index 0); absent when error is set. */
	leaf?: CertificateInfo;
	/** Ordered chain (leaf first). Empty when error is set. */
	chain: CertificateInfo[];
}

/** Response envelope for GET /devices/{id}/certificates. */
export interface DeviceCertificatesResponse {
	certificates: TLSPortCerts[];
	total: number;
}

export interface PrometheusInfo {
	url?: string;
	node_exporter_url?: string;
	labels?: Record<string, string>;
}

export interface ScanAttributes {
	vendor?: string;
	mac?: string;
	/** Locally-administered (U/L) bit set — the MAC was assigned locally, not
	 *  drawn from an IEEE OUI/MA-S/MA-M block. Neutral FACTUAL flag: the bit
	 *  cannot distinguish privacy randomization (unstable) from a locally fixed
	 *  setting (stable), so it is not a "randomized" verdict and does NOT change
	 *  device identity. Observability badge only. */
	mac_is_locally_administered?: boolean;
	/** multicast bit set — a real device should never source from such a MAC;
	 *  observability flag only (no identity effect). */
	mac_is_multicast?: boolean;
	/** IEEE assignment block the MAC matched via longest-prefix lookup — 6 hex
	 *  (MA-L /24), 7 hex (MA-M /28), or 9 hex (MA-S /36). Empty when no OUI
	 *  table loaded or MAC unknown/locally administered. */
	oui_prefix?: string;
	/** IEEE-registered organization name for the OUI prefix (the NIC silicon
	 *  vendor). Distinct from `vendor` (the device's self-declared brand) — the
	 *  two differ in OEM/rebrand/virtualization cases. */
	oui_vendor?: string;
	hostname?: string;
	os?: string;
	os_version?: string;
	kernel_version?: string;
	firmware_version?: string;
	cpu_count?: number;
	cpu_model?: string;
	memory_total_bytes?: number;
	uptime_seconds?: number;
	ttl?: number;
	last_scan_rtt_ms?: number;
	scan_source?: string;
	last_scanned_at?: string;
	inferred_type?: string;
	inferred_type_source?: string; // 'protocol' (trustworthy) | 'heuristic' (hostname guess, spoofable) | ''
	inferred_description?: string;
	snmp?: SNMPDiscovery;
	open_ports?: OpenPortEntry[];
	detected_services?: ServiceEntry[];
	prometheus?: PrometheusInfo;
	extras?: Record<string, string>;
	[key: string]: unknown;
}

export interface Device {
	id: number;
	name: string;
	type: string;
	brand: string;
	model: string;
	location: string;
	purpose: string;
	description: string;
	status: DeviceStatus;
	ip_address: string;
	mac_address: string;
	serial_number: string;
	purchase_date: string;
	warranty_expiry: string;
	tags: string;
	created_at: string;
	updated_at: string;
	scan_source?: string;
	prometheus_labels?: string;
	last_scanned_at?: string | null;
	last_scan_task_id?: number | null;
	// Liveness visibility. Lets an operator judge whether the silent-device
	// retention is about to prune a device.
	//   - last_seen: scan-derived "last observed online by a scan". Populated on
	//     list AND detail rows.
	//   - last_online_at: authoritative "last confirmed alive" from the verdict
	//     series (heartbeat/scan/lease). Preferred over last_seen when present.
	//     Detail-only (verdict series lives in a separate DB file).
	//   - offline_since: when the device flipped offline — retention clock start.
	//     Populated on list AND detail rows; the list uses it for the "offline for
	//     Nd/Nh" hover on the status dot.
	last_seen?: string | null;
	last_online_at?: string | null;
	offline_since?: string | null;
	open_ports?: string;
	detected_services?: string;
	prometheus_url?: string;
	node_exporter_url?: string;
	last_scan_rtt_ms?: number;
	// Dual JSON layer: scan_attributes (engine-written, typed object) +
	// user_attributes (free-form user key/value map). The legacy string
	// fields above remain populated for backwards compatibility; the UI
	// prefers scan_attributes when present.
	scan_attributes?: ScanAttributes;
	user_attributes?: Record<string, string>;
	// Distributed: the logical network this device was discovered on.
	network_id?: number;
	network_name?: string;
}
// ---------------------------------------------------------------------------
// Linked Document (used in device-document linking modal)
// ---------------------------------------------------------------------------

export interface LinkedDoc {
	id: number;
	title: string;
	type: string;
	url: string;
	description: string;
}

// ---------------------------------------------------------------------------
// DeviceStats
// ---------------------------------------------------------------------------

export interface DeviceStats {
	by_status: {
		online: number;
		offline: number;
		unknown: number;
	};
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

export interface User {
	id: number;
	username: string;
	email: string;
	role: UserRole;
	created_at: string;
}

// ---------------------------------------------------------------------------
// Profile (self-service settings page)
// ---------------------------------------------------------------------------

export interface Profile {
	id: number;
	username: string;
	email: string;
	role: UserRole;
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

export interface HeartbeatConfig {
	id: number;
	device_id: number;
	method: ProbeMethod;
	target: string;
	interval: number;
	timeout: number;
	enabled: boolean;
	snmp_community: string;
	snmp_oid: string;
	expected_status: number;
}

export interface HeartbeatResult {
	id: number;
	config_id: number;
	status: ProbeResultStatus;
	latency_ms: number;
	checked_at: string;
}

export interface DeviceHealth {
	device: Device;
	configs: HeartbeatConfig[];
	results: HeartbeatResult[];
	loading: boolean;
}

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

export interface Document {
	id: number;
	title: string;
	type: DocumentType;
	url: string;
	description: string;
	file_path: string;
	file_size: number;
	mime_type: string;
	created_at: string;
}

// ---------------------------------------------------------------------------
// System (device subsystem)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Topology / Neighbors (L2 adjacency — device_neighbors table)
// ---------------------------------------------------------------------------

// One neighbor edge as returned by GET /devices/{id}/neighbors. The
// neighbor_* fields are present only when the neighbor MAC matches a scanned
// device (LEFT JOIN); absent when the neighbor is unidentified.
export interface DeviceNeighbor {
	id: number;
	device_id: number;
	neighbor_device_id?: number | null;
	neighbor_mac: string;
	protocol: string; // 'LLDP' | 'Bridge-MIB' | 'CDP' | 'ARP'
	local_port?: string | null;
	remote_port?: string | null;
	neighbor_name?: string | null;
	neighbor_ip?: string | null;
	neighbor_type?: string | null;
	neighbor_status?: string | null;
	first_seen?: string | null;
	last_seen?: string | null;
}

// Topology graph node (one device) + edge (one L2 adjacency).
export interface TopoNode {
	id: number;
	name: string;
	ip_address: string;
	mac_address: string;
	type: string;
	status: string;
	inferred_type: string;
	brand: string;
	network_id?: number | null;
}

export interface TopoEdge {
	from_device_id: number;
	to_device_id?: number | null; // null = unidentified neighbor (dashed edge)
	to_mac: string;
	protocol: string;
	local_port?: string | null;
	remote_port?: string | null; // far-end ifName (LLDP/CDP only; empty for Bridge-MIB/ARP)
}

export interface TopologyGraph {
	nodes: TopoNode[];
	edges: TopoEdge[];
}

export interface System {
	id: number;
	device_id: number;
	name: string;
	entry_url: string;
	description: string;
	category: string;
	metrics_url: string;
	metrics_enabled: boolean;
	tags: string;
	created_at: string;
	updated_at: string;
}
// ---------------------------------------------------------------------------
// API Response wrappers
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
	data: T[];
	total: number;
	limit: number;
	offset: number;
}

export interface LoginResponse {
	token: string;
	user: {
		id: number;
		username: string;
		email: string;
		role: UserRole;
		must_change_password: boolean;
	};
	two_factor_required?: boolean;
	user_id?: number;
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

export interface AuditLog {
	id: number;
	user_id: number;
	username: string;
	action: string;
	resource_type: string;
	resource_id: string;
	ip_address: string;
	user_agent: string;
	details: string;
	created_at: string;
}

// ---------------------------------------------------------------------------
// Scanner Pipeline Config
// ---------------------------------------------------------------------------

export interface ICMPConfig {
	enabled: boolean;
	timeout: number;
}

export interface SNMPConfig {
	enabled: boolean;
	community: string;
}

// ---------------------------------------------------------------------------
// SNMP Credential (issue #135 — SNMPv3)
// ---------------------------------------------------------------------------
// Mirrors internal/api/handler/credential.go's masked projection. Passphrases
// are NEVER included (encrypted or plaintext) — has_auth/has_priv derive from
// the protocol fields. This is the LIST/GET response shape.

export interface SNMPCredential {
	id: number;
	name: string;
	security_level: 'v1v2c' | 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
	community?: string;
	username?: string;
	auth_protocol?: string;
	has_auth: boolean;
	priv_protocol?: string;
	has_priv: boolean;
	notes?: string;
}

// SNMPCredentialRequest is the CREATE/UPDATE body. auth_passphrase /
// priv_passphrase are plaintext (sent over TLS) and encrypted server-side.
// On UPDATE, an empty passphrase field means "leave unchanged" so an admin
// editing just the name doesn't need to retype the secret.
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

export interface SNMPCredentialListResponse {
	credentials: SNMPCredential[];
	total: number;
}

export interface PortScanConfig {
	enabled: boolean;
	ports: string;
	scan_type: string;
}

export interface ServiceDetectConfig {
	enabled: boolean;
}

export interface PrometheusStageConfig {
	enabled: boolean;
	ports: string;
}

export interface NodeExporterConfig {
	enabled: boolean;
}

export interface PipelineConfig {
	icmp: ICMPConfig;
	snmp: SNMPConfig;
	port_scan: PortScanConfig;
	service_detect: ServiceDetectConfig;
	prometheus: PrometheusStageConfig;
	node_exporter: NodeExporterConfig;
}

// ---------------------------------------------------------------------------
// Dashboard Widget (Prometheus-backed dashboard cards). The API shape is shared
// across WidgetPicker (create/edit form), DashboardWidget (rendered card), and
// the dashboard route's widget state. Defined once here to avoid the three-way
// drift that existed when each file declared its own copy (#71).
// ---------------------------------------------------------------------------

export interface DashboardWidgetConfig {
	id: string;
	name: string;
	type: string;
	data_source: string;
	query: string;
	refresh_interval: number;
	position: number;
	created_at: string;
	updated_at: string;
}

// ---------------------------------------------------------------------------
// Scanner Task
// ---------------------------------------------------------------------------

export interface ScannerTask {
	id: number;
	name: string;
	targets: string;
	cron_expr: string;
	enabled: boolean;
	timeout: number;
	community: string;
	// credential_id (issue #135): bound SNMP credential. null = use the engine's
	// global default community. When set, the task runs with that credential's
	// auth (v3 USM or a specific v1/v2c community), overriding community.
	credential_id: number | null;
	pipeline_config: PipelineConfig | null;
	last_run_at: string | null;
	next_run_at: string | null;
	last_run_status: string | null;
	created_at: string;
	updated_at: string;
}

// Scanner Run
export interface ScanRun {
	id: number;
	task_id: number;
	status: string;
	total_hosts: number;
	alive_hosts: number;
	new_hosts: number;
	updated_hosts: number;
	duration_ms: number;
	error_message?: string;
	started_at?: string;
	finished_at?: string;
	created_at: string;
}

// ---------------------------------------------------------------------------
// Network (distributed: logical network an agent discovers for)
// ---------------------------------------------------------------------------

export interface Network {
	id: number;
	name: string;
	cidr?: string;
	site?: string;
	agent_id?: string;
}

// ---------------------------------------------------------------------------
// Change Log (device_added / device_changed / device_lost events)
// ---------------------------------------------------------------------------

export type ChangeType = 'device_added' | 'device_changed' | 'device_lost' | 'device_recovered';

export interface ChangeLogEntry {
	id: number;
	agent_id?: string;
	network_id?: number;
	change_type: ChangeType;
	entity_type: string;
	entity_id?: number;
	before_data?: string;
	after_data?: string;
	detected_at: string;
}

// ---------------------------------------------------------------------------
// Discovery Status (passive discovery runtime counters + recent discoveries)
// ---------------------------------------------------------------------------

export interface DiscoveryConfig {
	Interval?: number;
	TriggerIdentify?: boolean;
}

export interface DiscoveryStats {
	EventsReceived?: number;
	SuppressedRecent?: number;
	KnownHostSkipped?: number;
	IdentifyTriggered?: number;
	IdentifyAlive?: number;
	IdentifyDead?: number;
	DeviceRecorded?: number;
}

export interface RecentDiscovery {
	ip: string;
	mac?: string;
	source: string;
	outcome: string;
	at: string;
}

export interface DiscoveryStatus {
	enabled: boolean;
	started_at?: string;
	uptime?: string;
	config?: DiscoveryConfig;
	sources?: string[];
	stats?: DiscoveryStats;
	recent_discoveries?: RecentDiscovery[];
}

// ---------------------------------------------------------------------------
// Agent Token (distributed: discovery-agent bearer tokens)
// ---------------------------------------------------------------------------

export interface AgentToken {
	id: number;
	agent_id: string;
	network_id?: number;
	name?: string;
	created_at: string;
	last_used_at?: string | null;
	revoked_at?: string | null;
}

/** Returned only on token creation — includes the plaintext token (once). */
export interface AgentTokenCreated extends AgentToken {
	token: string;
}

// ---------------------------------------------------------------------------
// Agent Command (center → agent command queue)
// ---------------------------------------------------------------------------

export type AgentCommandStatus = 'pending' | 'acknowledged' | 'done' | 'failed';

export interface AgentCommand {
	id: number;
	agent_id: string;
	command: string;
	payload: string;
	status: AgentCommandStatus;
	created_at: string;
	acknowledged_at?: string | null;
	result?: string | null;
}

// ---------------------------------------------------------------------------
// Notification log (notification_log table — outbound dispatch history)
// ---------------------------------------------------------------------------

export interface NotificationLog {
	id: number;
	status: string;
	payload: string;
	error_message: string;
	sent_at: string;
	is_read: boolean;
}

export interface NotificationLogsResponse {
	logs: NotificationLog[];
	// "total" is the requesting user's UNREAD count (server semantics), used
	// directly as the bell badge value.
	total: number;
}

export interface MarkAllReadResponse {
	marked: number;
}
