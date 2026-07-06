// ---------------------------------------------------------------------------
// Shared TypeScript types for MiBee Steward
// Merged from route files to eliminate duplication. This is the single source
// of truth for all domain types used across the frontend.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Enums / Unions
// ---------------------------------------------------------------------------

export type DeviceStatus = 'online' | 'offline' | 'unknown';
export type DeviceType = 'pc' | 'embedded' | 'iot' | 'other';
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

export interface PrometheusInfo {
	url?: string;
	node_exporter_url?: string;
	labels?: Record<string, string>;
}

export interface ScanAttributes {
	vendor?: string;
	mac?: string;
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
