<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import type { Device, System } from '$lib/types';
	import type { EChartsOption } from '$lib/charts/echarts';
	import { Monitor, BarChart3 } from '@lucide/svelte';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import SystemCard from '$lib/components/SystemCard.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Chart from '$lib/components/Chart.svelte';
	import LabelEditor from '$lib/components/scanner/LabelEditor.svelte';

	// --- Route param ---
	let deviceId = $derived(Number($page.params.id));

	// --- Core state ---
	let device = $state<Device | null>(null);
	let systems = $state<System[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');

	// --- Filters ---
	let categoryFilter = $state('');
	let offset = $state(0);
	const limit = 12;

	// --- Form modal ---
	let formOpen = $state(false);
	let editingSystem = $state<System | null>(null);
	let formError = $state('');
	let formLoading = $state(false);

	let formName = $state('');
	let formEntryUrl = $state('');
	let formDescription = $state('');
	let formCategory = $state('web_app');
	let formMetricsUrl = $state('');
	let formMetricsEnabled = $state(false);
	let formTags = $state('');

	// --- Delete state ---
	let deleteOpen = $state(false);
	let deleteTarget = $state<System | null>(null);

	// --- Heartbeat trend state ---
	let trendLoading = $state(false);
	let trendPreset = $state('24h');
	let trendFrom = $state('');
	let trendTo = $state('');
	let trendOption = $state<EChartsOption>({});
	let trendStats = $state<{ avg_latency_ms: number; success_count: number; fail_count: number; timeout_count: number } | null>(null);
	// --- Heartbeat config state ---
	let heartbeatConfigs = $state<Array<{ id: number; method: string; target: string; interval_seconds: number; timeout_seconds: number; enabled: number }>>([]);
	let heartbeatConfigLoading = $state(false);
	let creatingHeartbeat = $state(false);

	// --- Heartbeat config edit/delete state ---
	let editingConfig = $state<typeof heartbeatConfigs[0] | null>(null);
	let editConfigLoading = $state(false);
	let deletingConfigId = $state<number | null>(null);
	let deleteConfigLoading = $state(false);
	// --- Label state ---
	let labelSaving = $state(false);

	function parseLabels(raw: string | undefined | null): Record<string, string> {
		if (!raw) return {};
		try { return JSON.parse(raw); }
		catch { return {}; }
	}

	function parseJsonArray(raw: string | undefined | null): unknown[] {
		if (!raw || !raw.trim()) return [];
		try {
			const parsed = JSON.parse(raw);
			return Array.isArray(parsed) ? parsed : [];
		} catch {
			return [];
		}
	}

	async function handleSaveLabels(labels: Record<string, string>) {
		labelSaving = true;
		try {
			await api.put(`/devices/${deviceId}`, { prometheus_labels: JSON.stringify(labels) });
			addToast('success', m['labels.Labels Saved']());
			fetchDevice();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			labelSaving = false;
		}
	}

	// --- User attributes state (free-form key/value map) ---
	let userAttrSaving = $state(false);

	async function handleSaveUserAttributes(attrs: Record<string, string>) {
		userAttrSaving = true;
		try {
			// Send the full desired map as a patch. The backend merges: keys
			// present here are set/overwritten; empty-string values delete.
			// scan_attributes is engine-owned and not touched.
			await api.put(`/devices/${deviceId}`, { user_attributes: attrs });
			addToast('success', m['userfields.Attributes Saved']());
			fetchDevice();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			userAttrSaving = false;
		}
	}

	function formatTimestamp(iso: string | null | undefined): string {
		if (!iso) return '-';
		try { return new Date(iso).toLocaleString(); }
			catch { return iso; }
	}

	function formatBytes(bytes: number | undefined | null): string {
		if (!bytes || bytes <= 0) return '-';
		const units = ['B', 'KB', 'MB', 'GB', 'TB'];
		let v = bytes, i = 0;
		while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
		return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
	}

	function formatDuration(seconds: number | undefined | null): string {
		if (!seconds || seconds <= 0) return '-';
		const d = Math.floor(seconds / 86400);
		const h = Math.floor((seconds % 86400) / 3600);
		const min = Math.floor((seconds % 3600) / 60);
		if (d > 0) return `${d}d ${h}h`;
		if (h > 0) return `${h}h ${min}m`;
		return `${min}m`;
	}


	// --- Lifecycle ---
	onMount(() => {
		fetchDevice();
		fetchSystems();
		fetchHeartbeatConfigs();
		fetchHeartbeatTrend();
	});

	// --- Data fetching ---
	async function fetchDevice() {
		try {
			device = await api.get<Device>(`/devices/${deviceId}`);
		} catch (err: unknown) {
			error = getErrorMessage(err);
			addToast('error', error);
		}
	}

	async function fetchHeartbeatConfigs() {
		heartbeatConfigLoading = true;
		try {
			const res = await api.get<{ configs: typeof heartbeatConfigs; total: number }>(`/devices/${deviceId}/heartbeat-configs`);
			heartbeatConfigs = res.configs || [];
		} catch {
			heartbeatConfigs = [];
		} finally {
			heartbeatConfigLoading = false;
		}
	}

		async function createDefaultHeartbeatConfig() {
			creatingHeartbeat = true;
			try {
				const target = device?.ip_address || '';
				if (!target) {
					addToast('error', 'Device has no IP address');
					return;
				}
				await api.post(`/devices/${deviceId}/heartbeat-configs`, {
					method: 'icmp',
					target,
					interval_seconds: 30,
					timeout_seconds: 5,
					enabled: 1
				});
				addToast('success', m['heartbeat.Config Created']());
				await fetchHeartbeatConfigs();
			} catch (err: unknown) {
				addToast('error', getErrorMessage(err));
			} finally {
				creatingHeartbeat = false;
			}
		}

		// Edit a heartbeat config: open the modal with a copy of the config so
		// the form edits a draft without mutating the list entry directly.
		function openEditConfig(cfg: typeof heartbeatConfigs[0]) {
			editingConfig = { ...cfg };
		}

		async function saveEditConfig(e: Event) {
			e.preventDefault();
			if (!editingConfig) return;
			editConfigLoading = true;
			try {
				await api.put(`/heartbeat-configs/${editingConfig.id}`, {
					method: editingConfig.method,
					target: editingConfig.target,
					interval_seconds: editingConfig.interval_seconds,
					timeout_seconds: editingConfig.timeout_seconds,
					enabled: editingConfig.enabled
				});
				addToast('success', m['heartbeat.Config Updated']());
				editingConfig = null;
				await fetchHeartbeatConfigs();
			} catch (err: unknown) {
				addToast('error', getErrorMessage(err));
			} finally {
				editConfigLoading = false;
			}
		}

		async function deleteConfig(cfg: typeof heartbeatConfigs[0]) {
			deleteConfigLoading = true;
			try {
				await api.delete(`/heartbeat-configs/${cfg.id}`);
				addToast('success', m['heartbeat.Config Deleted']());
				deletingConfigId = null;
				await fetchHeartbeatConfigs();
			} catch (err: unknown) {
				addToast('error', getErrorMessage(err));
			} finally {
				deleteConfigLoading = false;
			}
		}


	async function fetchSystems() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			if (categoryFilter) params.set('category', categoryFilter);
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			const res = await api.get<{ systems: System[]; total: number }>(
				`/devices/${deviceId}/systems?${params}`
			);
			systems = res.systems || [];
			total = res.total || 0;
		} catch (err: unknown) {
			error = getErrorMessage(err);
			addToast('error', error);
		} finally {
			loading = false;
		}
	}

	function applyFilter() {
		offset = 0;
		fetchSystems();
	}

	// --- Form helpers ---
	function resetForm() {
		formName = '';
		formEntryUrl = '';
		formDescription = '';
		formCategory = 'web_app';
		formMetricsUrl = '';
		formMetricsEnabled = false;
		formTags = '';
		formError = '';
		editingSystem = null;
	}

	function openCreate() {
		resetForm();
		formOpen = true;
	}

	function openEdit(system: System) {
		editingSystem = system;
		formName = system.name;
		formEntryUrl = system.entry_url || '';
		formDescription = system.description || '';
		formCategory = system.category || 'custom';
		formMetricsUrl = system.metrics_url || '';
		formMetricsEnabled = system.metrics_enabled || false;
		formTags = system.tags || '';
		formError = '';
		formOpen = true;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;
		formError = '';

		if (!formName.trim()) {
			formError = m['systems.Name required']();
			formLoading = false;
			return;
		}

		const body = {
			name: formName.trim(),
			entry_url: formEntryUrl.trim(),
			description: formDescription.trim(),
			category: formCategory,
			metrics_url: formMetricsUrl.trim(),
			metrics_enabled: formMetricsEnabled,
			tags: formTags.trim()
		};

		try {
			if (editingSystem) {
				await api.put(`/devices/${deviceId}/systems/${editingSystem.id}`, body);
				addToast('success', m['systems.Updated']());
			} else {
				await api.post(`/devices/${deviceId}/systems`, body);
				addToast('success', m['systems.Created']());
			}
			formOpen = false;
			resetForm();
			fetchSystems();
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			formError = msg;
			addToast('error', msg);
		} finally {
			formLoading = false;
		}
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/devices/${deviceId}/systems/${deleteTarget.id}`);
			addToast('success', m['systems.Deleted']());
			deleteTarget = null;
			fetchSystems();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Helpers ---
	function statusDotClass(status: string): string {
		if (status === 'online') return 'bg-success animate-pulse-green';
		if (status === 'offline') return 'bg-error animate-pulse-red';
		return 'bg-muted';
	}

	const typeLabel: Record<string, string> = {
		pc: m['devices.PC'](),
		embedded: m['devices.Embedded'](),
		iot: m['devices.IoT'](),
		other: m['devices.Other']()
	};

	// --- Heartbeat trend helpers ---
	type TimePreset = '1h' | '6h' | '24h' | '7d' | '30d';

	function getTimeRange(preset: TimePreset): { from: string; to: string } {
		const now = new Date();
		const from = new Date(now);
		switch (preset) {
			case '1h': from.setHours(from.getHours() - 1); break;
			case '6h': from.setHours(from.getHours() - 6); break;
			case '24h': from.setDate(from.getDate() - 1); break;
			case '7d': from.setDate(from.getDate() - 7); break;
			case '30d': from.setDate(from.getDate() - 30); break;
		}
		return { from: from.toISOString(), to: now.toISOString() };
	}

	function getCSSVar(name: string, fallback: string): string {
		return getComputedStyle(document.documentElement)
			.getPropertyValue(name)
			.trim() || fallback;
	}

	async function fetchHeartbeatTrend() {
		trendLoading = true;
		let from: string;
		let to: string;
		if (trendPreset === 'custom' && trendFrom && trendTo) {
			from = new Date(trendFrom).toISOString();
			to = new Date(trendTo).toISOString();
		} else {
			const range = getTimeRange(trendPreset as TimePreset);
			from = range.from;
			to = range.to;
		}
		try {
			const [historyRes, statsRes] = await Promise.all([
				api.get<{ heartbeat_results: Array<{ id: number; status: string; latency_ms: number; checked_at: string }>; total: number }>(
					`/devices/${deviceId}/heartbeat-history?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&limit=1000`
				),
				api.get<{ avg_latency_ms: number; success_count: number; fail_count: number; timeout_count: number }>(
					`/devices/${deviceId}/heartbeat-stats?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`
				)
			]);
			trendStats = statsRes;
			buildTrendChart(historyRes.heartbeat_results || []);
		} catch {
			trendStats = null;
			trendOption = {};
		} finally {
			trendLoading = false;
		}
	}

	function buildTrendChart(results: Array<{ id: number; status: string; latency_ms: number; checked_at: string }>) {
		if (results.length === 0) {
			trendOption = {};
			return;
		}

		const textColor = getCSSVar('--color-text', '#fafafa');
		const mutedColor = getCSSVar('--color-text-muted', '#a1a1aa');
		const borderColor = getCSSVar('--color-border', '#27272a');
		const successColor = getCSSVar('--color-success', '#10b981');
		const errorColor = getCSSVar('--color-error', '#ef4444');
		const warningColor = getCSSVar('--color-warning', '#f59e0b');
		const primaryColor = getCSSVar('--color-primary', '#6366f1');

		const successData: [string, number][] = [];
		const failData: [string, number][] = [];
		const timeoutData: [string, number][] = [];

		for (const r of results) {
			const time = r.checked_at;
			const latency = r.latency_ms ?? 0;
			if (r.status === 'success') successData.push([time, latency]);
			else if (r.status === 'fail') failData.push([time, latency]);
			else timeoutData.push([time, latency]);
		}

		const allLatencies = results.map(r => r.latency_ms ?? 0);
		const maxLatency = Math.max(...allLatencies, 10);
		const yAxisMax = Math.ceil(maxLatency * 1.2);

		trendOption = {
			backgroundColor: 'transparent',
			tooltip: {
				trigger: 'axis',
				backgroundColor: 'rgba(24, 24, 27, 0.95)',
				borderColor: borderColor,
				textStyle: { color: textColor, fontSize: 12 },
				formatter(params: unknown) {
					const items = params as Array<{ seriesName: string; data: [string, number]; color: string }>;
					if (!Array.isArray(items) || items.length === 0) return '';
					const time = new Date(items[0].data[0]).toLocaleString();
					let html = `<div style="margin-bottom:4px;font-weight:600">${time}</div>`;
					for (const item of items) {
						if (item.data[1] !== undefined) {
							html += `<div style="display:flex;align-items:center;gap:6px">
								<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${item.color}"></span>
								${item.seriesName}: <b>${item.data[1]} ${m['heartbeat.ms']()}</b>
							</div>`;
						}
					}
					return html;
				}
			},
			legend: {
				data: [
					{ name: m['heartbeat.Success Status'](), itemStyle: { color: successColor } },
					{ name: m['heartbeat.Fail Status'](), itemStyle: { color: errorColor } },
					{ name: m['heartbeat.Timeout Status'](), itemStyle: { color: warningColor } }
				],
				textStyle: { color: mutedColor, fontSize: 11 },
				top: 0,
				right: 0
			},
			grid: { top: 36, right: 16, bottom: 28, left: 52 },
			xAxis: {
				type: 'time',
				axisLabel: { color: mutedColor, fontSize: 10, formatter: '{HH}:{mm}' },
				axisLine: { lineStyle: { color: borderColor } },
				splitLine: { show: false }
			},
			yAxis: {
				type: 'value',
				name: m['heartbeat.Latency'](),
				nameTextStyle: { color: mutedColor, fontSize: 11 },
				max: yAxisMax,
				axisLabel: { color: mutedColor, fontSize: 10 },
				axisLine: { lineStyle: { color: borderColor } },
				splitLine: { lineStyle: { color: borderColor, type: 'dashed' } }
			},
			series: [
				{
					name: m['heartbeat.Success Status'](),
					type: 'scatter',
					data: successData,
					symbolSize: 6,
					itemStyle: { color: successColor },
					z: 10
				},
				{
					name: m['heartbeat.Fail Status'](),
					type: 'scatter',
					data: failData,
					symbolSize: 8,
					itemStyle: { color: errorColor },
					symbol: 'diamond',
					z: 10
				},
				{
					name: m['heartbeat.Timeout Status'](),
					type: 'scatter',
					data: timeoutData,
					symbolSize: 7,
					itemStyle: { color: warningColor },
					symbol: 'triangle',
					z: 10
				},
				{
					type: 'line',
					data: results.map(r => [r.checked_at, r.latency_ms ?? 0] as [string, number]),
					smooth: true,
					symbol: 'none',
					lineStyle: { color: primaryColor, width: 1.5, opacity: 0.4 },
					z: 1
				}
			]
		};
	}
</script>

<div class="p-6">
	<!-- Breadcrumb -->
	<nav class="flex items-center gap-2 text-sm text-muted mb-6">
		<a href="/devices" class="hover:text-primary transition-colors">{m['navigation.Devices']()}</a>
		<svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6"/></svg>
		<span class="text-text">{device?.name ?? '...'}</span>
	</nav>

	<!-- Device info header -->
	{#if device}
		<div class="device-info-header">
			<div class="flex items-center gap-3">
				<span class="inline-block w-3 h-3 rounded-full {statusDotClass(device.status)}"></span>
				<h2 class="text-xl font-bold text-primary">{device.name}</h2>
				<span class="text-xs px-2 py-0.5 rounded-full bg-primary/10 text-primary font-medium">
					{typeLabel[device.type] || typeLabel['other']!}
				</span>
			</div>
			<div class="device-meta">
				{#if device.ip_address}
					<span class="device-meta-item">
						<svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>
						<span class="font-mono">{device.ip_address}</span>
					</span>
				{/if}
				{#if device.location}
					<span class="device-meta-item">
						<svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>
						{device.location}
					</span>
				{/if}
			</div>
		</div>
	{/if}

	<!-- Scan Info + Prometheus Labels -->
	{#if device}
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-6">
			<!-- Scan Info Panel -->
			<div class="scan-info-panel">
				<h3 class="scan-info-title">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
					{m['scaninfo.Title']()}
				</h3>

				{#if device.scan_source || device.last_scanned_at}
					<div class="scan-info-grid">
						{#if device.last_scanned_at}
							<div class="scan-info-field">
								<span class="scan-info-label">{m['scaninfo.Last Scanned']()}</span>
								<span class="scan-info-value">{formatTimestamp(device.last_scanned_at)}</span>
							</div>
						{/if}
						{#if device.scan_source}
							<div class="scan-info-field">
								<span class="scan-info-label">{m['scaninfo.Scan Source']()}</span>
								<span class="scan-info-source-badge {device.scan_source !== 'manual' ? 'scan-source-scanner' : 'scan-source-manual'}">
									{device.scan_source !== 'manual' ? m['scaninfo.Scanner']() : m['scaninfo.Manual']()}
								</span>
							</div>
						{/if}
						{#if device.scan_source !== 'manual' && device.last_scan_task_id}
							<div class="scan-info-field">
								<span class="scan-info-label">{m['scaninfo.Source Task']()}</span>
								<span class="scan-info-value font-mono text-xs">{m['scaninfo.Task ID']({ id: device.last_scan_task_id })}</span>
							</div>
						{/if}
					{#if device.scan_source && device.scan_source !== 'manual'}
						{@const parsedServices = parseJsonArray(device.detected_services) as Array<{port?: number; name?: string; protocol?: string}>}
						{@const parsedPorts = parseJsonArray(device.open_ports) as Array<{port?: number; service?: string}>}
						<div class="scan-info-field">
							<span class="scan-info-label">{m['scaninfo.Detected Services']()}</span>
							<div class="flex flex-wrap gap-1 mt-1">
								{#if parsedServices.length > 0}
									{#each parsedServices as svc}
										<span class="service-badge">{svc.port}/{svc.name ?? svc.protocol ?? ''}</span>
									{/each}
								{:else}
									<span class="text-xs text-muted italic">{m['scaninfo.No Services']()}</span>
								{/if}
							</div>
						</div>
						<div class="scan-info-field">
							<span class="scan-info-label">{m['scaninfo.Open Ports']()}</span>
							<div class="flex flex-wrap gap-1 mt-1">
								{#if parsedPorts.length > 0}
									{#each parsedPorts as p}
										<span class="service-badge">{p.port}{p.service ? '/' + p.service : ''}</span>
									{/each}
								{:else}
									<span class="text-xs text-muted italic">{m['scaninfo.No Ports']()}</span>
								{/if}
							</div>
						</div>
						{#if device.prometheus_url}
							<div class="scan-info-field">
								<span class="scan-info-label">{m['scaninfo.Prometheus URL']()}</span>
								<a href={device.prometheus_url} target="_blank" rel="noopener" class="text-primary hover:underline font-mono text-xs">{device.prometheus_url}</a>
							</div>
						{/if}
						{#if device.node_exporter_url}
							<div class="scan-info-field">
								<span class="scan-info-label">{m['scaninfo.Node Exporter URL']()}</span>
								<a href={device.node_exporter_url} target="_blank" rel="noopener" class="text-primary hover:underline font-mono text-xs">{device.node_exporter_url}</a>
							</div>
						{/if}
						{#if device.last_scan_rtt_ms && device.last_scan_rtt_ms > 0}
							<div class="scan-info-field">
								<span class="scan-info-label">{m['scaninfo.Last Scan RTT']()}</span>
								<span class="scan-info-value">{m['scaninfo.Scan RTT Value']({ rtt: device.last_scan_rtt_ms })}</span>
							</div>
						{/if}
						{/if}

					</div>
				{:else}
					<p class="text-xs text-muted italic">{m['scaninfo.Never Scanned']()}</p>
				{/if}
			</div>

			<!-- Prometheus Labels Panel -->
			<div class="scan-info-panel">
				<h3 class="scan-info-title">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
					{m['labels.Per Device Labels']()}
				</h3>
				<LabelEditor
					labels={parseLabels(device.prometheus_labels)}
					onSave={handleSaveLabels}
				/>
			</div>
		</div>
	{/if}

	<!-- Scan Discovery Attributes (from scan_attributes JSON) -->
	{#if device?.scan_attributes}
		{@const sa = device.scan_attributes}
		{@const extras = (sa.extras ?? {}) as Record<string, string>}
		{@const hasDiscoveryData = Boolean(
			sa.vendor || sa.mac || sa.hostname || sa.os || sa.os_version ||
			sa.kernel_version || sa.firmware_version || sa.cpu_count ||
			sa.memory_total_bytes || sa.uptime_seconds || sa.inferred_type ||
			sa.inferred_description || (sa.snmp && (sa.snmp.sys_descr || sa.snmp.sys_object_id)) ||
			extras['mdns_services'] || extras['mdns_model'] || extras['mdns_vendor'] ||
			extras['ssdp_server'] || extras['ssdp_location'] || extras['netbios_workgroup']
		)}
		{#if hasDiscoveryData}
			<div class="scan-info-panel mt-4">
				<h3 class="scan-info-title">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1.06 6.7 2.82L21 8"/><path d="M21 3v5h-5"/></svg>
					{m['scanfields.Discovery']()}
				</h3>
				<div class="scan-info-grid">
					{#if sa.vendor}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Vendor']()}</span><span class="scan-info-value">{sa.vendor}</span></div>{/if}
					{#if sa.mac}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.MAC']()}</span><span class="scan-info-value font-mono text-xs">{sa.mac}</span></div>{/if}
					{#if sa.hostname}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Hostname']()}</span><span class="scan-info-value">{sa.hostname}</span></div>{/if}
					{#if sa.os || sa.os_version}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.OS']()}</span><span class="scan-info-value">{[sa.os, sa.os_version].filter(Boolean).join(' ')}</span></div>{/if}
					{#if sa.kernel_version}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Kernel']()}</span><span class="scan-info-value font-mono text-xs">{sa.kernel_version}</span></div>{/if}
					{#if sa.firmware_version}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Firmware']()}</span><span class="scan-info-value">{sa.firmware_version}</span></div>{/if}
					{#if sa.cpu_count}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.CPU']()}</span><span class="scan-info-value">{m['scanfields.CPU Value']({ count: sa.cpu_count })}</span></div>{/if}
					{#if sa.memory_total_bytes}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Memory']()}</span><span class="scan-info-value">{formatBytes(sa.memory_total_bytes)}</span></div>{/if}
					{#if sa.uptime_seconds}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Uptime']()}</span><span class="scan-info-value">{formatDuration(sa.uptime_seconds)}</span></div>{/if}
					{#if sa.inferred_type}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Inferred Type']()}</span><span class="scan-info-value">{sa.inferred_type}</span></div>{/if}
					{#if sa.inferred_description}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Description']()}</span><span class="scan-info-value">{sa.inferred_description}</span></div>{/if}
					{#if sa.snmp && (sa.snmp.sys_descr || sa.snmp.sys_object_id)}
						<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.SNMP']()}</span><span class="scan-info-value text-xs">{sa.snmp.sys_name ? sa.snmp.sys_name + ' — ' : ''}{sa.snmp.sys_descr ?? sa.snmp.sys_object_id ?? ''}</span></div>
					{/if}
					{#if extras['mdns_services']}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.mDNS Services']()}</span><span class="scan-info-value text-xs">{extras['mdns_services']}</span></div>{/if}
					{#if extras['mdns_model'] || extras['mdns_md']}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Model']()}</span><span class="scan-info-value text-xs">{extras['mdns_model'] ?? extras['mdns_md']}</span></div>{/if}
					{#if extras['ssdp_server']}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.SSDP']()}</span><span class="scan-info-value text-xs">{extras['ssdp_server']}</span></div>{/if}
					{#if extras['netbios_workgroup']}<div class="scan-info-field"><span class="scan-info-label">{m['scanfields.Workgroup']()}</span><span class="scan-info-value text-xs">{extras['netbios_workgroup']}</span></div>{/if}
				</div>
			</div>
		{/if}
	{/if}

	<!-- User Attributes (free-form key/value, user-editable) -->
	{#if device}
		<div class="scan-info-panel mt-4">
			<h3 class="scan-info-title">
				<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7V4h16v3"/><path d="M9 20h6"/><path d="M12 4v16"/></svg>
				{m['userfields.Custom Attributes']()}
			</h3>
			<LabelEditor
				labels={device.user_attributes ?? {}}
				onSave={handleSaveUserAttributes}
			/>
		</div>
	{/if}


	<!-- Systems section header -->
	<div class="flex items-center justify-between mb-4 mt-8">
		<h3 class="text-lg font-semibold text-text">
			{m['systems.Systems']()} <span class="text-muted font-normal text-sm">({total})</span>
		</h3>
		<div class="flex gap-3">
			<select
				bind:value={categoryFilter}
				onchange={applyFilter}
				class="input"
			>
				<option value="">{m['systems.All Categories']()}</option>
				<option value="web_app">{m['systems.Web Application']()}</option>
				<option value="database">{m['systems.Database']()}</option>
				<option value="middleware">{m['systems.Middleware']()}</option>
				<option value="custom">{m['systems.Custom']()}</option>
			</select>
			<button
				onclick={openCreate}
				class="btn btn-primary"
			>
				+ {m['systems.Create System']()}
			</button>
		</div>
	</div>

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite">
			{error}
		</div>
	{/if}

	<!-- Loading skeleton -->
	{#if loading}
		<PageSkeleton type="table" />
{:else if systems.length === 0}
	<EmptyState
		icon={Monitor}
		title={m['systems.No Systems']()}
		description={m['systems.No Systems Desc']()}
	/>
	{:else}
		<!-- Card grid -->
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each systems as system (system.id)}
				<SystemCard
					{system}
					onEdit={() => openEdit(system)}
					onDelete={() => { deleteTarget = system; deleteOpen = true; }}
				/>
			{/each}
		</div>

		<Pagination {total} {limit} {offset} onPageChange={(o) => { offset = o; fetchSystems(); }} />
	{/if}

	<!-- Heartbeat Trend Section -->
	<div class="mt-10">
		<div class="flex items-center justify-between mb-4">
			<h3 class="text-lg font-semibold text-text">
				<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 inline-block mr-1.5 text-primary align-text-bottom" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
				{m['heartbeat.Trend Title']()}
			</h3>
			{#if !heartbeatConfigLoading && heartbeatConfigs.length === 0 && device?.ip_address}
				<button
					onclick={createDefaultHeartbeatConfig}
					disabled={creatingHeartbeat}
					class="btn btn-primary"
				>
					{creatingHeartbeat ? '...' : m['heartbeat.Create Config']()}
				</button>
			{/if}
		</div>

		<!-- Heartbeat Configs (discovered by the scanner) -->
		{#if !heartbeatConfigLoading && heartbeatConfigs.length > 0}
			<div class="bg-surface border border-border rounded-xl p-4 mb-4">
				<div class="flex items-center justify-between mb-3">
					<div>
						<h4 class="text-sm font-semibold text-text">{m['heartbeat.Configs Title']()}</h4>
						<p class="text-xs text-muted mt-0.5">{m['heartbeat.Configs Desc']()}</p>
					</div>
					<span class="text-xs px-2 py-0.5 rounded-full bg-primary/10 text-primary font-medium">
						{heartbeatConfigs.length}
					</span>
				</div>
				<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
					{#each heartbeatConfigs as cfg}
						<div class="flex items-start gap-2 p-2.5 rounded-lg bg-bg/50 border border-border/60">
							<span class="shrink-0 mt-0.5 inline-flex items-center justify-center w-12 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide
								{cfg.method === 'icmp' ? 'bg-accent/15 text-accent'
								: cfg.method === 'tcp' ? 'bg-primary/15 text-primary'
								: cfg.method === 'http' ? 'bg-success/15 text-success'
								: 'bg-accent-purple/15 text-accent-purple'}">
								{cfg.method}
							</span>
							<div class="min-w-0 flex-1">
								<div class="font-mono text-xs text-text truncate" title={cfg.target}>{cfg.target}</div>
								<div class="flex items-center gap-2 mt-0.5 text-[11px] text-muted">
									<span>{m['heartbeat.Interval']()}: {cfg.interval_seconds}{m['heartbeat.Seconds Short']()}</span>
									<span>·</span>
									<span>{m['heartbeat.Timeout']()}: {cfg.timeout_seconds}{m['heartbeat.Seconds Short']()}</span>
									{#if cfg.enabled === 0}
										<span class="px-1 py-0 rounded bg-error/10 text-error font-medium">{m['heartbeat.Disabled Badge']()}</span>
									{/if}
								</div>
							</div>
							<div class="shrink-0 flex items-center gap-1 mt-0.5">
								<button
									type="button"
									onclick={() => openEditConfig(cfg)}
									class="p-1 rounded text-muted hover:text-primary hover:bg-primary/10 transition-colors"
									aria-label={m['heartbeat.Edit Config']()}
									title={m['heartbeat.Edit Config']()}
								>
									<svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
								</button>
								<button
									type="button"
									onclick={() => { deletingConfigId = cfg.id; }}
									class="p-1 rounded text-muted hover:text-error hover:bg-error/10 transition-colors"
									aria-label={m['heartbeat.Delete Config']()}
									title={m['heartbeat.Delete Config']()}
								>
									<svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
								</button>
							</div>
						</div>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Time range selector -->
		<div class="flex flex-wrap items-center gap-2 mb-4">
			{#each ['1h', '6h', '24h', '7d', '30d'] as preset}
				<button
					onclick={() => { trendPreset = preset; fetchHeartbeatTrend(); }}
					class="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors
						{trendPreset === preset
							? 'bg-primary text-inverse'
							: 'bg-surface border border-border text-muted hover:text-text hover:border-primary'}"
				>
					{m[`heartbeat.Last ${preset}` as keyof typeof m]()}
				</button>
			{/each}
			<div class="flex items-center gap-2 ml-2">
				<input
					type="datetime-local"
					bind:value={trendFrom}
					class="input px-2 py-1.5 text-xs"
				/>
				<span class="text-muted text-xs">~</span>
				<input
					type="datetime-local"
					bind:value={trendTo}
					class="input px-2 py-1.5 text-xs"
				/>
				<button
					onclick={() => { trendPreset = 'custom'; fetchHeartbeatTrend(); }}
					disabled={!trendFrom || !trendTo}
					class="px-3 py-1.5 rounded-lg text-xs font-medium bg-surface border border-border text-muted
						hover:text-text hover:border-primary disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
				>
					{m['common.Filter']()}
				</button>
			</div>
		</div>

		<!-- Stats cards -->
		{#if trendStats}
			{@const totalChecks = trendStats.success_count + trendStats.fail_count + trendStats.timeout_count}
			{@const successRate = totalChecks > 0 ? ((trendStats.success_count / totalChecks) * 100).toFixed(1) : '0.0'}
			<div class="grid grid-cols-3 gap-3 mb-4">
				<div class="trend-stat-card">
					<div class="trend-stat-label">{m['heartbeat.Avg Latency']()}</div>
					<div class="trend-stat-value" style="color: var(--color-primary)">
						{trendStats.avg_latency_ms.toFixed(1)}<span class="trend-stat-unit">{m['heartbeat.ms']()}</span>
					</div>
				</div>
				<div class="trend-stat-card">
					<div class="trend-stat-label">{m['heartbeat.Success Rate']()}</div>
					<div class="trend-stat-value" style="color: var(--color-success)">
						{successRate}<span class="trend-stat-unit">%</span>
					</div>
				</div>
				<div class="trend-stat-card">
					<div class="trend-stat-label">{m['heartbeat.Total Checks']()}</div>
					<div class="trend-stat-value" style="color: var(--color-text)">
						{totalChecks}
					</div>
				</div>
			</div>
		{/if}

		<!-- No config warning -->
		{#if !heartbeatConfigLoading && heartbeatConfigs.length === 0 && !trendLoading}
			<div class="mb-4 px-4 py-3 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
				{m['heartbeat.NoConfig']()}: {m['heartbeat.NoConfigDesc']()}
				{#if device?.ip_address}
					<button
						onclick={createDefaultHeartbeatConfig}
						disabled={creatingHeartbeat}
						class="ml-2 px-3 py-1 bg-primary text-inverse font-semibold rounded-lg
							hover:bg-primary-hover transition-colors text-xs disabled:opacity-50"
					>
						{creatingHeartbeat ? '...' : m['heartbeat.Create Config']()}
					</button>
				{/if}
			</div>
		{/if}

		<!-- Chart -->

		<!-- Chart -->
		{#if trendLoading}
			<PageSkeleton type="table" />
		{:else if Object.keys(trendOption).length > 0}
			<div class="bg-surface border border-border rounded-xl p-4">
				<Chart option={trendOption} height="320px" />
			</div>
		{:else}
			<EmptyState
				icon={BarChart3}
				title={m['heartbeat.No Data']()}
				description=""
			/>
		{/if}
	</div>
</div>

<!-- Create/Edit Modal -->
<Modal bind:open={formOpen} title={editingSystem ? m['systems.Edit System']() : m['systems.Create System']()} maxWidth="36rem" onClose={resetForm}>
	{#if formError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{formError}
		</div>
	{/if}

	<form onsubmit={handleSubmit} class="space-y-4">
		<!-- Name -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['systems.System Name']()} *</label>
			<input
				bind:value={formName}
				required
				class="input"
			/>
		</div>

		<!-- Entry URL -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['systems.Entry URL']()}</label>
			<input
				bind:value={formEntryUrl}
				type="url"
				placeholder="https://..."
				class="input"
			/>
		</div>

		<!-- Description -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['systems.Description']()}</label>
			<textarea
				bind:value={formDescription}
				rows="2"
				class="input resize-y"
			></textarea>
		</div>

		<!-- Category -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['systems.Category']()}</label>
			<select
				bind:value={formCategory}
				class="input"
			>
				<option value="web_app">{m['systems.Web Application']()}</option>
				<option value="database">{m['systems.Database']()}</option>
				<option value="middleware">{m['systems.Middleware']()}</option>
				<option value="custom">{m['systems.Custom']()}</option>
			</select>
		</div>

		<!-- Metrics URL -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['systems.Metrics URL']()}</label>
			<input
				bind:value={formMetricsUrl}
				type="url"
				placeholder="https://..."
				class="input"
			/>
		</div>

		<!-- Metrics enabled -->
		<div class="flex items-center gap-2">
			<input
				type="checkbox"
				bind:checked={formMetricsEnabled}
				id="metrics-enabled"
				class="w-4 h-4 rounded border-border text-primary focus:ring-primary accent-primary"
			/>
			<label for="metrics-enabled" class="text-sm text-text">{m['systems.Enable Metrics']()}</label>
		</div>

		<!-- Tags -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['systems.Tags']()}</label>
			<input
				bind:value={formTags}
				placeholder="monitoring,production"
				class="input"
			/>
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<button type="submit" disabled={formLoading}
				class="btn btn-primary">
				{formLoading ? '...' : m['common.Save']()}
			</button>
			<button type="button" onclick={() => { formOpen = false; resetForm(); }}
				class="px-6 py-2 border border-border text-muted rounded-lg
					hover:border-primary transition-colors text-sm">
				{m['common.Cancel']()}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteOpen}
	title={m['systems.Delete System']()}
	message={`${m['common.Are you sure?']()} "${deleteTarget?.name ?? ''}"`}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>

<!-- Heartbeat config edit modal -->
<Modal
	open={editingConfig !== null}
	title={m['heartbeat.Edit Config']()}
	maxWidth="32rem"
	onClose={() => { editingConfig = null; }}
>
	{#if editingConfig}
		<form onsubmit={saveEditConfig} class="space-y-4">
			<!-- Method -->
			<div>
				<label class="block text-xs text-muted mb-1">{m['heartbeat.Method']()}</label>
				<select bind:value={editingConfig.method} class="input">
					<option value="icmp">icmp</option>
					<option value="tcp">tcp</option>
					<option value="http">http</option>
					<option value="snmp">snmp</option>
				</select>
			</div>

			<!-- Target -->
			<div>
				<label class="block text-xs text-muted mb-1">{m['heartbeat.Target']()}</label>
				<input bind:value={editingConfig.target} required class="input" />
			</div>

			<!-- Interval seconds -->
			<div>
				<label class="block text-xs text-muted mb-1">{m['heartbeat.Interval Seconds']()}</label>
				<input type="number" min="1" bind:value={editingConfig.interval_seconds} required class="input" />
			</div>

			<!-- Timeout seconds -->
			<div>
				<label class="block text-xs text-muted mb-1">{m['heartbeat.Timeout Seconds']()}</label>
				<input type="number" min="1" bind:value={editingConfig.timeout_seconds} required class="input" />
			</div>

			<!-- Enabled -->
			<div class="flex items-center gap-2">
				<input
					type="checkbox"
					checked={editingConfig.enabled !== 0}
					onchange={(e) => { editingConfig!.enabled = e.currentTarget.checked ? 1 : 0; }}
					id="config-enabled"
					class="w-4 h-4 rounded border-border text-primary focus:ring-primary accent-primary"
				/>
				<label for="config-enabled" class="text-sm text-text">{m['heartbeat.Enabled Toggle']()}</label>
			</div>

			<!-- Actions -->
			<div class="flex gap-3 pt-2">
				<button type="submit" disabled={editConfigLoading} class="btn btn-primary">
					{editConfigLoading ? '...' : m['common.Save']()}
				</button>
				<button type="button" onclick={() => { editingConfig = null; }}
					class="px-6 py-2 border border-border text-muted rounded-lg
						hover:border-primary transition-colors text-sm">
					{m['common.Cancel']()}
				</button>
			</div>
		</form>
	{/if}
</Modal>

<!-- Heartbeat config delete confirmation -->
<ConfirmDialog
	open={deletingConfigId !== null}
	title={m['heartbeat.Delete Config']()}
	message={m['heartbeat.Delete Confirm']()}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={() => {
		if (deletingConfigId !== null) {
			const cfg = heartbeatConfigs.find((c) => c.id === deletingConfigId);
			if (cfg) deleteConfig(cfg);
		}
	}}
	onCancel={() => { deletingConfigId = null; }}
/>

<style>
	.device-info-header {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 1rem 1.25rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 0.75rem;
	}

	@media (max-width: 480px) {
		.device-info-header {
			padding: 0.75rem;
		}
	}

	.device-meta {
		display: flex;
		flex-wrap: wrap;
		gap: 1rem;
		padding-left: 1.5rem;
	}

	@media (max-width: 480px) {
		.device-meta {
			gap: 0.5rem;
			padding-left: 1.25rem;
		}
	}

	.device-meta-item {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.8125rem;
		color: var(--color-text-muted);
	}

	.trend-stat-card {
		padding: 0.75rem 1rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 0.625rem;
	}

	.trend-stat-label {
		font-size: 0.6875rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.25rem;
	}

	.trend-stat-value {
		font-size: 1.375rem;
		font-weight: 700;
		font-family: var(--font-mono);
		line-height: 1.2;
	}

	.trend-stat-unit {
		font-size: 0.6875rem;
		font-weight: 400;
		margin-left: 0.25rem;
		opacity: 0.6;
	}

	@media (max-width: 640px) {
		.trend-stat-value {
			font-size: 1.125rem;
		}
	}
	.scan-info-panel {
		padding: 1rem 1.25rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: 0.75rem;
	}

	.scan-info-title {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.9375rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0 0 0.75rem;
	}

	.scan-info-grid {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
	}

	.scan-info-field {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
	}

	.scan-info-label {
		font-size: 0.6875rem;
		color: var(--color-text-muted);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.scan-info-value {
		font-size: 0.8125rem;
		color: var(--color-text);
	}

	.scan-info-source-badge {
		display: inline-block;
		width: fit-content;
		padding: 0.125rem 0.5rem;
		font-size: 0.75rem;
		font-weight: 500;
		border-radius: 9999px;
	}

	.scan-source-scanner {
		background: rgba(16, 185, 129, 0.15);
		color: var(--color-success);
	}

	.scan-source-manual {
		background: rgba(129, 140, 248, 0.15);
		color: var(--color-accent);
	}

	.service-badge {
		display: inline-block;
		padding: 0.0625rem 0.5rem;
		font-size: 0.6875rem;
		font-weight: 500;
		border-radius: 9999px;
		background: rgba(99, 102, 241, 0.12);
		color: var(--color-accent);
		border: 1px solid rgba(99, 102, 241, 0.2);
	}

</style>
