<script lang="ts">
	import { onMount } from 'svelte';
	import { writable } from 'svelte/store';
	import Chart from '$lib/components/Chart.svelte';
	import DashboardWidget from '$lib/components/DashboardWidget.svelte';
	import WidgetPicker from '$lib/components/WidgetPicker.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { Plus, RotateCw, Puzzle, BarChart3 } from '@lucide/svelte';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { auth } from '$lib/stores/auth';
	import type { EChartsOption } from '$lib/charts/echarts';

	interface DeviceStats {
		by_status: { online: number; offline: number; unknown: number };
	}

	interface Device {
		id: string;
		name: string;
		type: string;
		location: string;
		status: string;
	}

	interface DevicesResponse {
		devices: Device[];
		total: number;
	}

	// Overview mirrors GET /dashboard/overview — the aggregated payload that
	// feeds the type/location distributions (full population, not a 200-row
	// sample), scan activity, and the offline-device list.
	interface OverviewScanRun {
		id: number; task_id: number; status: string;
		total_hosts: number; alive_hosts: number; new_hosts: number;
		duration_ms: number; error_message?: string;
		started_at?: string; finished_at?: string;
	}
	interface OverviewDevice {
		id: number; name: string; ip_address: string;
		type: string; status: string; last_scanned_at?: string;
	}
	interface OverviewResponse {
		devices: {
			total: number; online: number; offline: number; unknown: number; online_rate: number;
			by_type: Record<string, number>;
			by_location: Record<string, number>;
		};
		scanning: {
			tasks_total: number; runs_total: number;
			recent_runs: OverviewScanRun[];
			runs_by_status: Record<string, number>;
			last_discovery?: OverviewScanRun;
		};
		abnormal: OverviewDevice[];
		generated: string;
	}

	interface DashboardConfig {
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

	interface DashboardConfigsResponse {
		configs: DashboardConfig[];
		total: number;
	}

	interface WidgetState {
		id: string;
		name: string;
		type: string;
		data_source: string;
		query: string;
		refresh_interval: number;
		position: number;
		chartOption: EChartsOption;
		loading: boolean;
		created_at: string;
		updated_at: string;
	}

	// loading is a writable store (not $state). A bare {#if loading} backed by
	// $state failed to re-evaluate under prerender hydration — the {#if}'s
	// dependency subscription never fired on the true→false transition, even
	// though the assignment happened (verified via console). Other $state vars
	// (overview/stats) in the same component updated fine, so this is specific
	// to the {#if <state-var>} re-evaluation path. A store with the $ prefix
	// ($loading) uses Svelte's long-stable auto-subscription, which reliably
	// re-renders. (devices/+page.svelte uses $state loading and works — the
	// difference is unrooted in Svelte 5 runes hydration; the store sidesteps it.)
	const loading = writable(true);
	let refreshing = $state(false);
	let lastUpdated = $state<Date | null>(null);
	let stats = $state<DeviceStats | null>(null);
	let devices = $state<Device[]>([]);
	let overview = $state<OverviewResponse | null>(null);
	let widgets = $state<WidgetState[]>([]);
	let useCustomLayout = $state(false);
	// isAdmin is derived from the $auth store. The previous implementation kept
	// it as a $state updated by a top-level auth.subscribe() that never
	// unsubscribed — that subscription during component init poisoned Svelte 5's
	// effect scheduler under hydration and froze the DOM on the loading skeleton
	// (data loaded, $state set, but no re-render). Deriving from $auth directly
	// aligns with how +layout.svelte already consumes the store.
	let isAdmin = $derived($auth.user?.role === 'admin');

	let pickerOpen = $state(false);
	let editingWidget = $state<DashboardConfig | null>(null);
	let confirmOpen = $state(false);
	let removingWidgetId = $state<string | null>(null);

	let draggedId: string | null = $state(null);
	let refreshTimers: ReturnType<typeof setInterval>[] = [];

	function getCSSVar(name: string, fallback: string): string {
		return getComputedStyle(document.documentElement)
			.getPropertyValue(name)
			.trim() || fallback;
	}

	function getTextColor(): string {
		return getCSSVar('--color-text', '#e5e7eb');
	}

	function getTextMutedColor(): string {
		return getCSSVar('--color-text-muted', '#6b7280');
	}

	function getBorderColor(): string {
		return getCSSVar('--color-border', '#1f2937');
	}

	function getPrimaryColor(): string {
		return getCSSVar('--color-primary', '#6366f1');
	}

	// ── Chart builders (for default fallback layout) ──

	function buildStatusPie(data: DeviceStats): EChartsOption {
		const { online = 0, offline = 0, unknown = 0 } = data.by_status;
		const primary = getPrimaryColor();
		return {
			backgroundColor: 'transparent',
			tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
			legend: {
				orient: 'vertical',
				right: 10,
				top: 'center',
				textStyle: { color: getTextMutedColor() }
			},
			series: [{
				type: 'pie',
				radius: ['40%', '70%'],
				center: ['40%', '50%'],
				avoidLabelOverlap: false,
				itemStyle: { borderRadius: 6, borderColor: 'transparent', borderWidth: 2 },
				label: { show: false },
				emphasis: {
					label: { show: true, fontSize: 14, fontWeight: 'bold', color: getTextColor() }
				},
				data: [
					{ value: online, name: m["devices.Online"](), itemStyle: { color: primary } },
					{ value: offline, name: m["devices.Offline"](), itemStyle: { color: getCSSVar('--color-error', '#ef4444') } },
					{ value: unknown, name: m["devices.Unknown"](), itemStyle: { color: getTextMutedColor() } }
				]
			}]
		};
	}

	function buildHeartbeatGauge(data: DeviceStats): EChartsOption {
		const { online = 0, offline = 0, unknown = 0 } = data.by_status;
		const total = online + offline + unknown;
		const rate = total > 0 ? Math.round((online / total) * 100) : 0;
		const primary = getPrimaryColor();
		return {
			backgroundColor: 'transparent',
			series: [{
				type: 'gauge',
				startAngle: 200,
				endAngle: -20,
				min: 0,
				max: 100,
				splitNumber: 10,
				itemStyle: { color: primary },
				progress: { show: true, width: 18 },
				pointer: { show: false },
				axisLine: { lineStyle: { width: 18, color: [[1, getBorderColor()]] } },
				axisTick: { show: false },
				splitLine: { show: false },
				axisLabel: { show: false },
				title: { fontSize: 14, color: getTextMutedColor(), offsetCenter: [0, '70%'] },
				detail: {
					valueAnimation: true,
					fontSize: 28,
					fontWeight: 'bold',
					color: primary,
					offsetCenter: [0, '40%'],
					formatter: '{value}%'
				},
				data: [{ value: rate, name: m["heartbeat.Success"]() + ' Rate' }]
			}]
		};
	}

	function buildTypePie(byType: Record<string, number>): EChartsOption {
		// Color map keyed on the RAW type token (pc/embedded/...), NOT the
		// translated label. The old version keyed on the translated label, which
		// broke under i18n (zh label "嵌入式" never matched the "Embedded" key, so
		// every non-PC slice fell back to cyan).
		const primary = getPrimaryColor();
		const colorByType: Record<string, string> = {
			pc: primary,
			embedded: getCSSVar('--color-accent', '#818cf8'),
			iot: getCSSVar('--color-accent-purple', '#a78bfa'),
			server: getCSSVar('--color-success', '#22c55e'),
			camera: getCSSVar('--color-accent-cyan', '#67e8f9'),
			switch: '#f59e0b',
			router: '#ec4899',
			firewall: '#ef4444',
			nas: '#14b8a6',
			other: getCSSVar('--color-accent-cyan', '#67e8f9'),
			unknown: getCSSVar('--color-accent-cyan', '#67e8f9')
		};
		const typeLabel: Record<string, string> = {
			pc: m["devices.PC"](),
			embedded: m["devices.Embedded"](),
			iot: m["devices.IoT"](),
			server: m["devices.Server"]?.() ?? 'server',
			camera: m["devices.Camera"]?.() ?? 'camera',
			switch: m["devices.Switch"]?.() ?? 'switch',
			router: m["devices.Router"]?.() ?? 'router',
			firewall: m["devices.Firewall"]?.() ?? 'firewall',
			nas: m["devices.NAS"]?.() ?? 'nas',
			other: m["devices.Other"](),
			unknown: m["devices.Other"]()
		};
		// Prefer the full-population overview.by_type when available; fall back to
		// the 200-row device sample so the chart still renders if overview failed.
		const source = (overview?.devices.by_type && Object.keys(overview.devices.by_type).length > 0)
			? overview.devices.by_type
			: byType;
		const entries = Object.entries(source).sort((a, b) => b[1] - a[1]);
		const pieData = entries.map(([type, value]) => ({
			value,
			name: typeLabel[type] ?? type,
			itemStyle: { color: colorByType[type] ?? getCSSVar('--color-accent-cyan', '#67e8f9') }
		}));
		return {
			backgroundColor: 'transparent',
			tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
			legend: {
				orient: 'vertical',
				right: 10,
				top: 'center',
				textStyle: { color: getTextMutedColor() }
			},
			series: [{
				type: 'pie',
				radius: ['40%', '70%'],
				center: ['40%', '50%'],
				avoidLabelOverlap: false,
				itemStyle: { borderRadius: 6, borderColor: 'transparent', borderWidth: 2 },
				label: { show: false },
				emphasis: {
					label: { show: true, fontSize: 14, fontWeight: 'bold', color: getTextColor() }
				},
				data: pieData.length > 0
					? pieData
					: [{ value: 0, name: m["dashboard.No Data"](), itemStyle: { color: getBorderColor() } }]
			}]
		};
	}

	function buildLocationBar(devs: Device[]): EChartsOption {
		// Prefer full-population overview.by_location; fall back to the sample.
		const sample: Record<string, number> = {};
		for (const d of devs) {
			const loc = d.location || 'N/A';
			sample[loc] = (sample[loc] || 0) + 1;
		}
		const source = (overview?.devices.by_location && Object.keys(overview.devices.by_location).length > 0)
			? overview.devices.by_location
			: sample;
		const entries = Object.entries(source).sort((a, b) => b[1] - a[1]);
		const border = getBorderColor();
		const primary = getPrimaryColor();
		if (entries.length === 0) {
			return {
				backgroundColor: 'transparent',
				title: {
					text: m["dashboard.No Data"](),
					left: 'center',
					top: 'center',
					textStyle: { color: getTextMutedColor(), fontSize: 14 }
				}
			};
		}
		return {
			backgroundColor: 'transparent',
			tooltip: { trigger: 'axis' },
			grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
			xAxis: {
				type: 'category',
				data: entries.map((e) => e[0]),
				axisLabel: { color: getTextMutedColor(), fontSize: 11, rotate: 30, formatter: (v: string) => v.length > 8 ? v.substring(0, 8) + '...' : v },
				axisLine: { lineStyle: { color: border } }
			},
			yAxis: {
				type: 'value',
				axisLabel: { color: getTextMutedColor() },
				splitLine: { lineStyle: { color: `${border}40` } }
			},
			series: [{
				type: 'bar',
				data: entries.map((e) => e[1]),
				itemStyle: { color: primary, borderRadius: [4, 4, 0, 0] },
				barMaxWidth: 40
			}]
		};
	}

	// ── Prometheus → ECharts option builders ──

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	function promToGaugeOption(data: any, widgetName: string): EChartsOption {
		const value = data?.data?.result?.[0]?.value?.[1]
			? parseFloat(data.data.result[0].value[1])
			: 0;
		const primary = getPrimaryColor();
		return {
			backgroundColor: 'transparent',
			series: [{
				type: 'gauge',
				startAngle: 200,
				endAngle: -20,
				min: 0,
				max: 100,
				splitNumber: 10,
				itemStyle: { color: primary },
				progress: { show: true, width: 18 },
				pointer: { show: false },
				axisLine: { lineStyle: { width: 18, color: [[1, getBorderColor()]] } },
				axisTick: { show: false },
				splitLine: { show: false },
				axisLabel: { show: false },
				title: { fontSize: 14, color: getTextMutedColor(), offsetCenter: [0, '70%'] },
				detail: {
					valueAnimation: true,
					fontSize: 28,
					fontWeight: 'bold',
					color: primary,
					offsetCenter: [0, '40%'],
					formatter: '{value}'
				},
				data: [{ value: isNaN(value) ? 0 : Math.round(value), name: widgetName }]
			}]
		};
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	function promToLineOption(data: any, widgetName: string): EChartsOption {
		const result = data?.data?.result?.[0];
		const primary = getPrimaryColor();
		const border = getBorderColor();
		if (!result?.values?.length) {
			return {
				backgroundColor: 'transparent',
				title: { text: m["dashboard.No Data"](), left: 'center', top: 'center', textStyle: { color: getTextMutedColor(), fontSize: 14 } }
			};
		}
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const times = result.values.map((v: any) => new Date(v[0] * 1000).toLocaleTimeString());
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const values = result.values.map((v: any) => parseFloat(v[1]));
		return {
			backgroundColor: 'transparent',
			tooltip: { trigger: 'axis' },
			grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
			xAxis: { type: 'category', data: times, axisLabel: { color: getTextMutedColor(), fontSize: 10 }, axisLine: { lineStyle: { color: border } } },
			yAxis: { type: 'value', axisLabel: { color: getTextMutedColor() }, splitLine: { lineStyle: { color: `${border}40` } } },
			series: [{ type: 'line', data: values, smooth: true, itemStyle: { color: primary }, lineStyle: { width: 2 } }]
		};
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	function promToBarOption(data: any, widgetName: string): EChartsOption {
		const results = data?.data?.result || [];
		const primary = getPrimaryColor();
		const border = getBorderColor();
		if (results.length === 0) {
			return {
				backgroundColor: 'transparent',
				title: { text: m["dashboard.No Data"](), left: 'center', top: 'center', textStyle: { color: getTextMutedColor(), fontSize: 14 } }
			};
		}
		const labels = results.map((r: { metric: { [key: string]: string } }) => r.metric.__name__ || r.metric.job || widgetName);
		const values = results.map((r: { value: [number, string] }) => parseFloat(r.value[1]));
		return {
			backgroundColor: 'transparent',
			tooltip: { trigger: 'axis' },
			grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
			xAxis: { type: 'category', data: labels, axisLabel: { color: getTextMutedColor(), fontSize: 10 }, axisLine: { lineStyle: { color: border } } },
			yAxis: { type: 'value', axisLabel: { color: getTextMutedColor() }, splitLine: { lineStyle: { color: `${border}40` } } },
			series: [{ type: 'bar', data: values, itemStyle: { color: primary, borderRadius: [4, 4, 0, 0] }, barMaxWidth: 40 }]
		};
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	function promToPieOption(data: any, widgetName: string): EChartsOption {
		const results = data?.data?.result || [];
		if (results.length === 0) {
			return {
				backgroundColor: 'transparent',
				title: { text: m["dashboard.No Data"](), left: 'center', top: 'center', textStyle: { color: getTextMutedColor(), fontSize: 14 } }
			};
		}
		const palette = ['#6366f1', '#818cf8', '#a78bfa', '#67e8f9', '#f59e0b', '#ef4444', '#10b981'];
		const pieData = results.map((r: { metric: { [key: string]: string }; value: [number, string] }, i: number) => ({
			value: parseFloat(r.value[1]),
			name: r.metric.__name__ || r.metric.job || `${widgetName} ${i + 1}`,
			itemStyle: { color: palette[i % palette.length] }
		}));
		return {
			backgroundColor: 'transparent',
			tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
			legend: {
				orient: 'vertical',
				right: 10,
				top: 'center',
				textStyle: { color: getTextMutedColor() }
			},
			series: [{
				type: 'pie',
				radius: ['40%', '70%'],
				center: ['40%', '50%'],
				avoidLabelOverlap: false,
				itemStyle: { borderRadius: 6, borderColor: 'transparent', borderWidth: 2 },
				label: { show: false },
				emphasis: {
					label: { show: true, fontSize: 14, fontWeight: 'bold', color: getTextColor() }
				},
				data: pieData
			}]
		};
	}

	// ── Data fetching ──

	async function fetchCustomWidgets() {
		try {
			const res = await api.get<DashboardConfigsResponse>('/dashboard/configs');
			if (res.configs && res.configs.length > 0) {
				useCustomLayout = true;
				widgets = res.configs
					.sort((a, b) => a.position - b.position)
					.map((cfg) => ({
						id: cfg.id,
						name: cfg.name,
						type: cfg.type,
						data_source: cfg.data_source,
						query: cfg.query,
						refresh_interval: cfg.refresh_interval,
						position: cfg.position,
						chartOption: {} as EChartsOption,
						loading: true,
						created_at: cfg.created_at,
						updated_at: cfg.updated_at
					}));
				// Fetch data for each widget
				await Promise.all(widgets.map((w) => refreshWidgetData(w)));
			} else {
				useCustomLayout = false;
				widgets = [];
			}
		} catch {
			useCustomLayout = false;
			widgets = [];
		}
	}

	async function refreshWidgetData(w: WidgetState) {
		try {
			const now = Math.floor(Date.now() / 1000);
			let chartOption: EChartsOption;

			if (w.type === 'line') {
				const data = await api.get(`/dashboard/query_range?query=${encodeURIComponent(w.query)}&start=${now - 3600}&end=${now}&step=60`);
				chartOption = promToLineOption(data, w.name);
			} else {
				const data = await api.get(`/dashboard/query?query=${encodeURIComponent(w.query)}&time=${now}`);
				if (w.type === 'gauge') chartOption = promToGaugeOption(data, w.name);
				else if (w.type === 'bar') chartOption = promToBarOption(data, w.name);
				else chartOption = promToPieOption(data, w.name);
			}

			const idx = widgets.findIndex((x) => x.id === w.id);
			if (idx >= 0) {
				widgets[idx] = { ...widgets[idx], chartOption, loading: false };
			}
		} catch {
			const idx = widgets.findIndex((x) => x.id === w.id);
			if (idx >= 0) {
				widgets[idx] = { ...widgets[idx], loading: false };
			}
		}
	}

	async function fetchDefaultData() {
		// stats (status pie + gauge) + overview (full-population type/location
		// distributions, scan activity, offline list) load in parallel. overview
		// is in its own try so a failure there doesn't blank the legacy charts.
		try {
			const [statsRes, devsRes] = await Promise.all([
				api.get<DeviceStats>('/devices/stats'),
				api.get<DevicesResponse>('/devices?limit=200')
			]);
			stats = statsRes;
			devices = devsRes.devices || [];
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
			stats = { by_status: { online: 0, offline: 0, unknown: 0 } };
			devices = [];
		}
		try {
			overview = await api.get<OverviewResponse>('/dashboard/overview');
		} catch {
			// Non-fatal: legacy charts still render; type/location pies fall back
			// to the 200-row sample, scan/offline sections render empty.
			overview = null;
		}
	}

	// loadAll is async and toggles loading itself (in finally). The caller
	// (onMount) fires it WITHOUT await: under prerender hydration, an awaited
	// async onMount's post-await $state writes (e.g. loading=false) didn't
	// re-render the {#if loading} block — the await moves the write out of
	// Svelte's effect-scheduling context. Mirrors the working devices-page
	// pattern (sync onMount + fire-and-forget fetch with internal loading toggle).
	async function loadAll() {
		// Re-assert loading=true at the start of every load. devices-page does
		// the same in fetchDevices — the explicit write (even when already true)
		// is what establishes Svelte's dependency subscription for the {#if}
		// block under prerender hydration; without it the initial true→false
		// transition didn't re-render.
		loading.set(true);
		try {
			await fetchCustomWidgets();
			if (!useCustomLayout) {
				await fetchDefaultData();
			}
			lastUpdated = new Date();
		} finally {
			loading.set(false);
		}
	}

	function setupRefreshTimers() {
		clearRefreshTimers();
		if (useCustomLayout) {
			for (const w of widgets) {
				if (w.refresh_interval > 0) {
					const timer = setInterval(() => refreshWidgetData(w), w.refresh_interval * 1000);
					refreshTimers.push(timer);
				}
			}
		} else {
			const timer = setInterval(loadAll, 30000);
			refreshTimers.push(timer);
		}
	}

	function clearRefreshTimers() {
		for (const t of refreshTimers) clearInterval(t);
		refreshTimers = [];
	}

	// ── Drag and drop ──

	function handleDragStart(_e: DragEvent, id: string) {
		draggedId = id;
	}

	function handleDragOver(_e: DragEvent) {
		// needed for drop to fire
	}

	function handleDrop(_e: DragEvent, targetId: string) {
		if (!draggedId || draggedId === targetId) return;

		const fromIdx = widgets.findIndex((w) => w.id === draggedId);
		const toIdx = widgets.findIndex((w) => w.id === targetId);
		if (fromIdx < 0 || toIdx < 0) return;

		// Swap
		const updated = [...widgets];
		const temp = updated[fromIdx];
		updated[fromIdx] = updated[toIdx];
		updated[toIdx] = temp;

		// Update positions
		widgets = updated.map((w, i) => ({ ...w, position: i }));

		// Persist positions
		if (isAdmin) {
			for (const w of widgets) {
				api.put(`/dashboard/configs/${w.id}`, { position: w.position }).catch(() => {
					// silent fail — positions are best-effort
				});
			}
		}

		draggedId = null;
	}

	// ── Widget actions ──

	function handleAddWidget() {
		editingWidget = null;
		pickerOpen = true;
	}

	function handleEditWidget(id: string) {
		const w = widgets.find((x) => x.id === id);
		if (w) {
			editingWidget = {
				id: w.id,
				name: w.name,
				type: w.type,
				data_source: w.data_source,
				query: w.query,
				refresh_interval: w.refresh_interval,
				position: w.position,
				created_at: w.created_at,
				updated_at: w.updated_at
			};
			pickerOpen = true;
		}
	}

	function handleRemoveWidget(id: string) {
		removingWidgetId = id;
		confirmOpen = true;
	}

	async function confirmRemoveWidget() {
		if (!removingWidgetId) return;
		try {
			await api.delete(`/dashboard/configs/${removingWidgetId}`);
			addToast('success', m["dashboard.Widget Deleted"]());
			await loadAll();
			setupRefreshTimers();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	async function onWidgetSaved() {
		await loadAll();
		setupRefreshTimers();
	}

	function handleRefresh() {
		refreshing = true;
		loadAll().finally(() => {
			refreshing = false;
			setupRefreshTimers();
		});
	}

	// ── Lifecycle ──
	// (The top-level auth.subscribe that used to live here was removed — see the
	// note above isAdmin. The $auth store is consumed directly in the markup.)

	onMount(() => {
		// Fire-and-forget: loadAll toggles loading=false in its own finally so the
		// {#if loading} block re-renders correctly under hydration.
		void loadAll();
		setupRefreshTimers();
		return clearRefreshTimers;
	});
</script>

<div class="p-4 md:p-8">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6 md:mb-8 gap-4">
		<div class="flex items-center gap-4 min-w-0">
			<h2 class="text-2xl font-bold text-primary">{m["dashboard.Dashboard"]()}</h2>
			{#if lastUpdated}
				<span class="text-xs text-muted whitespace-nowrap">
					{lastUpdated.toLocaleTimeString()}
				</span>
			{/if}
			{#if useCustomLayout}
				<span class="text-xs text-muted px-2 py-0.5 rounded bg-border">
					{m["dashboard.Config"]()}
				</span>
			{:else}
				<span class="text-xs text-muted px-2 py-0.5 rounded bg-border">
					{m["dashboard.Default Layout"]()}
				</span>
			{/if}
		</div>
		<div class="flex items-center gap-2">
			{#if isAdmin}
				<button
					onclick={handleAddWidget}
					class="btn btn-secondary shrink-0"
				>
					<Plus class="w-4 h-4" />
					<span>{m["dashboard.Add Widget"]()}</span>
				</button>
			{/if}
			<button
				onclick={handleRefresh}
				disabled={refreshing}
				class="btn btn-primary shrink-0"
			>
				<RotateCw class="w-4 h-4 {refreshing ? 'animate-spin' : ''}" />
				<span>{m["dashboard.Refresh"]()}</span>
			</button>
		</div>
	</div>

	{#if useCustomLayout}
		<!-- Custom widget layout with drag-and-drop -->
		{#if widgets.length === 0}
			<EmptyState
				icon={Puzzle}
				title={m["dashboard.No Widgets"]()}
				description={m["dashboard.No Widgets Desc"]()}
				actionLabel={isAdmin ? m["dashboard.Add Widget"]() : undefined}
				onAction={isAdmin ? handleAddWidget : undefined}
			/>
		{:else}
			{#if isAdmin}
				<p class="text-xs text-muted mb-3">{m["dashboard.Drag to Reorder"]()}</p>
			{/if}
			<div class="widget-grid">
				{#each widgets as widget (widget.id)}
					<DashboardWidget
						{widget}
						onEdit={handleEditWidget}
						onRemove={handleRemoveWidget}
						ondragstart={handleDragStart}
						ondragover={handleDragOver}
						ondrop={handleDrop}
					/>
				{/each}
			</div>
		{/if}
	{:else if devices.length === 0 && stats && stats.by_status.online + stats.by_status.offline + stats.by_status.unknown === 0}
		<EmptyState
			icon={BarChart3}
			title={m["dashboard.No Data"]()}
			description={m["devices.No Devices Desc"]()}
			actionLabel={m["devices.Create Device"]()}
		/>
	{:else}
		<!-- Default 2x2 Chart Grid -->
		<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
			<!-- Device Status Distribution (Pie) -->
			<div class="bg-surface border border-border rounded-lg overflow-hidden">
				<div class="px-4 py-3 border-b border-border">
					<h3 class="text-sm font-semibold text-text">{m["dashboard.Device Status Distribution"]()}</h3>
				</div>
				<div class="p-2 md:p-4 h-[200px] md:h-[280px]">
					<Chart option={buildStatusPie(stats || { by_status: { online: 0, offline: 0, unknown: 0 } })} height="100%" />
				</div>
			</div>

			<!-- Heartbeat Success Rate (Gauge) -->
			<div class="bg-surface border border-border rounded-lg overflow-hidden">
				<div class="px-4 py-3 border-b border-border">
					<h3 class="text-sm font-semibold text-text">{m["dashboard.Heartbeat Success Rate"]()}</h3>
				</div>
				<div class="p-2 md:p-4 h-[200px] md:h-[280px]">
					<Chart option={buildHeartbeatGauge(stats || { by_status: { online: 0, offline: 0, unknown: 0 } })} height="100%" />
				</div>
			</div>

			<!-- Device Type Distribution (Pie) -->
			<div class="bg-surface border border-border rounded-lg overflow-hidden">
				<div class="px-4 py-3 border-b border-border">
					<h3 class="text-sm font-semibold text-text">{m["dashboard.Device Type Distribution"]()}</h3>
				</div>
				<div class="p-2 md:p-4 h-[200px] md:h-[280px]">
					<Chart option={buildTypePie(overview?.devices.by_type ?? {})} height="100%" />
				</div>
			</div>

			<!-- Device Count by Location (Bar) -->
			<div class="bg-surface border border-border rounded-lg overflow-hidden">
				<div class="px-4 py-3 border-b border-border">
					<h3 class="text-sm font-semibold text-text">{m["dashboard.Device Count by Location"]()}</h3>
				</div>
				<div class="p-2 md:p-4 h-[200px] md:h-[280px]">
					<Chart option={buildLocationBar(devices)} height="100%" />
				</div>
			</div>

			<!-- Scan Activity — reflects "discovery", the system's core job -->
			<div class="bg-surface border border-border rounded-lg overflow-hidden md:col-span-2">
				<div class="px-4 py-3 border-b border-border flex items-center justify-between">
					<h3 class="text-sm font-semibold text-text">{m["dashboard.Scan Activity"]()}</h3>
					{#if overview?.scanning.last_discovery}
						<span class="text-xs text-muted">
							{m["dashboard.Last Discovery"]()}:
							<strong class="text-success ml-1">{overview.scanning.last_discovery.alive_hosts}/{overview.scanning.last_discovery.total_hosts}</strong>
						</span>
					{/if}
				</div>
				<div class="p-4">
					{#if overview?.scanning.recent_runs.length}
						<div class="overflow-x-auto">
							<table class="w-full text-sm">
								<thead>
									<tr class="text-left text-xs text-muted border-b border-border">
										<th class="py-2 pr-3">#</th>
										<th class="py-2 pr-3">{m["common.Status"]()}</th>
										<th class="py-2 pr-3 tabular-nums">{m["devices.Alive"]()}</th>
										<th class="py-2 pr-3 tabular-nums">{m["scanner.New"]()}</th>
										<th class="py-2 pr-3 tabular-nums">{m["scanner.Duration"]()}</th>
									</tr>
								</thead>
								<tbody>
									{#each overview.scanning.recent_runs as run}
										<tr class="border-b border-border/50 last:border-0">
											<td class="py-2 pr-3 font-mono text-xs">#{run.id}</td>
											<td class="py-2 pr-3">
												<span class="inline-flex items-center gap-1 {run.status === 'completed' ? 'text-success' : run.status === 'failed' ? 'text-error' : 'text-accent'}">
													{run.status === 'completed' ? '✓' : run.status === 'failed' ? '✗' : '◌'} {run.status}
												</span>
											</td>
											<td class="py-2 pr-3 tabular-nums">{run.alive_hosts}/{run.total_hosts}</td>
											<td class="py-2 pr-3 tabular-nums">{run.new_hosts}</td>
											<td class="py-2 pr-3 tabular-nums text-muted">{run.duration_ms}ms</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{:else}
						<p class="text-sm text-muted py-4 text-center">{m["dashboard.No Scan Activity"]()}</p>
					{/if}
				</div>
			</div>

			<!-- Abnormal Devices — offline list, clickable to the device page -->
			<div class="bg-surface border border-border rounded-lg overflow-hidden md:col-span-2">
				<div class="px-4 py-3 border-b border-border flex items-center justify-between">
					<h3 class="text-sm font-semibold text-text">{m["dashboard.Offline Devices"]()}</h3>
					<a href="/devices?status=offline" class="text-xs text-primary hover:underline">
						{m["dashboard.View All"]()} →
					</a>
				</div>
				<div class="p-2">
					{#if overview?.abnormal.length}
						<div class="divide-y divide-border/50">
							{#each overview.abnormal as dev}
								<a href="/devices?search={dev.ip_address}" class="flex items-center justify-between px-2 py-2 hover:bg-surface-2 rounded transition-colors">
									<div class="flex items-center gap-2 min-w-0">
										<span class="inline-block w-2 h-2 rounded-full bg-error shrink-0"></span>
										<span class="text-sm truncate">{dev.name || dev.ip_address}</span>
										<span class="text-xs text-muted font-mono truncate">{dev.ip_address}</span>
									</div>
									<span class="text-xs text-muted shrink-0 ml-2">{dev.type || '-'}</span>
								</a>
							{/each}
						</div>
					{:else}
						<p class="text-sm text-muted py-4 text-center">
							{m["dashboard.No Offline Devices"]()}
						</p>
					{/if}
				</div>
			</div>
		</div>
	{/if}
</div>

<WidgetPicker bind:open={pickerOpen} editWidget={editingWidget} onSaved={onWidgetSaved} />
<ConfirmDialog
	bind:open={confirmOpen}
	title={m["dashboard.Remove Widget"]()}
	message={m["dashboard.Remove Confirm"]()}
	confirmLabel={m["common.Delete"]()}
	confirmVariant="danger"
	onConfirm={confirmRemoveWidget}
/>

<style>
	.widget-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
		gap: 1rem;
	}

	@media (max-width: 480px) {
		.widget-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
