<script lang="ts">
	import { api } from '$lib/api/client';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import Chart from '$lib/components/Chart.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import { m } from '$lib/i18n-paraglide';
	import { LoaderCircle, HeartPulse } from '@lucide/svelte';

	interface HeartbeatConfig {
		id: number;
		device_id: number;
		method: string;
		target: string;
		interval: number;
		timeout: number;
		enabled: boolean;
		snmp_community: string;
		snmp_oid: string;
		expected_status: number;
	}

	interface HeartbeatResult {
		id: number;
		config_id: number;
		status: string;
		latency_ms: number;
		checked_at: string;
	}

	let {
		deviceId,
		expanded = false
	}: {
		deviceId: number;
		expanded?: boolean;
	} = $props();

	let configs = $state<HeartbeatConfig[]>([]);
	let results = $state<HeartbeatResult[]>([]);
	let loading = $state(false);
	let loaded = $state(false);

	let showChart = $state(false);
	let sparklineOption = $state<EChartsOption>({});

	// Lazy-load when expanded
	$effect(() => {
		if (expanded && !loaded && !loading) {
			fetchData();
		}
		if (!expanded && loaded) {
			// Destroy chart on collapse
			showChart = false;
		}
	});

	async function fetchData() {
		loading = true;
		try {
			const [configsRes, resultsRes] = await Promise.allSettled([
				api.get<{ configs: HeartbeatConfig[] }>(`/devices/${deviceId}/heartbeat-configs`),
				api.get<{ results: HeartbeatResult[] }>(`/devices/${deviceId}/heartbeat-results`)
			]);
			configs = configsRes.status === 'fulfilled' ? configsRes.value.configs || [] : [];
			results = resultsRes.status === 'fulfilled' ? resultsRes.value.results || [] : [];
			loaded = true;

			if (results.length > 0) {
				buildSparkline();
				showChart = true;
			}
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			loading = false;
		}
	}

	function buildSparkline() {
		const points = results
			.slice(0, 30)
			.reverse()
			.map((r) => r.latency_ms);
		if (points.length === 0) return;

		sparklineOption = {
			animation: false,
			grid: { top: 2, right: 2, bottom: 2, left: 2 },
			xAxis: { type: 'category', show: false, data: points.map((_, i) => i) },
			yAxis: { type: 'value', show: false },
			series: [
				{
					type: 'line',
					data: points,
					smooth: true,
					symbol: 'none',
					lineStyle: { width: 1.5, color: 'var(--color-accent)' },
					areaStyle: {
						color: {
							type: 'linear',
							x: 0, y: 0, x2: 0, y2: 1,
							colorStops: [
								{ offset: 0, color: 'rgba(129,140,248,0.3)' },
								{ offset: 1, color: 'rgba(129,140,248,0)' }
							]
						}
					}
				}
			],
			tooltip: { show: false }
		};
	}

	function latestForConfig(configId: number): HeartbeatResult | null {
		const r = results.find((r) => r.config_id === configId);
		return r ?? null;
	}

	function statusColor(status: string): string {
		if (status === 'success') return 'text-success';
		if (status === 'fail') return 'text-error';
		return 'text-muted';
	}

	function formatLatency(ms: number): string {
		if (!ms && ms !== 0) return '-';
		return `${ms}ms`;
	}

	function formatTime(iso: string): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	function lastCheckTime(): string {
		if (results.length === 0) return '-';
		return formatTime(results[0].checked_at);
	}
</script>

{#if expanded}
	<div class="border-t border-border bg-bg/50 px-4 py-3">
		{#if loading}
			<div class="flex items-center gap-2 text-xs text-muted">
				<LoaderCircle class="w-3.5 h-3.5 animate-spin" />
				{m['heartbeat.Loading']()}
			</div>
		{:else if configs.length === 0}
			<EmptyState icon={HeartPulse} title={m['heartbeat.NoConfig']()} description={m['heartbeat.NoConfigDesc']()} />
		{:else}
			<!-- Status summary per config -->
			<div class="space-y-2">
				{#each configs as config}
					{@const latest = latestForConfig(config.id)}
					<div class="flex items-center justify-between gap-3 text-xs">
						<div class="flex items-center gap-2 min-w-0">
							<span class="px-1.5 py-0.5 rounded bg-accent/10 text-accent font-mono shrink-0">
								{config.method}
							</span>
							<span class="text-muted font-mono truncate">{config.target}</span>
							{#if !config.enabled}
								<span class="text-muted opacity-50">{m['heartbeat.Disabled']()}</span>
							{/if}
						</div>
						<div class="flex items-center gap-2 shrink-0">
							{#if latest}
								<span class={statusColor(latest.status)}>
								{latest.status === 'success' ? m['heartbeat.StatusOK']() : m['heartbeat.StatusFail']()}
								</span>
								<span class="text-muted">{formatLatency(latest.latency_ms)}</span>
							{:else}
								<span class="text-muted">-</span>
							{/if}
						</div>
					</div>
				{/each}
			</div>

			<!-- Sparkline + last check -->
			{#if showChart && results.length > 0}
				<div class="flex items-center gap-4 mt-3 pt-3 border-t border-border">
					<div class="shrink-0" style="width:200px;height:40px;">
						<Chart option={sparklineOption} width="200px" height="40px" />
					</div>
					<div class="flex flex-col gap-1 text-xs text-muted">
						<span>{m['heartbeat.LastCheck']()} {lastCheckTime()}</span>
						<span>{m['heartbeat.ResultsCount']({ count: results.length })}</span>
					</div>
				</div>
			{/if}

			<!-- Refresh -->
			<div class="mt-2 flex justify-end">
				<button
					onclick={() => { loaded = false; showChart = false; fetchData(); }}
					class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
				>
				{m['heartbeat.Refresh']()}
				</button>
			</div>
		{/if}
	</div>
{/if}
