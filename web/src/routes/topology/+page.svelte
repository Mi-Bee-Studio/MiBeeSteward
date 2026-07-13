<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import { goto } from '$app/navigation';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Share2 as TopologyIcon } from '@lucide/svelte';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import type { TopologyGraph, TopoNode } from '$lib/types';

	interface Network {
		id: number;
		name: string;
		cidr?: string | null;
		site?: string | null;
	}

	let graph = $state<TopologyGraph | null>(null);
	let networks = $state<Network[]>([]);
	let selectedNetwork = $state<number | null>(null); // null = all
	let loading = $state(true);
	let error = $state('');
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	onMount(() => {
		fetchNetworks();
		fetchTopology();
		// Topology changes as scans run; refresh every 60s.
		pollTimer = setInterval(fetchTopology, 60000);
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	async function fetchNetworks() {
		try {
			const res = await api.get<{ networks: Network[] }>('/networks');
			networks = res.networks ?? [];
		} catch {
			// Non-fatal — the "all networks" view still works.
		}
	}

	async function fetchTopology() {
		try {
			const qs = selectedNetwork ? `?network_id=${selectedNetwork}` : '';
			graph = await api.get<TopologyGraph>(`/topology${qs}`);
			error = '';
		} catch (err: unknown) {
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	function onNetworkChange() {
		loading = true;
		fetchTopology();
	}

	// Node color by device type (the hand-set type, or inferred_type when richer).
	function nodeCategory(node: TopoNode): string {
		return node.type || 'other';
	}

	// Categories for the legend + color mapping.
	const typeCategories = [
		'switch', 'router', 'firewall', 'server', 'nas', 'camera',
		'pc', 'embedded', 'iot', 'other'
	];
	const typeColors: Record<string, string> = {
		switch: '#3b82f6', router: '#8b5cf6', firewall: '#ef4444',
		server: '#10b981', nas: '#f59e0b', camera: '#ec4899',
		pc: '#06b6d4', embedded: '#64748b', iot: '#84cc16', other: '#94a3b8'
	};

	// Build the ECharts graph option. Nodes = devices; edges = L2 adjacencies.
	// Edges to an unidentified neighbor (to_device_id null) render dashed + point
	// at a synthetic "MAC" node so the relationship is still visible.
	let topologyOption = $derived<EChartsOption | null>(buildOption(graph));

	function buildOption(g: TopologyGraph | null): EChartsOption | null {
		if (!g || (g.nodes.length === 0 && g.edges.length === 0)) return null;

		// Identify MACs that appear as a neighbor but have no matching node —
		// render them as synthetic "unidentified" nodes (dashed-edge targets).
		const knownMACs = new Set(g.nodes.map((n) => n.mac_address).filter(Boolean));
		const syntheticNodes = new Map<string, { mac: string; protocol: string }>();
		for (const e of g.edges) {
			if (e.to_mac && !knownMACs.has(e.to_mac) && !syntheticNodes.has(e.to_mac)) {
				syntheticNodes.set(e.to_mac, { mac: e.to_mac, protocol: e.protocol });
			}
		}

		const echartsNodes = [
			...g.nodes.map((n) => ({
				id: String(n.id),
				name: n.name || n.ip_address || `#${n.id}`,
				category: nodeCategory(n),
				symbolSize: 40,
				value: n,
				itemStyle: { color: typeColors[nodeCategory(n)] ?? typeColors.other },
				label: { show: true }
			})),
			...[...syntheticNodes.values()].map((s) => ({
				id: `mac:${s.mac}`,
				name: s.mac,
				category: 'other',
				symbolSize: 24,
				itemStyle: { color: typeColors.other, opacity: 0.5 },
				label: { show: true, fontSize: 9, color: '#94a3b8' }
			}))
		];

		const echartsEdges = g.edges.map((e, i) => {
			const target = e.to_device_id ? String(e.to_device_id) : `mac:${e.to_mac}`;
			return {
				id: `e${i}`,
				source: String(e.from_device_id),
				target,
				lineStyle: {
					color: e.protocol === 'LLDP' ? '#3b82f6' : '#10b981',
					width: e.protocol === 'LLDP' ? 2 : 1,
					type: e.to_device_id ? 'solid' : 'dashed',
					opacity: 0.6
				},
				value: e
			};
		});

		return {
			tooltip: {
				formatter: (p: any) => {
					if (p.dataType === 'node') {
						const v = p.data.value as TopoNode | undefined;
						if (!v) return p.data.name; // synthetic node
						return `<b>${v.name}</b><br/>IP: ${v.ip_address || '-'}<br/>MAC: ${v.mac_address || '-'}<br/>Type: ${v.type}<br/>Status: ${v.status}`;
					}
					const e = p.data.value as { protocol: string; local_port?: string | null } | undefined;
					return e ? `${e.protocol}${e.local_port ? ' · port ' + e.local_port : ''}` : '';
				}
			},
			legend: {
				data: typeCategories.filter((c) =>
					g.nodes.some((n) => nodeCategory(n) === c)
				),
				textStyle: { color: '#cbd5e1' },
				top: 10
			},
			series: [
				{
					type: 'graph',
					layout: 'force',
					roam: true,
					draggable: true,
					label: { show: true, position: 'right', fontSize: 10, color: '#e2e8f0' },
					force: { repulsion: 200, edgeLength: [80, 200], gravity: 0.05 },
					categories: typeCategories.map((c) => ({ name: c })),
					data: echartsNodes,
					links: echartsEdges,
					edgeSymbol: ['none', 'arrow'],
					edgeSymbolSize: 6,
					emphasis: { focus: 'adjacency', lineStyle: { width: 3 } }
				}
			]
		};
	}

	function onChartClick(ev: { dataType: string; data: { value?: TopoNode } }) {
		if (ev.dataType === 'node' && ev.data.value?.id) {
			goto(`/devices/detail/${ev.data.value.id}`);
		}
	}
</script>

{#if !$auth.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m['errors.Unauthorized Desc']?.() ?? 'Please log in.'}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m['navigation.Login']()}</a>
	</div>
{:else}
<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6 flex-wrap gap-3">
		<h2 class="text-2xl font-bold text-primary">{m['topology.Title']?.() ?? 'Network Topology'}</h2>
		<div class="flex items-center gap-3">
			<!-- Network filter -->
			<select
				bind:value={selectedNetwork}
				onchange={onNetworkChange}
				class="px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text"
			>
				<option value={null}>{m['topology.All Networks']?.() ?? 'All networks'}</option>
				{#each networks as net}
					<option value={net.id}>{net.name}{net.site ? ` · ${net.site}` : ''}</option>
				{/each}
			</select>
			<button
				onclick={fetchTopology}
				class="px-4 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary hover:text-primary transition-colors text-sm"
			>
				{m['dashboard.Refresh']()}
			</button>
		</div>
	</div>

	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	{#if loading}
		<PageSkeleton type="table" />
	{:else if !topologyOption}
		<EmptyState
			icon={TopologyIcon}
			title={m['topology.Empty']?.() ?? 'No topology data yet'}
			description={m['topology.Empty Desc']?.() ?? 'L2 neighbor edges (Bridge-MIB / LLDP) are populated when switches are scanned. Run a scan that includes managed switches.'}
		/>
	{:else}
		<!-- Legend summary -->
		<div class="flex flex-wrap items-center gap-4 mb-3 text-xs text-text-muted">
			<span>{(graph?.nodes.length ?? 0)} {m['topology.Nodes']?.() ?? 'devices'}</span>
			<span>{(graph?.edges.length ?? 0)} {m['topology.Edges']?.() ?? 'adjacencies'}</span>
			<span class="flex items-center gap-1.5">
				<span class="inline-block w-6 h-0.5" style="background:#3b82f6"></span>LLDP
			</span>
			<span class="flex items-center gap-1.5">
				<span class="inline-block w-6 h-0.5" style="background:#10b981"></span>Bridge-MIB
			</span>
			<span class="flex items-center gap-1.5">
				<span class="inline-block w-6 h-0 border-t border-dashed border-text-muted"></span>
				{m['topology.Unidentified']?.() ?? 'unidentified neighbor'}
			</span>
		</div>
		<div class="bg-surface border border-border rounded-lg p-2">
			<Chart option={topologyOption} height="70vh" onclick={(p) => onChartClick(p as unknown as { dataType: string; data: { value?: TopoNode } })} />
		</div>
		<p class="text-xs text-text-muted mt-2">{m['topology.Click Hint']?.() ?? 'Click a device node to open its detail page. Drag to rearrange; scroll to zoom.'}</p>
	{/if}
</div>
{/if}
