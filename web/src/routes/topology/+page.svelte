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
	//
	// Layout strategy:
	//   - Has edges → force layout (edges pull connected nodes, repulsion spreads
	//     them). Repulsion scales with node count so dense graphs don't collapse.
	//   - No edges (or all isolated) → circular layout (force with no edges piles
	//     every node in the center; circular spreads them evenly around a ring).
	// Labels: hidden when node count is high (> 50, they'd overlap) — hover/tap
	// a node to see its name via tooltip.
	let topologyOption = $derived<EChartsOption | null>(buildOption(graph));

	function buildOption(g: TopologyGraph | null): EChartsOption | null {
		if (!g || g.nodes.length === 0) return null;

		const hasEdges = g.edges.length > 0;
		const nodeCount = g.nodes.length;
		const showLabels = nodeCount <= 50;

		// Identify MACs that appear as a neighbor but have no matching node —
		// render them as synthetic "unidentified" nodes (dashed-edge targets).
		const knownMACs = new Set(g.nodes.map((n) => n.mac_address).filter(Boolean));
		const syntheticNodes = new Map<string, { mac: string; protocol: string }>();
		for (const e of g.edges) {
			if (e.to_mac && !knownMACs.has(e.to_mac) && !syntheticNodes.has(e.to_mac)) {
				syntheticNodes.set(e.to_mac, { mac: e.to_mac, protocol: e.protocol });
			}
		}

		// Circular layout for isolated/island-heavy graphs: spread nodes around a
		// ring so they don't collapse into the center (force needs edges to pull
		// nodes apart; without them gravity wins and piles everything up).
		let positions: Record<string, [number, number]> | null = null;
		if (!hasEdges) {
			positions = {};
			const ringNodes = g.nodes;
			const radius = 320; // ring radius in px (graph is zoomable)
			ringNodes.forEach((n, i) => {
				const angle = (2 * Math.PI * i) / ringNodes.length;
				positions![String(n.id)] = [
					Math.cos(angle) * radius,
					Math.sin(angle) * radius
				];
			});
		}

		const echartsNodes = [
			...g.nodes.map((n) => {
				const node: Record<string, unknown> = {
					id: String(n.id),
					name: n.name || n.ip_address || `#${n.id}`,
					category: nodeCategory(n),
					symbolSize: nodeCount > 100 ? 18 : nodeCount > 50 ? 26 : 36,
					value: n,
					itemStyle: { color: typeColors[nodeCategory(n)] ?? typeColors.other },
					label: { show: showLabels, position: 'right', fontSize: 10, color: '#e2e8f0' }
				};
				if (positions && positions[String(n.id)]) {
					node.x = positions[String(n.id)][0];
					node.y = positions[String(n.id)][1];
					node.fixed = true; // keep the circular layout stable
				}
				return node;
			}),
			...[...syntheticNodes.values()].map((s) => ({
				id: `mac:${s.mac}`,
				name: s.mac,
				category: 'other',
				symbolSize: 22,
				itemStyle: { color: typeColors.other, opacity: 0.5 },
				label: { show: showLabels, fontSize: 9, color: '#94a3b8' }
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

		// Force params: repulsion scales with node count (more nodes need more
		// space). gravity near-zero when there are edges (let repulsion dominate);
		// not used at all for the circular layout (nodes are fixed).
		const repulsion = Math.max(120, nodeCount * 6);

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
			animationDuration: 800,
			animationEasingUpdate: 'cubicOut',
			series: [
				{
					type: 'graph',
					// Always 'force': when there are no edges we pre-place nodes in a
					// ring and mark them fixed, so force keeps them in place (layout
					// 'none' ignores x/y in some ECharts versions).
					layout: 'force',
					roam: true,
					draggable: hasEdges, // allow drag only when edges exist to rearrange
					label: { show: showLabels, position: 'right', fontSize: 10, color: '#e2e8f0' },
					force: {
						repulsion: hasEdges ? repulsion : 1,     // no repulsion war when fixed
						edgeLength: [80, 200],
						gravity: hasEdges ? 0.01 : 0,            // no gravity pull when fixed
						layoutAnimation: hasEdges
					},
					categories: typeCategories.map((c) => ({ name: c })),
					data: echartsNodes,
					links: echartsEdges,
					edgeSymbol: ['none', 'arrow'],
					edgeSymbolSize: 6,
					emphasis: {
						focus: 'adjacency',
						lineStyle: { width: 3 },
						label: { show: true } // always show label on hover, even if globally hidden
					}
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
			{#if (graph?.edges.length ?? 0) === 0}
				<span class="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400">
					{m['topology.No Edges Hint']?.() ?? 'No L2 edges yet — scan managed switches to populate adjacency'}
				</span>
			{/if}
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
