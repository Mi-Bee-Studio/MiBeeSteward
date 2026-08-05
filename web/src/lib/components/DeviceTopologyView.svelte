<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  DeviceTopologyView — the L2-topology force-directed graph (issue #136).

  Renders as a view inside /devices. Uses ECharts' `graph` series (force layout)
  rather than the older `tree` (radial) series — a graph renders mesh/cycle
  edges that a tree cannot, and the force layout naturally separates the
  detected gateway (top), switches/routers (core band), and endpoints (edge).

  Interactions:
    - Click node   → highlight neighbors + show node detail (IP/MAC/type/degree)
    - Click edge   → show port drill-down (local ↔ remote port, protocol)
    - Double-click node → open device detail page
    - Drag node / scroll / drag-canvas → reposition / zoom / pan (ECharts roam)
    - Search box   → dim non-matching nodes + their edges

  Layering is heuristic (detectRoot + device-type classification); real STP
  root-bridge role needs probe+schema work (follow-up). See topologyGraph.ts.

  Props:
    networkId — the currently-selected network filter from the devices page
                (empty/null = all networks). Passed through to /topology?network_id=.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { goto } from '$app/navigation';
	import { escapeHtml } from '$lib/utils';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import type { TopologyGraph, TopoNode } from '$lib/types';
	import {
		buildGraph,
		recommendedForceParams,
		LAYER_ORDER,
		type GraphNode,
		type GraphLink,
		type TopoLayer
	} from '$lib/utils/topologyGraph';
	import { Share2, X } from '@lucide/svelte';

	let {
		networkId = ''
	}: {
		networkId?: string;
	} = $props();

	let graph = $state<TopologyGraph | null>(null);
	let loading = $state(true);
	let error = $state('');
	let searchQuery = $state('');
	// Selected node/edge for the drill-down panels (mutually exclusive — clicking
	// one clears the other so only one panel shows at a time).
	let selectedNode = $state<GraphNode | null>(null);
	let selectedEdge = $state<GraphLink | null>(null);
	// Per-layer visibility (the legend doubles as a filter toggle). All on by default.
	let layerVisible = $state<Record<TopoLayer, boolean>>({
		root: true,
		core: true,
		access: true,
		edge: true
	});
	let pollTimer: ReturnType<typeof setInterval> | null = null;
	let fetchSeq = 0;
	let prevSignature = '';

	onMount(() => {
		fetchTopology();
		pollTimer = setInterval(() => fetchTopology(true), 60000);
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	// Refetch when the network filter changes (prop reactivity).
	$effect(() => {
		void networkId; // track
		fetchTopology();
	});

	async function fetchTopology(silent = false) {
		const seq = ++fetchSeq;
		try {
			const qs = networkId ? `?network_id=${networkId}` : '';
			const fresh = await api.get<TopologyGraph>(`/topology${qs}`);
			if (seq !== fetchSeq) return;
			const sig = graphSignature(fresh);
			if (silent && sig === prevSignature) return;
			prevSignature = sig;
			graph = fresh;
			error = '';
		} catch (err: unknown) {
			if (seq !== fetchSeq) return;
			error = getErrorMessage(err);
		} finally {
			if (seq === fetchSeq) loading = false;
		}
	}

	function graphSignature(g: TopologyGraph): string {
		const nodeIds = g.nodes.map((n) => n.id).sort((a, b) => a - b).join(',');
		const edgeKeys = g.edges
			.map((e) => `${e.from_device_id}>${e.to_device_id ?? e.to_mac}:${e.protocol}`)
			.sort()
			.join(',');
		return `${g.nodes.length}|${g.edges.length}|${nodeIds}|${edgeKeys}`;
	}

	// Read a computed CSS variable so ECharts (canvas-rendered, can't resolve
	// var(...)) follows the theme.
	function cssVar(name: string, fallback: string): string {
		const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
		return v || fallback;
	}

	// Layer → (css-var token, hex fallback). Drives node color by layer.
	const LAYER_COLORS: Record<TopoLayer, [string, string]> = {
		root: ['--color-warning', '#f59e0b'], // gateway = amber (stands out)
		core: ['--color-info', '#3b82f6'], // switches/routers = blue
		access: ['--color-accent-purple', '#8b5cf6'], // middle layer = purple
		edge: ['--color-muted', '#64748b'] // endpoints = grey (blend in)
	};

	// Protocol → (css-var token, hex fallback, dash pattern). Drives edge color/style.
	// High-confidence L2 (LLDP/CDP) = green solid; Bridge-MIB = blue solid;
	// STP = purple dashed; ARP (L3, low-confidence) = grey dotted.
	const PROTOCOL_STYLES: Record<string, { color: [string, string]; type: 'solid' | 'dashed' | 'dotted'; width: number }> = {
		LLDP: { color: ['--color-success', '#10b981'], type: 'solid', width: 2 },
		CDP: { color: ['--color-success', '#10b981'], type: 'solid', width: 2 },
		'Bridge-MIB': { color: ['--color-info', '#3b82f6'], type: 'solid', width: 1.5 },
		'Q-BRIDGE-MIB': { color: ['--color-info', '#3b82f6'], type: 'solid', width: 1.5 },
		STP: { color: ['--color-accent-purple', '#8b5cf6'], type: 'dashed', width: 1.5 },
		ARP: { color: ['--color-muted', '#94a3b8'], type: 'dotted', width: 1 }
	};

	function protocolStyle(protocol: string) {
		return PROTOCOL_STYLES[protocol] ?? { color: ['--color-muted', '#94a3b8'], type: 'solid', width: 1 };
	}

	function typeLabel(type: string): string {
		const labels: Record<string, string> = {
			pc: m['devices.PC'](),
			embedded: m['devices.Embedded'](),
			iot: m['devices.IoT'](),
			server: m['devices.Server'](),
			switch: m['devices.Switch'](),
			router: m['devices.Router'](),
			firewall: m['devices.Firewall'](),
			nas: m['devices.NAS'](),
			camera: m['devices.Camera'](),
			phone: m['devices.Phone'](),
			printer: m['devices.Printer'](),
			other: m['devices.Other']()
		};
		return labels[type] ?? type;
	}

	function deviceType(n: TopoNode): string {
		return (n.inferred_type || n.type || 'other').toLowerCase();
	}

	function layerLabel(layer: TopoLayer): string {
		const labels: Record<TopoLayer, string> = {
			root: m['topology.Layer Root'](),
			core: m['topology.Layer Core'](),
			access: m['topology.Layer Access'](),
			edge: m['topology.Layer Endpoint']()
		};
		return labels[layer];
	}

	// The ECharts option. Rebuilt whenever graph/search/layer-filter change.
	let graphOption = $derived<EChartsOption | null>(buildOption(graph, searchQuery, layerVisible));

	function buildOption(
		g: TopologyGraph | null,
		search: string,
		lvis: Record<TopoLayer, boolean>
	): EChartsOption | null {
		if (!g || g.nodes.length === 0) return null;
		const built = buildGraph(g);
		if (built.nodes.length === 0) return null;

		const force = recommendedForceParams(built.nodes.length);

		// Nodes filtered by layer visibility. Hidden layers' nodes are omitted
		// (and their links auto-dropped by ECharts when an endpoint is absent).
		const visibleNodeIds = new Set<number>();
		for (const gn of built.nodes) {
			if (lvis[gn.layer]) visibleNodeIds.add(gn.id);
		}

		const nodeByName = new Map<string, GraphNode>();
		for (const gn of built.nodes) {
			nodeByName.set(String(gn.id), gn);
		}

		// Pre-compute the search match set so we can dim non-matches.
		const matchedIds = new Set<number>();
		if (search) {
			const q = search.toLowerCase();
			for (const gn of built.nodes) {
				const n = gn.value;
				if (
					(n.name || '').toLowerCase().includes(q) ||
					(n.ip_address || '').toLowerCase().includes(q) ||
					(n.mac_address || '').toLowerCase().includes(q)
				) {
					matchedIds.add(gn.id);
				}
			}
		}
		// When searching, also keep direct neighbors of matched nodes visible-at-full-opacity.
		const highlightedIds = new Set<number>(matchedIds);
		if (search) {
			for (const link of built.links) {
				if (matchedIds.has(link.source)) highlightedIds.add(link.target);
				if (matchedIds.has(link.target)) highlightedIds.add(link.source);
			}
		}

		const echartsNodes = built.nodes
			.filter((gn) => visibleNodeIds.has(gn.id))
			.map((gn) => {
				const dimmed = search && !highlightedIds.has(gn.id);
				const [token, fallback] = LAYER_COLORS[gn.layer];
				// Root gets a larger glyph; others scale with degree.
				const size = gn.isRoot ? 44 : Math.max(16, Math.min(40, 12 + gn.degree * 2));
				const showLabel =
					force.labelDensity === 'all' ||
					(force.labelDensity === 'core' && (gn.layer === 'root' || gn.layer === 'core'));
				return {
					id: String(gn.id),
					name: gn.name,
					category: gn.category,
					symbolSize: size,
					value: gn,
					itemStyle: {
						color: cssVar(token, fallback),
						opacity: dimmed ? 0.15 : 1,
						borderColor: gn.isRoot ? cssVar('--color-warning', '#f59e0b') : 'transparent',
						borderWidth: gn.isRoot ? 3 : 0
					},
					label: {
						show: showLabel && !dimmed,
						position: 'right',
						fontSize: 11,
						color: cssVar('--color-text', '#e2e8f0'),
						formatter: () => gn.value.name || gn.value.ip_address || `#${gn.value.id}`
					}
				};
			});

		const echartsLinks = built.links
			.filter((l) => visibleNodeIds.has(l.source) && (l.isUnidentified || visibleNodeIds.has(l.target)))
			.map((l) => {
				const style = protocolStyle(l.protocol);
				const dimmed = search && !highlightedIds.has(l.source) && !highlightedIds.has(l.target);
				return {
					source: String(l.source),
					target: String(l.target),
					value: l,
					lineStyle: {
						color: cssVar(style.color[0], style.color[1]),
						width: l.isCrossLink ? style.width + 0.5 : style.width,
						type: l.isUnidentified ? 'dashed' : style.type,
						opacity: dimmed ? 0.1 : l.isCrossLink ? 0.5 : 0.8,
						curveness: l.isCrossLink ? 0.3 : 0.1
					},
					emphasis: { lineStyle: { width: 3 } }
				};
			});

		// ECharts categories (legend + force grouping). Order matches LAYER_ORDER.
		const categories = LAYER_ORDER.map((layer) => ({
			name: layerLabel(layer)
		}));

		return {
			tooltip: {
				formatter: (p: any) => {
					if (p.dataType === 'node') {
						const gn = p.data.value as GraphNode | undefined;
						if (!gn || !gn.value) return '';
						const n = gn.value;
						const gw = gn.isRoot ? ` ⭐ ${escapeHtml(m['topology.Gateway']())}` : '';
						const ipLabel = escapeHtml(m['topology.Tooltip IP']());
						const macLabel = escapeHtml(m['topology.Tooltip MAC']());
						const typeLabelStr = escapeHtml(m['topology.Tooltip Type']());
						const statusLabel = escapeHtml(m['topology.Tooltip Status']());
						const degreeLabel = escapeHtml(m['topology.Degree']());
						return `<b>${escapeHtml(n.name)}</b>${gw}<br/>${ipLabel}: ${escapeHtml(n.ip_address || '-')}<br/>${macLabel}: ${escapeHtml(n.mac_address || '-')}<br/>${typeLabelStr}: ${escapeHtml(typeLabel(deviceType(n)))}<br/>${statusLabel}: ${escapeHtml(n.status || '-')}<br/>${degreeLabel}: ${gn.degree}`;
					}
					if (p.dataType === 'edge') {
						const l = p.data.value as GraphLink | undefined;
						if (!l) return '';
						const protoLabel = escapeHtml(m['topology.Protocol']());
						const localLabel = escapeHtml(m['topology.Local Port']());
						const remoteLabel = escapeHtml(m['topology.Remote Port']());
						const remote = l.remotePort ? escapeHtml(l.remotePort) : '—';
						return `<b>${escapeHtml(l.protocol)}</b><br/>${localLabel}: ${escapeHtml(l.localPort || '—')}<br/>${remoteLabel}: ${remote}`;
					}
					return '';
				}
			},
			legend: {
				data: categories.map((c) => c.name),
				textStyle: { color: cssVar('--color-text-muted', '#cbd5e1') },
				top: 10
			},
			animationDuration: 800,
			series: [
				{
					type: 'graph',
					layout: 'force',
					data: echartsNodes,
					links: echartsLinks,
					categories,
					roam: true,
					draggable: true,
					force: {
						repulsion: force.repulsion,
						edgeLength: force.edgeLength,
						gravity: force.gravity,
						layoutAnimation: force.layoutAnimation
					},
					emphasis: {
						focus: 'adjacency',
						lineStyle: { width: 3 },
						label: { show: true }
					},
					lineStyle: { color: 'source', opacity: 0.7 }
				}
			]
		};
	}

	// Click handler: node → select node (clear edge); edge → select edge (clear node).
	function onChartClick(ev: { dataType: string; data: { value?: GraphNode | GraphLink } }) {
		if (ev.dataType === 'node') {
			const gn = ev.data.value as GraphNode | undefined;
			selectedNode = gn && gn.value ? gn : null;
			selectedEdge = null;
		} else if (ev.dataType === 'edge') {
			const gl = ev.data.value as GraphLink | undefined;
			selectedEdge = gl && gl.protocol !== undefined ? gl : null;
			selectedNode = null;
		}
	}

	// Double-click node → device detail page (preserved from the old tree view).
	function onChartDblClick(ev: { dataType: string; data: { value?: GraphNode } }) {
		if (ev.dataType === 'node') {
			const gn = ev.data.value as GraphNode | undefined;
			if (gn && gn.value && gn.value.id) goto('/devices/detail/' + gn.value.id);
		}
	}

	// Resolve a link's endpoint device names for the detail panel (nicer than
	// showing bare ids).
	function nodeNameById(id: number): string {
		if (!graph) return `#${id}`;
		const n = graph.nodes.find((x) => x.id === id);
		return n ? n.name || n.ip_address || `#${id}` : `#${id}`;
	}
</script>

<div class="flex flex-col gap-3 h-full">
	<!-- Toolbar: search + layer-filter toggles + refresh -->
	<div class="flex flex-wrap items-center gap-2">
		<input
			type="text"
			bind:value={searchQuery}
			placeholder={m['common.Search']() + '…'}
			class="input max-w-xs"
		/>
		<!-- Layer filter pills (also reflected in the legend) -->
		<div class="flex items-center gap-1 text-xs">
			{#each LAYER_ORDER as layer}
				<button
					onclick={() => (layerVisible = { ...layerVisible, [layer]: !layerVisible[layer] })}
					class="px-2 py-1 rounded-full border transition-colors {layerVisible[layer]
						? 'border-border-strong bg-surface-strong'
						: 'border-border bg-surface opacity-50'}"
					style={layerVisible[layer] ? `border-color: ${cssVar(LAYER_COLORS[layer][0], LAYER_COLORS[layer][1])}` : ''}
				>
					<span
						class="inline-block w-2 h-2 rounded-full mr-1 align-middle"
						style="background: {cssVar(LAYER_COLORS[layer][0], LAYER_COLORS[layer][1])}"
					></span>
					{layerLabel(layer)}
				</button>
			{/each}
		</div>
		<div class="flex-1"></div>
		<button
			onclick={() => fetchTopology()}
			class="btn btn-secondary text-sm"
		>{m['dashboard.Refresh']()}</button>
	</div>

	{#if loading}
		<PageSkeleton type="table" />
	{:else if error}
		<div class="px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite">
			{error}
		</div>
	{:else if !graph || graph.nodes.length === 0}
		<EmptyState
			icon={Share2}
			title={m['topology.Empty']()}
			description={m['topology.Empty Desc']()}
		/>
	{:else if !graphOption}
		<!-- Nodes exist but no edges → can't build a graph. -->
		<EmptyState
			icon={Share2}
			title={m['topology.No Edges Title']()}
			description={m['topology.No Edges Desc']()}
		/>
	{:else}
		<div class="flex gap-3 flex-1 min-h-[500px]">
			<!-- Graph canvas (fills available space; detail panel overlays on the right) -->
			<div class="bg-surface border border-border rounded-lg p-2 flex-1 min-w-0">
				<Chart option={graphOption} height="640px" onclick={onChartClick} ondblclick={onChartDblClick} />
			</div>

			<!-- Drill-down panel: shows when a node or edge is selected -->
			{#if selectedNode}
				<aside class="w-72 shrink-0 bg-surface border border-border rounded-lg p-4 text-sm overflow-y-auto">
					<div class="flex items-start justify-between mb-2">
						<h3 class="font-semibold text-base">{m['topology.Node Detail Title']()}</h3>
						<button onclick={() => (selectedNode = null)} class="text-muted hover:text-text" aria-label="close">
							<X class="w-4 h-4" />
						</button>
					</div>
					<dl class="space-y-1.5">
						<div><dt class="text-muted inline">{m['topology.Tooltip IP']()}: </dt><dd class="inline font-mono">{selectedNode.value.ip_address || '—'}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Tooltip MAC']()}: </dt><dd class="inline font-mono">{selectedNode.value.mac_address || '—'}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Tooltip Type']()}: </dt><dd class="inline">{typeLabel(deviceType(selectedNode.value))}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Tooltip Status']()}: </dt><dd class="inline">{selectedNode.value.status || '—'}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Degree']()}: </dt><dd class="inline">{selectedNode.degree}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Brand']()}: </dt><dd class="inline">{selectedNode.value.brand || '—'}</dd></div>
						{#if selectedNode.value.network_id}
							<div><dt class="text-muted inline">{m['topology.Network']()}: </dt><dd class="inline">{selectedNode.value.network_id}</dd></div>
						{/if}
					</dl>
					{#if selectedNode.isRoot}
						<p class="mt-3 text-xs text-warning">⭐ {m['topology.Gateway']()}</p>
					{/if}
					<a
						href="/devices/detail/{selectedNode.value.id}"
						class="btn btn-secondary text-xs mt-4 inline-block"
					>{m['topology.Open Device']()}</a>
				</aside>
			{:else if selectedEdge}
				<aside class="w-72 shrink-0 bg-surface border border-border rounded-lg p-4 text-sm overflow-y-auto">
					<div class="flex items-start justify-between mb-2">
						<h3 class="font-semibold text-base">{m['topology.Edge Detail Title']()}</h3>
						<button onclick={() => (selectedEdge = null)} class="text-muted hover:text-text" aria-label="close">
							<X class="w-4 h-4" />
						</button>
					</div>
					<dl class="space-y-1.5">
						<div>
							<dt class="text-muted">{m['topology.Protocol']()}</dt>
							<dd class="font-mono">{selectedEdge.protocol}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.From Device']()}</dt>
							<dd>{nodeNameById(selectedEdge.source)}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.Local Port']()}</dt>
							<dd class="font-mono">{selectedEdge.localPort || '—'}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.To Device']()}</dt>
							<dd>{selectedEdge.isUnidentified ? m['topology.Unidentified Neighbor']() : nodeNameById(selectedEdge.target)}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.Remote Port']()}</dt>
							<dd class="font-mono">{selectedEdge.remotePort || '—'}</dd>
						</div>
						{#if selectedEdge.isCrossLink}
							<p class="text-xs text-accent-purple mt-2">↻ {m['topology.Cross Link']()}</p>
						{/if}
					</dl>
				</aside>
			{/if}
		</div>
		<p class="text-xs text-muted">
			{m['topology.Click Hint']()}
		</p>
	{/if}
</div>
