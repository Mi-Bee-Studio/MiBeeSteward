<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  TopologyCanvas2D: the ECharts force-directed 2D renderer for the topology
  view (#635 PR1). Split out of DeviceTopologyView so the surrounding
  data/UI shell is renderer-agnostic; a three.js 3D renderer (PR2) will
  implement the same contract.

  Contract:
    Props (in):
      graph          — the raw /topology API payload (non-empty; the shell
                       only mounts the canvas once nodes exist)
      search         — active search query ('' = none)
      layerVisible   — per-layer visibility pills
      hiddenProtocols— per-protocol hide map (absent = shown)
      expandOrphans  — orphan group expanded back onto the canvas
      height         — canvas height
    Callbacks (out):
      onselectnode(gn | null)   — a device node was clicked
      onselectedge(gl | null)   — an edge was clicked
      onopenorphans()           — the collapsed orphan group node was clicked
      onopendevice(id)          — a node was double-clicked

  All visual verdicts (sizes, rings, labels, the opacity ladder, search
  dimming) come from the shared rules in topologyGraph.ts — do not add
  renderer-local styling decisions here, or 2D and 3D drift apart.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { m } from '$lib/i18n-paraglide';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import { escapeHtml } from '$lib/utils';
	import { cssVar, resolveToken } from '$lib/utils/cssVar';
	import { layerLabel, typeLabel, deviceType, formatAge, formatBytes } from '$lib/utils/topologyLabels';
	import type { TopologyGraph } from '$lib/types';
	import {
		buildGraph,
		recommendedForceParams,
		LAYER_ORDER,
		LAYER_COLORS,
		protocolStyle,
		nodeSize,
		nodeRing,
		nodeLabelVisible,
		edgeOpacity,
		SEARCH_DIM_NODE_OPACITY,
		searchHighlightSet,
		unknownNeighborStubs,
		ORPHAN_GROUP_ID,
		isStaleEdge,
		edgeAgeMs,
		splitOrphans,
		type GraphNode,
		type GraphLink,
		type TopoLayer
	} from '$lib/utils/topologyGraph';

	let {
		graph,
		search = '',
		layerVisible,
		hiddenProtocols = {},
		expandOrphans = false,
		height = '640px',
		onselectnode,
		onselectedge,
		onopenorphans,
		onopendevice
	}: {
		graph: TopologyGraph;
		search?: string;
		layerVisible: Record<TopoLayer, boolean>;
		hiddenProtocols?: Record<string, boolean>;
		expandOrphans?: boolean;
		height?: string;
		onselectnode?: (gn: GraphNode | null) => void;
		onselectedge?: (gl: GraphLink | null) => void;
		onopenorphans?: () => void;
		onopendevice?: (deviceId: number) => void;
	} = $props();

	// Freshness tick (#637): staleness fading, offline dimming and edge ages
	// are time-driven verdicts computed at option-build time — a static page
	// never crossed a threshold on its own. Rebuild every 30s so ghosts fade
	// without user interaction. Positions are id-stable across setOption
	// merges (same mechanism as the search-rebuild path), so this never
	// restarts the force layout.
	let freshnessTick = $state(0);
	onMount(() => {
		const t = setInterval(() => (freshnessTick += 1), 30_000);
		return () => clearInterval(t);
	});

	// The ECharts option. Rebuilt whenever graph/search/layer/edge-type/orphan
	// state changes — or the freshness tick fires (#637).
	let graphOption = $derived.by(() => {
		void freshnessTick; // track: time-driven style refreshes
		return buildOption(graph, search, layerVisible, hiddenProtocols, expandOrphans);
	});

	function buildOption(
		g: TopologyGraph,
		search: string,
		lvis: Record<TopoLayer, boolean>,
		hiddenProto: Record<string, boolean>,
		expandOrphans: boolean
	): EChartsOption | null {
		if (!g || g.nodes.length === 0) return null;
		const built = buildGraph(g);
		if (built.nodes.length === 0) return null;

		// Orphan grouping (#584): collapsed mode renders the connected subgraph
		// plus one synthetic dashed group node; expanded renders everything.
		const { connected, orphans } = splitOrphans(built.nodes);
		const layoutNodes = expandOrphans ? built.nodes : connected;
		const orphanVisible = orphans.filter((o) => lvis[o.layer]).length;
		const renderCount = layoutNodes.length + (expandOrphans || orphanVisible === 0 ? 0 : 1);

		const force = recommendedForceParams(Math.max(renderCount, 1));

		// Nodes filtered by layer visibility. Hidden layers' nodes are omitted
		// (and their links auto-dropped by ECharts when an endpoint is absent).
		// Orphans have no links, so collapsing them drops nothing (#584).
		const visibleNodeIds = new Set<number>();
		for (const gn of layoutNodes) {
			if (lvis[gn.layer]) visibleNodeIds.add(gn.id);
		}

		// Search dimming: matched nodes and their one-hop neighbors stay lit.
		const highlightedIds = searchHighlightSet(built.nodes, built.links, search);

		const echartsNodes = layoutNodes
			.filter((gn) => visibleNodeIds.has(gn.id))
			.map((gn) => {
				const dimmed = search && !highlightedIds.has(gn.id);
				const [token, fallback] = [LAYER_COLORS[gn.layer].token, LAYER_COLORS[gn.layer].fallback];
				// Root gets a larger glyph; others scale with degree.
				const size = nodeSize(gn);
				const showLabel = nodeLabelVisible(gn, force.labelDensity);
				// Cross-segment bridge (#556): a blue ring marks the node that
				// joins two segments (the root keeps its amber gateway ring).
				const ring = nodeRing(gn);
				return {
					id: String(gn.id),
					name: gn.name,
					category: gn.category,
					symbolSize: size,
					value: gn,
					itemStyle: {
						color: cssVar(token, fallback),
						opacity: dimmed ? SEARCH_DIM_NODE_OPACITY : 1,
						borderColor: ring ? cssVar(ring.color.token, ring.color.fallback) : 'transparent',
						borderWidth: ring ? ring.width : 0
					},
					label: {
						show: showLabel && !dimmed,
						position: 'right',
						fontSize: 11,
						color: cssVar('--color-text', '#e2e8f0'),
						formatter: () =>
							(gn.isBridge ? '⇄ ' : '') + (gn.value.name || gn.value.ip_address || `#${gn.value.id}`)
					}
				};
			});

		// The collapsed orphan group node (#584): one dashed hollow circle
		// instead of an island ocean. Click opens the member list panel.
		if (!expandOrphans && orphanVisible > 0) {
			echartsNodes.push({
				id: ORPHAN_GROUP_ID,
				name: m['topology.Orphan Group Node']({ n: orphanVisible }),
				symbolSize: 56,
				itemStyle: {
					color: 'transparent',
					borderColor: cssVar('--color-muted', '#94a3b8'),
					borderWidth: 2,
					borderType: 'dashed'
				},
				label: {
					show: true,
					position: 'inside',
					fontSize: 11,
					color: cssVar('--color-text-muted', '#cbd5e1'),
					formatter: () => m['topology.Orphan Group Node']({ n: orphanVisible })
				}
			});
		}

		// Node status by id (#585): an edge whose endpoint is offline (per
		// heartbeat) is a "was connected", not an "is connected".
		const statusById = new Map<string, string>();
		for (const gn of built.nodes) statusById.set(String(gn.id), gn.value.status || '');

		const visibleLinks = built.links
			.filter((l) => visibleNodeIds.has(l.source) && (l.isUnidentified || visibleNodeIds.has(l.target)))
			// Edge-type filter (#583): the legend pills toggle whole protocols.
			.filter((l) => !hiddenProto[l.protocol]);

		// Unidentified-neighbor stubs (#636): edges whose far end is only a MAC
		// hang off one synthetic dashed node per unseen MAC. Without them
		// ECharts drops the links (no target device) while the legend still
		// counts them.
		const stubs = unknownNeighborStubs(visibleLinks);
		const stubIdByMac = new Map(stubs.map((s) => [s.mac, s.id]));
		for (const s of stubs) {
			echartsNodes.push({
				id: s.id,
				name: s.mac,
				symbolSize: 18,
				itemStyle: {
					color: 'transparent',
					borderColor: cssVar('--color-muted', '#94a3b8'),
					borderWidth: 2,
					borderType: 'dashed'
				},
				label: {
					show: force.labelDensity === 'all' && !search,
					position: 'right',
					fontSize: 10,
					color: cssVar('--color-text-muted', '#cbd5e1'),
					formatter: () => `${m['topology.Unidentified Neighbor']()} ${s.mac}`
				}
			});
		}

		const echartsLinks = visibleLinks.map((l) => {
			const style = protocolStyle(l.protocol);
			const dimmed = search && !highlightedIds.has(l.source) && !highlightedIds.has(l.target);
			// Staleness (#585): an adjacency past its freshness threshold
			// (10min generic, 5min WiFi) fades and dashed-izes — the ghost
			// of a departed client must not read as a live link.
			const stale = isStaleEdge(l);
			// Offline endpoint (#585): edges of an offline device dim the
			// same way regardless of the edge's own freshness.
			const offlineEnd =
				statusById.get(String(l.source)) === 'offline' ||
				(!l.isUnidentified && statusById.get(String(l.target)) === 'offline');
			return {
				source: String(l.source),
				target: l.isUnidentified
					? (stubIdByMac.get(l.toMac || '(unknown)') ?? String(l.target))
					: String(l.target),
				value: l,
				lineStyle: {
					color: resolveToken(style.color),
					width: l.isCrossLink ? style.width + 0.5 : style.width,
					type: l.isUnidentified || stale ? 'dashed' : style.dash,
					opacity: edgeOpacity(l, { stale, offlineEnd, dimmed: !!dimmed }),
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
						const br = gn.isBridge ? `<br/>⇄ ${escapeHtml(m['topology.Bridges Segments']())}` : '';
						const ipLabel = escapeHtml(m['topology.Tooltip IP']());
						const macLabel = escapeHtml(m['topology.Tooltip MAC']());
						const typeLabelStr = escapeHtml(m['topology.Tooltip Type']());
						const statusLabel = escapeHtml(m['topology.Tooltip Status']());
						const degreeLabel = escapeHtml(m['topology.Degree']());
						return `<b>${escapeHtml(n.name)}</b>${gw}${br}<br/>${ipLabel}: ${escapeHtml(n.ip_address || '-')}<br/>${macLabel}: ${escapeHtml(n.mac_address || '-')}<br/>${typeLabelStr}: ${escapeHtml(typeLabel(deviceType(n)))}<br/>${statusLabel}: ${escapeHtml(n.status || '-')}<br/>${degreeLabel}: ${gn.degree}`;
					}
					if (p.dataType === 'edge') {
						const l = p.data.value as GraphLink | undefined;
						if (!l) return '';
						const protoLabel = escapeHtml(m['topology.Protocol']());
						const localLabel = escapeHtml(m['topology.Local Port']());
						const remoteLabel = escapeHtml(m['topology.Remote Port']());
						const remote = l.remotePort ? escapeHtml(l.remotePort) : '—';
						let tip = `<b>${escapeHtml(l.protocol)}</b><br/>${localLabel}: ${escapeHtml(l.localPort || '—')}<br/>${remoteLabel}: ${remote}`;
						if (l.protocol === 'speaks-with' && l.bytes != null) {
							tip += `<br/>${escapeHtml(m['topology.Bytes']())}: ${formatBytes(l.bytes)}`;
						}
						const age = edgeAgeMs(l);
						if (age !== null) {
							tip += `<br/>${escapeHtml(m['topology.Last Seen']())}: ${formatAge(age)}`;
							if (isStaleEdge(l)) tip += ` <span style="opacity:0.7">(${escapeHtml(m['topology.Edge Stale']())})</span>`;
						}
						return tip;
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

	// Click dispatch: node → onselectnode (the synthetic orphan group becomes
	// onopenorphans); edge → onselectedge. The shell owns the mutually
	// exclusive panel state; the canvas only reports what was clicked.
	function onChartClick(ev: { dataType: string; data: { id?: string; value?: GraphNode | GraphLink } }) {
		if (ev.dataType === 'node') {
			if ((ev.data as { id?: string }).id === ORPHAN_GROUP_ID) {
				onopenorphans?.();
				return;
			}
			const gn = ev.data.value as GraphNode | undefined;
			onselectnode?.(gn && gn.value ? gn : null);
		} else if (ev.dataType === 'edge') {
			const gl = ev.data.value as GraphLink | undefined;
			onselectedge?.(gl && gl.protocol !== undefined ? gl : null);
		}
	}

	// Double-click node → device detail page (the shell navigates).
	function onChartDblClick(ev: { dataType: string; data: { value?: GraphNode } }) {
		if (ev.dataType === 'node') {
			const gn = ev.data.value as GraphNode | undefined;
			if (gn && gn.value && gn.value.id) onopendevice?.(gn.value.id);
		}
	}
</script>

{#if graphOption}
	<Chart option={graphOption} {height} onclick={onChartClick} ondblclick={onChartDblClick} />
{/if}
