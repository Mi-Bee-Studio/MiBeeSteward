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

import type { TopologyGraph, TopoNode, TopoEdge } from '$lib/types';

/**
 * Topology graph builder for the force-directed visualization (issue #136).
 *
 * Replaces the older `topologyTree.ts` BFS-tree builder. The key difference:
 * a tree layout can only render a spanning tree and silently drops mesh/cycle
 * edges (crossLinks were computed but discarded). This builder produces a full
 * graph (nodes + ALL links including cycles), so ECharts' `graph` series can
 * draw redundant links, STP-blocked ports, and mesh topologies.
 *
 * Layering is heuristic (no real STP root-bridge role in the data yet: the
 * stp_mib probe only emits designated-bridge MAC, not dot1dStpPortRole). The
 * layers drive both the visual grouping (ECharts categories → legend + color)
 * and the force layout (gravity pulls each layer toward its band). True STP
 * root-role layering is a follow-up that needs probe + schema work.
 */

/** The 4 topology layers, ordered root → edge. Also the ECharts category index. */
export type TopoLayer = 'root' | 'core' | 'access' | 'edge';

export const LAYER_ORDER: TopoLayer[] = ['root', 'core', 'access', 'edge'];

/** A node in the force-graph, carrying its layer + computed degree. */
export interface GraphNode {
	/** Numeric device id: ECharts graph uses this as the node id (coerced to string internally). */
	id: number;
	name: string;
	value: TopoNode;
	/** Undirected link count (both ends counted). Drives symbolSize. */
	degree: number;
	/** Heuristic layer: drives category (color/gravity) + legend. */
	layer: TopoLayer;
	/** ECharts category index (matches LAYER_ORDER). */
	category: number;
	/** True for the detectedRoot: gets the gateway glyph. */
	isRoot: boolean;
	/** True when the node bridges multiple segments (#556): present in more
	 * than one network per the multi-homed presence facts (#526). These are
	 * the cross-segment link points — the nodes that join two LAN clusters. */
	isBridge: boolean;
}

/** A link in the force-graph. All edges become links (tree edges AND crossLinks). */
export interface GraphLink {
	/** Numeric source device id (ECharts coerces to string). */
	source: number;
	/** Numeric target device id. */
	target: number;
	/** Discovery protocol: LLDP / CDP / Bridge-MIB / Q-BRIDGE-MIB / STP / ARP. */
	protocol: string;
	/** Local-end ifName (may be empty for ARP). */
	localPort?: string | null;
	/** Far-end ifName (LLDP/CDP only; empty for Bridge-MIB/ARP). */
	remotePort?: string | null;
	/** True if this edge closed a cycle during BFS (mesh/back link). */
	isCrossLink: boolean;
	/** True if the far end is an unidentified neighbor (no matching device). */
	isUnidentified: boolean;
	/** Raw to_mac for unidentified far ends (#636): the identity of the
	 * synthetic canvas stub node. Null when the edge resolved to a device. */
	toMac?: string | null;
	/** speaks-with edges (#500): observed byte total (both directions). */
	bytes?: number | null;
	/** When the adjacency was last re-observed (#585), RFC3339; null/empty =
	 *  age unknown (treated as fresh, never faded). Drives ghost-edge fading. */
	lastSeen?: string | null;
}

export interface GraphBuildResult {
	nodes: GraphNode[];
	links: GraphLink[];
	/** Node ids grouped by layer, for collapse/expand controls. */
	layers: Record<TopoLayer, number[]>;
	/** The detected root node id (null if graph is empty). */
	rootId: number | null;
}

/**
 * Weak-evidence protocols (#583): relations inferred from observation rather
 * than reported wiring — ARP is "same subnet per the gateway's table",
 * speaks-with is "these two talked". They render fainter than hard L2 facts
 * and the legend labels them, so users stop reading inference as cabling.
 */
export const WEAK_PROTOCOLS = new Set(['ARP', 'speaks-with']);

/**
 * Display order for edge types in the legend (#583): hard wiring facts first,
 * inferred/corroborating relations last.
 */
export const PROTOCOL_ORDER = [
	'LLDP',
	'CDP',
	'Bridge-MIB',
	'Q-BRIDGE-MIB',
	'STP',
	'WiFi',
	'route-table',
	'ARP',
	'speaks-with'
];

/**
 * edgeTypeCounts (#583): per-protocol edge totals for the current graph,
 * ordered by PROTOCOL_ORDER (unknown protocols sort last, alphabetically).
 * The legend lists only what actually appears on the canvas.
 */
export function edgeTypeCounts(links: GraphLink[]): Array<{ protocol: string; count: number }> {
	const counts = new Map<string, number>();
	for (const l of links) {
		counts.set(l.protocol, (counts.get(l.protocol) ?? 0) + 1);
	}
	return [...counts.entries()]
		.map(([protocol, count]) => ({ protocol, count }))
		.sort(
			(a, b) =>
				(PROTOCOL_ORDER.indexOf(a.protocol) + 1 || PROTOCOL_ORDER.length + a.protocol.charCodeAt(0)) -
				(PROTOCOL_ORDER.indexOf(b.protocol) + 1 || PROTOCOL_ORDER.length + b.protocol.charCodeAt(0))
		);
}

/**
 * Edge freshness thresholds (#585): how long an adjacency may go unobserved
 * before the graph treats it as a ghost. Generic edges use 10 minutes (a
 * generous 2× a typical scan cycle); WiFi associations fade at half that —
 * associations are far more volatile than wiring facts and a departed client
 * simply stops refreshing the edge (#539 left the data side correct; this is
 * the UI half).
 */
export const STALE_EDGE_MS = 10 * 60 * 1000;
export const WIFI_STALE_MS = 5 * 60 * 1000;

/** Age of an edge in ms, or null when unknown (no/invalid lastSeen). */
export function edgeAgeMs(l: Pick<GraphLink, 'protocol' | 'lastSeen'>, now = Date.now()): number | null {
	if (!l.lastSeen) return null;
	const t = Date.parse(l.lastSeen);
	if (Number.isNaN(t)) return null;
	return Math.max(0, now - t);
}

/** Staleness verdict for an edge (#585): past its protocol's threshold. */
export function isStaleEdge(
	l: Pick<GraphLink, 'protocol' | 'lastSeen'>,
	now = Date.now()
): boolean {
	const age = edgeAgeMs(l, now);
	if (age === null) return false;
	return age > (l.protocol === 'WiFi' ? WIFI_STALE_MS : STALE_EDGE_MS);
}

/**
 * splitOrphans (#584): partition nodes into connected (degree > 0 or the
 * root — the root is the graph's anchor and stays on the canvas even in the
 * degenerate no-edge case) versus orphans (degree 0). Orphan oceans are the
 * default deployment shape: without LLDP/Bridge/WiFi/flow sources the graph
 * shows an ARP star at best and everything else floats alone, conveying
 * nothing a device list doesn't already say.
 */
export function splitOrphans(nodes: GraphNode[]): { connected: GraphNode[]; orphans: GraphNode[] } {
	const connected: GraphNode[] = [];
	const orphans: GraphNode[] = [];
	for (const gn of nodes) {
		if (gn.degree > 0 || gn.isRoot) connected.push(gn);
		else orphans.push(gn);
	}
	return { connected, orphans };
}

/** The edge families the enrichment hints (#584) know how to light up. */
export type EnrichmentFamily = 'wifi' | 'traffic' | 'snmp';

/**
 * missingEnrichmentFamilies (#584): which data-source families the current
 * graph has ZERO edges from — the actionable gap, in display order. WiFi
 * associations (hostapd), device-to-device traffic (passive observation),
 * and managed-switch wiring (SNMP walks) are all existing capabilities the
 * default deployment simply hasn't turned on; the hints link to the
 * settings page where each source is enabled.
 */
export function missingEnrichmentFamilies(links: GraphLink[]): EnrichmentFamily[] {
	const present = new Set(links.map((l) => l.protocol));
	const missing: EnrichmentFamily[] = [];
	if (!present.has('WiFi')) missing.push('wifi');
	if (!present.has('speaks-with')) missing.push('traffic');
	if (
		!present.has('LLDP') &&
		!present.has('CDP') &&
		!present.has('Bridge-MIB') &&
		!present.has('Q-BRIDGE-MIB')
	) {
		missing.push('snmp');
	}
	return missing;
}

/** Endpoint types that live at the network edge (leaves). */
const ENDPOINT_TYPES = new Set([
	'pc',
	'camera',
	'phone',
	'printer',
	'iot',
	'embedded'
]);

/** Infrastructure types that form the core/distribution layer. */
const CORE_TYPES = new Set(['switch', 'router', 'firewall']);

/**
 * detectRoot picks the topology root: the device that should sit at the top of
 * the visualization. The collected STP fact wins outright when present (#525):
 * a bridge whose dot1dStp walk says "I am the root" IS the root, no guessing.
 * Otherwise heuristic, in priority order:
 *   1. Highest ARP in-degree (the gateway most devices ARP toward), preferring
 *      an explicit router-typed node among ties.
 *   2. Any router-typed node (when no ARP edges exist).
 *   3. Highest-degree node, preferring an IP ending in .1 (LAN gateway convention).
 *
 * Unchanged from topologyTree.ts: just relocated so both detectRoot + buildGraph
 * live in the force-graph module.
 */
export function detectRoot(graph: TopologyGraph): TopoNode | null {
	const { nodes, edges } = graph;

	if (nodes.length === 0) {
		return null;
	}

	// --- Pass 0: the collected STP root fact (#525) ---
	const stpRoot = nodes.find((n) => n.stp_root === true);
	if (stpRoot) {
		return stpRoot;
	}

	const macToNodeId = new Map<string, number>();
	for (const node of nodes) {
		macToNodeId.set(node.mac_address.toLowerCase(), node.id);
	}

	// --- Pass 1: ARP in-degree (who do devices point at via ARP?) ---
	const arpInDegree = new Map<number, number>();
	for (const node of nodes) {
		arpInDegree.set(node.id, 0);
	}

	for (const edge of edges) {
		if (edge.protocol !== 'ARP') continue;

		const toMac = edge.to_mac.toLowerCase();
		const toId = edge.to_device_id;

		const matchedByMac = macToNodeId.get(toMac);
		if (matchedByMac !== undefined) {
			arpInDegree.set(matchedByMac, (arpInDegree.get(matchedByMac) ?? 0) + 1);
		}

		if (toId !== null && toId !== undefined) {
			arpInDegree.set(toId, (arpInDegree.get(toId) ?? 0) + 1);
		}
	}

	const maxArpDegree = arpInDegree.size > 0 ? Math.max(...arpInDegree.values()) : 0;
	if (maxArpDegree >= 1) {
		const candidates = nodes.filter((n) => (arpInDegree.get(n.id) ?? 0) === maxArpDegree);
		const routerCandidate = candidates.find((n) => {
			const infType = n.inferred_type?.toLowerCase() ?? '';
			const type = n.type?.toLowerCase() ?? '';
			return infType.includes('router') || type.includes('router');
		});
		if (routerCandidate) {
			return routerCandidate;
		}
		return candidates[0];
	}

	// --- Pass 2: any router-typed node ---
	const routerNode = nodes.find((n) => {
		const infType = n.inferred_type?.toLowerCase() ?? '';
		const type = n.type?.toLowerCase() ?? '';
		return infType === 'router' || type === 'router';
	});
	if (routerNode) {
		return routerNode;
	}

	// --- Pass 3: highest undirected degree, prefer .1 IP ---
	const degree = new Map<number, number>();
	for (const node of nodes) {
		degree.set(node.id, 0);
	}

	for (const edge of edges) {
		const from = edge.from_device_id;
		degree.set(from, (degree.get(from) ?? 0) + 1);

		if (edge.to_device_id !== null && edge.to_device_id !== undefined) {
			degree.set(edge.to_device_id, (degree.get(edge.to_device_id) ?? 0) + 1);
		}
	}

	const maxDegree = degree.size > 0 ? Math.max(...degree.values()) : 0;
	const highDegreeNodes = nodes.filter((n) => (degree.get(n.id) ?? 0) === maxDegree);

	const dotOneNode = highDegreeNodes.find((n) => n.ip_address.endsWith('.1'));
	if (dotOneNode) {
		return dotOneNode;
	}

	return highDegreeNodes[0];
}

/**
 * classifyLayer assigns a heuristic layer to a node. The root (already chosen
 * by detectRoot) is always `root`; otherwise the device type drives it:
 *   - switch/router/firewall → core
 *   - endpoint types (pc/camera/phone/...) → edge
 *   - everything else (server/nas/other) → access (middle)
 *
 * The inferred_type (from scan_vendor/scan_os) is preferred over the hand-set
 * `type` field because it's what the scanner actually detected.
 */
function classifyLayer(node: TopoNode, isRoot: boolean): TopoLayer {
	if (isRoot) return 'root';
	const t = (node.inferred_type || node.type || 'other').toLowerCase();
	// inferred_type may carry a richer string ("cisco router"); check substring.
	const isCore = [...CORE_TYPES].some((c) => t.includes(c));
	if (isCore) return 'core';
	const isEndpoint = [...ENDPOINT_TYPES].some((c) => t.includes(c));
	if (isEndpoint) return 'edge';
	return 'access';
}

/**
 * isSegmentBridge: the node is present in more than one network per the
 * collected multi-homed presence facts (#526) — a cross-segment link point
 * (#556). Dual-NIC routers, the box bridging two LANs, a federated segment's
 * interconnect: these are the nodes that join otherwise separate clusters.
 */
export function isSegmentBridge(node: TopoNode): boolean {
	return (node.networks?.length ?? 0) > 1;
}

/**
 * formatPresence renders one presence entry for the node card (#556):
 * "lan-63 · 192.0.2.0/24 · 192.0.2.5", degrading gracefully — no name
 * hydration → "#3 · 192.0.2.0/24 · …"; no cidr → name + address only.
 */
export function formatPresence(pn: NonNullable<TopoNode['networks']>[number]): string {
	const seg = pn.name || `#${pn.network_id}`;
	return pn.cidr ? `${seg} · ${pn.cidr} · ${pn.ip_address}` : `${seg} · ${pn.ip_address}`;
}

/**
 * buildGraph turns the raw /topology API response into the force-graph payload.
 *
 * Unlike the old buildTree, this preserves EVERY edge (including cycle-closing
 * cross-links and edges to unidentified neighbors): a `graph` series renders
 * mesh topologies that a `tree` series cannot.
 *
 * Degree is undirected (counts both endpoints of each link) and is the basis
 * for node sizing in the visualization.
 */
export function buildGraph(graph: TopologyGraph): GraphBuildResult {
	const { nodes, edges } = graph;

	const empty: GraphBuildResult = {
		nodes: [],
		links: [],
		layers: { root: [], core: [], access: [], edge: [] },
		rootId: null
	};

	if (nodes.length === 0) {
		return empty;
	}

	// MAC → nodeId index for resolving unidentified-neighbor edges.
	const macToNodeId = new Map<string, number>();
	for (const node of nodes) {
		macToNodeId.set(node.mac_address.toLowerCase(), node.id);
	}

	// Resolve every edge to a numeric target (or mark unidentified).
	interface ResolvedEdge {
		from: number;
		to: number | null; // null = unidentified neighbor
		edge: TopoEdge;
	}
	const resolved: ResolvedEdge[] = [];
	for (const edge of edges) {
		const from = edge.from_device_id;
		let to: number | null = null;
		if (edge.to_device_id !== null && edge.to_device_id !== undefined) {
			to = edge.to_device_id;
		} else {
			const matched = macToNodeId.get(edge.to_mac.toLowerCase());
			if (matched !== undefined) to = matched;
		}
		if (from === to) continue; // self-loop
		resolved.push({ from, to, edge });
	}

	// Undirected degree (count both ends). Unidentified edges count only the from side.
	const degree = new Map<number, number>();
	for (const node of nodes) degree.set(node.id, 0);
	for (const { from, to } of resolved) {
		degree.set(from, (degree.get(from) ?? 0) + 1);
		if (to !== null) degree.set(to, (degree.get(to) ?? 0) + 1);
	}

	// Detect root, then classify every node into a layer.
	const root = detectRoot(graph);
	const rootId = root?.id ?? null;

	const graphNodes: GraphNode[] = nodes.map((node) => {
		const isRoot = root !== null && node.id === root.id;
		const layer = classifyLayer(node, isRoot);
		return {
			id: node.id,
		name: node.name || node.ip_address || `#${node.id}`,
		value: node,
		degree: degree.get(node.id) ?? 0,
		layer,
		category: LAYER_ORDER.indexOf(layer),
		isRoot,
		isBridge: isSegmentBridge(node)
	};
});

	// BFS from root (then any unreached node) to mark cross-links (cycle-closing
	// edges). This mirrors the old buildTree's cross-link detection: a tree edge
	// reaches an unvisited node; a non-tree edge (to an already-visited node) is
	// a cross-link. BOTH are emitted as graph links: only the flag differs.
	const visited = new Set<number>();
	const crossLinkSet = new Set<string>(); // "from>to" keys

	function bfsFrom(startId: number): void {
		const queue: number[] = [startId];
		visited.add(startId);
		while (queue.length > 0) {
			const cur = queue.shift()!;
			// Out-edges from cur that resolve to a known device.
			for (const { from, to } of resolved) {
				if (from !== cur || to === null) continue;
				if (visited.has(to)) {
					crossLinkSet.add(`${from}>${to}`);
				} else {
					visited.add(to);
					queue.push(to);
				}
			}
		}
	}

	if (rootId !== null) bfsFrom(rootId);
	for (const node of nodes) {
		if (!visited.has(node.id)) bfsFrom(node.id);
	}

	// Build the link list. Include edges to unidentified neighbors (to=null);
	// they render as dashed links to a synthetic "unknown" stub in the component.
	const links: GraphLink[] = [];
	for (const { from, to, edge } of resolved) {
		const isUnidentified = to === null;
		const targetId = to ?? -1; // -1 = unidentified stub (component handles)
		links.push({
			source: from,
			target: targetId,
			protocol: edge.protocol,
			localPort: edge.local_port,
			remotePort: edge.remote_port,
			isCrossLink: to !== null && crossLinkSet.has(`${from}>${to}`),
			isUnidentified,
			toMac: isUnidentified ? edge.to_mac : null,
			bytes: edge.bytes ?? null,
			lastSeen: edge.last_seen ?? null
		});
	}

	// Group node ids by layer (for collapse/expand controls + legend counts).
	const layers: Record<TopoLayer, number[]> = { root: [], core: [], access: [], edge: [] };
	for (const gn of graphNodes) {
		layers[gn.layer].push(gn.id);
	}

	return { nodes: graphNodes, links, layers, rootId };
}

/**
 * recommendedForceParams tunes the force-layout constants by node count.
 * ECharts force is O(n²) repulsion; on large graphs we trade animation smoothness
 * for stability by lowering repulsion and disabling layoutAnimation.
 *
 * Thresholds are empirical (issue #136 acceptance: 50+ nodes render smoothly).
 */
export function recommendedForceParams(nodeCount: number): {
	repulsion: number;
	edgeLength: [number, number];
	gravity: number;
	layoutAnimation: boolean;
	labelDensity: 'all' | 'core' | 'none';
} {
	if (nodeCount > 80) {
		return {
			repulsion: 80,
			edgeLength: [40, 100],
			gravity: 0.25,
			layoutAnimation: false,
			labelDensity: 'core'
		};
	}
	if (nodeCount > 40) {
		return {
			repulsion: 120,
			edgeLength: [50, 130],
			gravity: 0.15,
			layoutAnimation: true,
			labelDensity: 'core'
		};
	}
	return {
		repulsion: 200,
		edgeLength: [60, 160],
		gravity: 0.1,
		layoutAnimation: true,
		labelDensity: 'all'
	};
}

// ---------------------------------------------------------------------------
// Shared visual rules (#635 PR1): renderer-agnostic style verdicts.
//
// The 2D canvas (ECharts) and the future 3D renderer (three.js) must render
// the SAME decisions — node size, ring badges, label budgets, the edge
// opacity ladder, search dimming. These pure functions/tables express each
// rule once, in theme-token form (CSS variable name + hex fallback); each
// renderer resolves tokens to concrete colors itself (canvas contexts can't
// parse var()). Keep anything DOM- or i18n-dependent OUT of this module.
// ---------------------------------------------------------------------------

/** A color expressed as a CSS-variable token plus a hard hex fallback. */
export interface TokenColor {
	token: string;
	fallback: string;
}

/**
 * Layer → fill color. root = amber (the gateway must stand out), core = blue,
 * access = purple, edge = grey (endpoints blend in).
 */
export const LAYER_COLORS: Record<TopoLayer, TokenColor> = {
	root: { token: '--color-warning', fallback: '#f59e0b' },
	core: { token: '--color-info', fallback: '#3b82f6' },
	access: { token: '--color-accent-purple', fallback: '#8b5cf6' },
	edge: { token: '--color-muted', fallback: '#64748b' }
};

/**
 * Protocol → line color/dash/width. High-confidence L2 (LLDP/CDP) = green
 * solid; Bridge-MIB = blue solid; STP = purple dashed; ARP (L3,
 * low-confidence) = grey dotted. route-table has no entry yet (#640) and
 * falls through to the muted-solid default.
 */
export interface ProtocolStyle {
	color: TokenColor;
	dash: 'solid' | 'dashed' | 'dotted';
	width: number;
}

export const PROTOCOL_STYLES: Record<string, ProtocolStyle> = {
	LLDP: { color: { token: '--color-success', fallback: '#10b981' }, dash: 'solid', width: 2 },
	CDP: { color: { token: '--color-success', fallback: '#10b981' }, dash: 'solid', width: 2 },
	'Bridge-MIB': { color: { token: '--color-info', fallback: '#3b82f6' }, dash: 'solid', width: 1.5 },
	'Q-BRIDGE-MIB': { color: { token: '--color-info', fallback: '#3b82f6' }, dash: 'solid', width: 1.5 },
	STP: { color: { token: '--color-accent-purple', fallback: '#8b5cf6' }, dash: 'dashed', width: 1.5 },
	// WiFi (#505): hostapd association observed on the AP — its own class,
	// amber dashed, as the release notes have always described.
	WiFi: { color: { token: '--color-accent-amber', fallback: '#f59e0b' }, dash: 'dashed', width: 1.5 },
	ARP: { color: { token: '--color-muted', fallback: '#94a3b8' }, dash: 'dotted', width: 1 },
	// speaks-with (#500): L3 traffic observation — visually the faintest
	// class (corroborating relation, not a link fact).
	'speaks-with': { color: { token: '--color-info', fallback: '#38bdf8' }, dash: 'dotted', width: 1 }
};

/** Line style for any protocol string; unknown protocols get muted solid. */
export function protocolStyle(protocol: string): ProtocolStyle {
	return (
		PROTOCOL_STYLES[protocol] ?? {
			color: { token: '--color-muted', fallback: '#94a3b8' },
			dash: 'solid',
			width: 1
		}
	);
}

/** Node glyph size: the root is a fixed 44; others scale with degree,
 *  clamped to 16–40. */
export function nodeSize(gn: Pick<GraphNode, 'isRoot' | 'degree'>): number {
	return gn.isRoot ? 44 : Math.max(16, Math.min(40, 12 + gn.degree * 2));
}

/**
 * Node ring badge (#556): the root keeps its amber gateway ring, a
 * multi-segment bridge gets a blue one (root wins when both apply); plain
 * nodes get none.
 */
export function nodeRing(gn: Pick<GraphNode, 'isRoot' | 'isBridge'>): { color: TokenColor; width: number } | null {
	if (gn.isRoot) return { color: { token: '--color-warning', fallback: '#f59e0b' }, width: 3 };
	if (gn.isBridge) return { color: { token: '--color-primary', fallback: '#3b82f6' }, width: 2 };
	return null;
}

/**
 * Label visibility by density budget: 'all' labels every node; 'core' only
 * the root/core layers (medium+ graphs); 'none' labels nothing.
 */
export function nodeLabelVisible(gn: Pick<GraphNode, 'layer'>, density: 'all' | 'core' | 'none'): boolean {
	if (density === 'all') return true;
	if (density === 'none') return false;
	return gn.layer === 'root' || gn.layer === 'core';
}

/**
 * The edge opacity ladder (#583/#585) as one pure verdict. Weak evidence
 * (ARP/speaks-with) starts fainter; staleness and an offline endpoint each
 * multiply another 0.4 in; a cross-link renders as a half-tone secondary
 * line INSTEAD of the ladder; an active search dims everything to
 * near-invisible first.
 */
export function edgeOpacity(
	link: Pick<GraphLink, 'protocol' | 'isCrossLink'>,
	state: { stale?: boolean; offlineEnd?: boolean; dimmed?: boolean } = {}
): number {
	if (state.dimmed) return 0.1;
	if (link.isCrossLink) return 0.5;
	let opacity = WEAK_PROTOCOLS.has(link.protocol) ? 0.4 : 0.8;
	if (state.stale) opacity *= 0.4;
	if (state.offlineEnd) opacity *= 0.4;
	return opacity;
}

/** Node opacity while a search is active and the node is not part of the
 *  highlight set (#… search dimming). */
export const SEARCH_DIM_NODE_OPACITY = 0.15;

/**
 * Which node ids stay lit for a search query: matches on name / IP / MAC
 * (case-insensitive substring) plus the direct neighbors of every match, so
 * a matched node's context survives the dimming. Empty query → empty set
 * (nothing is dimmed).
 */
export function searchHighlightSet(
	nodes: Array<Pick<GraphNode, 'id' | 'value'>>,
	links: Array<Pick<GraphLink, 'source' | 'target'>>,
	query: string
): Set<number> {
	if (!query) return new Set();
	const q = query.toLowerCase();
	const matched = new Set<number>();
	for (const gn of nodes) {
		const n = gn.value;
		if (
			(n.name || '').toLowerCase().includes(q) ||
			(n.ip_address || '').toLowerCase().includes(q) ||
			(n.mac_address || '').toLowerCase().includes(q)
		) {
			matched.add(gn.id);
		}
	}
	const highlighted = new Set(matched);
	for (const link of links) {
		if (matched.has(link.source)) highlighted.add(link.target);
		if (matched.has(link.target)) highlighted.add(link.source);
	}
	return highlighted;
}

/** Synthetic node id for the collapsed orphan group (#584): real device ids
 *  are numeric strings, so this can never collide. */
export const ORPHAN_GROUP_ID = 'orphans-group';

/** One synthetic canvas node for an unidentified neighbor (#636): all edges
 *  pointing at the same unseen MAC collapse onto one stub. */
export interface UnknownNeighborStub {
	/** ECharts node id; never collides with numeric device ids. */
	id: string;
	/** The MAC the far end reported ('(unknown)' when the edge carried none). */
	mac: string;
	/** How many visible links point at this stub. */
	linkCount: number;
}

/**
 * unknownNeighborStubs (#636): edges to unidentified neighbors used to be
 * silently dropped by the renderer (their target device doesn't exist) while
 * the legend still counted them. Grouping them by to_mac gives the canvas one
 * dashed stub node per unseen MAC to hang those links on. Feed it the
 * ALREADY-FILTERED link list so stubs appear only when their links do.
 */
export function unknownNeighborStubs(
	links: Array<Pick<GraphLink, 'isUnidentified' | 'toMac'>>
): UnknownNeighborStub[] {
	const byMac = new Map<string, number>();
	for (const l of links) {
		if (!l.isUnidentified) continue;
		const mac = l.toMac || '(unknown)';
		byMac.set(mac, (byMac.get(mac) ?? 0) + 1);
	}
	return [...byMac.entries()].map(([mac, linkCount]) => ({ id: `unknown:${mac}`, mac, linkCount }));
}

/**
 * topologyFingerprint (#637): change-detector for the topology payload.
 * Covers STRUCTURE (node ids, edge endpoints/protocols) and everything that
 * drives time-sensitive rendering — per-edge last_seen and per-node status —
 * so a silent poll actually delivers freshness updates instead of
 * short-circuiting on an unchanged skeleton (the #637 bug: ghost edges never
 * faded on a static page because the signature ignored last_seen).
 * Order-insensitive (both sides sort); array order churn must not rebuild.
 */
export function topologyFingerprint(g: TopologyGraph): string {
	const nodeKeys = g.nodes
		.map((n) => `${n.id}:${n.status ?? ''}`)
		.sort()
		.join(',');
	const edgeKeys = g.edges
		.map((e) => `${e.from_device_id}>${e.to_device_id ?? e.to_mac}:${e.protocol}@${e.last_seen ?? ''}`)
		.sort()
		.join(',');
	return `${g.nodes.length}|${g.edges.length}|${nodeKeys}|${edgeKeys}`;
}
