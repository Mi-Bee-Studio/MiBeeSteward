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
 * Layering is heuristic (no real STP root-bridge role in the data yet — the
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
	/** Numeric device id — ECharts graph uses this as the node id (coerced to string internally). */
	id: number;
	name: string;
	value: TopoNode;
	/** Undirected link count (both ends counted). Drives symbolSize. */
	degree: number;
	/** Heuristic layer — drives category (color/gravity) + legend. */
	layer: TopoLayer;
	/** ECharts category index (matches LAYER_ORDER). */
	category: number;
	/** True for the detectedRoot — gets the gateway glyph. */
	isRoot: boolean;
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
}

export interface GraphBuildResult {
	nodes: GraphNode[];
	links: GraphLink[];
	/** Node ids grouped by layer, for collapse/expand controls. */
	layers: Record<TopoLayer, number[]>;
	/** The detected root node id (null if graph is empty). */
	rootId: number | null;
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
 * detectRoot picks the topology root — the device that should sit at the top of
 * the visualization. Heuristic, in priority order:
 *   1. Highest ARP in-degree (the gateway most devices ARP toward), preferring
 *      an explicit router-typed node among ties.
 *   2. Any router-typed node (when no ARP edges exist).
 *   3. Highest-degree node, preferring an IP ending in .1 (LAN gateway convention).
 *
 * Unchanged from topologyTree.ts — just relocated so both detectRoot + buildGraph
 * live in the force-graph module.
 */
export function detectRoot(graph: TopologyGraph): TopoNode | null {
	const { nodes, edges } = graph;

	if (nodes.length === 0) {
		return null;
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
 * buildGraph turns the raw /topology API response into the force-graph payload.
 *
 * Unlike the old buildTree, this preserves EVERY edge (including cycle-closing
 * cross-links and edges to unidentified neighbors) — a `graph` series renders
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
			isRoot
		};
	});

	// BFS from root (then any unreached node) to mark cross-links (cycle-closing
	// edges). This mirrors the old buildTree's cross-link detection: a tree edge
	// reaches an unvisited node; a non-tree edge (to an already-visited node) is
	// a cross-link. BOTH are emitted as graph links — only the flag differs.
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

	// Build the link list. Include edges to unidentified neighbors (to=null) —
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
			isUnidentified
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
