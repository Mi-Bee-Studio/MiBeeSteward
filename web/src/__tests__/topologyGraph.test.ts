/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it } from 'vitest';
import {
	detectRoot,
	buildGraph,
	recommendedForceParams,
	LAYER_ORDER
} from '$lib/utils/topologyGraph';

// --- Inline type definitions (vitest may not resolve SvelteKit path aliases) ---

interface TopoNode {
	id: number;
	name: string;
	ip_address: string;
	mac_address: string;
	type: string;
	status: string;
	inferred_type: string;
	brand: string;
	network_id?: number | null;
}

interface TopoEdge {
	from_device_id: number;
	to_device_id?: number | null;
	to_mac: string;
	protocol: string;
	local_port?: string | null;
	remote_port?: string | null;
}

interface TopologyGraph {
	nodes: TopoNode[];
	edges: TopoEdge[];
}

// Helper: build a node with sensible defaults.
function node(over: Partial<TopoNode> & Pick<TopoNode, 'id'>): TopoNode {
	return {
		name: `node-${over.id}`,
		ip_address: `10.0.0.${over.id}`,
		mac_address: `00:00:00:00:00:${over.id.toString(16).padStart(2, '0')}`,
		type: 'other',
		status: 'online',
		inferred_type: 'other',
		brand: '',
		...over
	};
}

describe('topologyGraph', () => {
	describe('detectRoot', () => {
		it('1. Empty graph → returns null', () => {
			const graph: TopologyGraph = { nodes: [], edges: [] };
			expect(detectRoot(graph)).toBeNull();
		});

		it('2. ARP star → returns gateway with highest ARP in-degree', () => {
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, name: 'Gateway', ip_address: '192.168.1.1', mac_address: 'aa:bb:cc:dd:ee:ff', type: 'router', inferred_type: 'router' }),
					node({ id: 2, ip_address: '192.168.1.10', inferred_type: 'pc' }),
					node({ id: 3, ip_address: '192.168.1.11', inferred_type: 'pc' }),
					node({ id: 4, ip_address: '192.168.1.12', inferred_type: 'pc' })
				],
				edges: [
					{ from_device_id: 2, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' },
					{ from_device_id: 3, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' },
					{ from_device_id: 4, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' }
				]
			};
			const root = detectRoot(graph);
			expect(root).not.toBeNull();
			expect(root!.id).toBe(1);
		});

		it('3. LLDP hierarchy → returns the router-typed gateway', () => {
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, name: 'Gateway', ip_address: '192.168.1.1', mac_address: 'aa:bb:cc:dd:ee:ff', type: 'router', inferred_type: 'router' }),
					node({ id: 2, type: 'switch', inferred_type: 'switch' }),
					node({ id: 3, type: 'camera', inferred_type: 'camera' }),
					node({ id: 4, inferred_type: 'pc' })
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 4, to_mac: '00:00:00:00:00:04', protocol: 'LLDP' }
				]
			};
			expect(detectRoot(graph)!.id).toBe(1);
		});

		it('4. No ARP, no router type → falls back to highest degree, prefer .1 IP', () => {
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, ip_address: '10.0.0.1' }),
					node({ id: 2, ip_address: '10.0.0.2' }),
					node({ id: 3, ip_address: '10.0.0.3' })
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' },
					{ from_device_id: 1, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' }
				]
			};
			// node 1 has degree 2 (highest) + ends in .1 → root.
			expect(detectRoot(graph)!.id).toBe(1);
		});
	});

	describe('buildGraph', () => {
		it('1. Empty graph → empty result', () => {
			const result = buildGraph({ nodes: [], edges: [] });
			expect(result.nodes).toEqual([]);
			expect(result.links).toEqual([]);
			expect(result.rootId).toBeNull();
		});

		it('2. Nodes without edges → nodes present (degree 0), no links', () => {
			const graph: TopologyGraph = {
				nodes: [node({ id: 1 }), node({ id: 2 })],
				edges: []
			};
			const result = buildGraph(graph);
			expect(result.nodes.length).toBe(2);
			expect(result.links).toEqual([]);
			expect(result.nodes.every((n) => n.degree === 0)).toBe(true);
		});

		it('3. LLDP chain → all edges become links, degrees computed', () => {
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, type: 'router', inferred_type: 'router' }),
					node({ id: 2, type: 'switch', inferred_type: 'switch' }),
					node({ id: 3, type: 'camera', inferred_type: 'camera' })
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP', local_port: 'Gi0/1', remote_port: 'Gi1/0/24' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP', local_port: 'Gi1/0/1' }
				]
			};
			const result = buildGraph(graph);
			// Both edges are links (a graph renders all edges, not just a spanning tree).
			expect(result.links.length).toBe(2);
			// Degrees are undirected: router=1, switch=2, camera=1.
			const byId = new Map(result.nodes.map((n) => [n.id, n]));
			expect(byId.get(1)!.degree).toBe(1);
			expect(byId.get(2)!.degree).toBe(2);
			expect(byId.get(3)!.degree).toBe(1);
			// remote_port is carried through (issue #136 drill-down).
			expect(result.links[0].remotePort).toBe('Gi1/0/24');
			expect(result.links[0].localPort).toBe('Gi0/1');
			// None are cross-links (it's a tree).
			expect(result.links.every((l) => !l.isCrossLink)).toBe(true);
		});

		it('4. Cycle → all 3 edges present, exactly 1 cross-link', () => {
			const graph: TopologyGraph = {
				nodes: [node({ id: 1 }), node({ id: 2 }), node({ id: 3 })],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' },
					{ from_device_id: 3, to_device_id: 1, to_mac: '00:00:00:00:00:01', protocol: 'LLDP' }
				]
			};
			const result = buildGraph(graph);
			// ALL 3 links preserved (tree would drop 1) — key graph-vs-tree win.
			expect(result.links.length).toBe(3);
			expect(result.links.filter((l) => l.isCrossLink).length).toBe(1);
		});

		it('5. Layering → root/core/access/edge categories assigned by device type', () => {
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, type: 'router', inferred_type: 'router' }),
					node({ id: 2, type: 'switch', inferred_type: 'switch' }),
					node({ id: 3, type: 'camera', inferred_type: 'camera' }),
					node({ id: 4, type: 'other', inferred_type: 'nas' })
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 4, to_mac: '00:00:00:00:00:04', protocol: 'LLDP' }
				]
			};
			const result = buildGraph(graph);
			expect(result.rootId).toBe(1);
			const byId = new Map(result.nodes.map((n) => [n.id, n]));
			expect(byId.get(1)!.layer).toBe('root');
			expect(byId.get(1)!.isRoot).toBe(true);
			expect(byId.get(2)!.layer).toBe('core'); // switch
			expect(byId.get(3)!.layer).toBe('edge'); // camera (endpoint)
			expect(byId.get(4)!.layer).toBe('access'); // nas (not core, not endpoint)
			// Category indices match LAYER_ORDER.
			expect(byId.get(1)!.category).toBe(LAYER_ORDER.indexOf('root'));
			expect(byId.get(2)!.category).toBe(LAYER_ORDER.indexOf('core'));
		});

		it('6. Unidentified neighbor → link flagged isUnidentified, not dropped', () => {
			const graph: TopologyGraph = {
				nodes: [node({ id: 1, type: 'router', inferred_type: 'router' })],
				edges: [{ from_device_id: 1, to_mac: 'ff:ff:ff:ff:ff:ff', protocol: 'LLDP' }]
			};
			const result = buildGraph(graph);
			// The edge to an unknown MAC is preserved (graph renders it as a stub).
			expect(result.links.length).toBe(1);
			expect(result.links[0].isUnidentified).toBe(true);
		});

		it('7. layers grouping → node ids bucketed by layer', () => {
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, type: 'router', inferred_type: 'router' }),
					node({ id: 2, type: 'switch', inferred_type: 'switch' }),
					node({ id: 3, type: 'camera', inferred_type: 'camera' })
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' }
				]
			};
			const result = buildGraph(graph);
			expect(result.layers.root).toContain(1);
			expect(result.layers.core).toContain(2);
			expect(result.layers.edge).toContain(3);
			expect(result.layers.access).toEqual([]);
		});

		it('8. Self-loop → dropped (not a real link)', () => {
			const graph: TopologyGraph = {
				nodes: [node({ id: 1 })],
				edges: [{ from_device_id: 1, to_device_id: 1, to_mac: '00:00:00:00:00:01', protocol: 'LLDP' }]
			};
			const result = buildGraph(graph);
			expect(result.links).toEqual([]);
		});
	});

	describe('recommendedForceParams', () => {
		it('small graph (≤40) → full labels, animation on, high repulsion', () => {
			const p = recommendedForceParams(20);
			expect(p.labelDensity).toBe('all');
			expect(p.layoutAnimation).toBe(true);
			expect(p.repulsion).toBe(200);
		});

		it('medium graph (41–80) → core-only labels', () => {
			const p = recommendedForceParams(60);
			expect(p.labelDensity).toBe('core');
			expect(p.layoutAnimation).toBe(true);
			expect(p.repulsion).toBe(120);
		});

		it('large graph (>80) → core-only labels, animation OFF (perf)', () => {
			const p = recommendedForceParams(120);
			expect(p.labelDensity).toBe('core');
			expect(p.layoutAnimation).toBe(false);
			expect(p.repulsion).toBe(80); // lower to stabilize
		});
	});
});
