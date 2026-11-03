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
	edgeTypeCounts,
	WEAK_PROTOCOLS,
	isStaleEdge,
	edgeAgeMs,
	STALE_EDGE_MS,
	WIFI_STALE_MS,
	splitOrphans,
	missingEnrichmentFamilies,
	recommendedForceParams,
	LAYER_ORDER,
	isSegmentBridge,
	formatPresence,
	protocolStyle,
	nodeSize,
	nodeRing,
	nodeLabelVisible,
	edgeOpacity,
	searchHighlightSet,
	LAYER_COLORS
} from '$lib/utils/topologyGraph';
import type { TopologyGraph, TopoNode, TopoEdge } from '$lib/types';

// Helpers: build wire-shaped fixtures with sensible defaults. The nullable
// fields (to_device_id / local_port / remote_port / network_id) are ALWAYS
// present on the wire (null when unknown): the fixtures mirror that.

function node(over: Partial<TopoNode> & Pick<TopoNode, 'id'>): TopoNode {
	return {
		name: `node-${over.id}`,
		ip_address: `10.0.0.${over.id}`,
		mac_address: `00:00:00:00:00:${over.id.toString(16).padStart(2, '0')}`,
		type: 'other',
		status: 'online',
		inferred_type: 'other',
		brand: '',
		network_id: null,
		...over
	};
}

function edge(over: Partial<TopoEdge> & Pick<TopoEdge, 'from_device_id' | 'to_mac'>): TopoEdge {
	return {
		to_device_id: null,
		protocol: 'LLDP',
		local_port: null,
		remote_port: null,
		...over
	};
}

describe('topologyGraph', () => {
	describe('detectRoot', () => {
		it('1. Empty graph → returns null', () => {
			const graph: TopologyGraph = { nodes: [], edges: [] };
			expect(detectRoot(graph)).toBeNull();
		});

		it('0. STP root fact wins over every heuristic (#525)', () => {
			// A hub-and-spoke ARP star that would pick the router by in-degree —
			// but a downstream switch reports dot1dStp facts naming ITSELF the
			// root bridge. The collected fact beats the guess.
			const graph: TopologyGraph = {
				nodes: [
					node({ id: 1, name: 'Gateway', ip_address: '192.168.1.1', type: 'router', inferred_type: 'router' }),
					node({ id: 2, name: 'core-sw', inferred_type: 'switch', stp_root: true }),
					node({ id: 3, ip_address: '192.168.1.11', inferred_type: 'pc' })
				],
				edges: [
					edge({ from_device_id: 3, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' })
				]
			};
			const root = detectRoot(graph);
			expect(root?.id).toBe(2);
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
					edge({ from_device_id: 2, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' }),
					edge({ from_device_id: 3, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' }),
					edge({ from_device_id: 4, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' })
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
					edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
					edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' }),
					edge({ from_device_id: 2, to_device_id: 4, to_mac: '00:00:00:00:00:04', protocol: 'LLDP' })
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
					edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
					edge({ from_device_id: 1, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' })
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
					edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP', local_port: 'Gi0/1', remote_port: 'Gi1/0/24' }),
					edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP', local_port: 'Gi1/0/1' })
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
					edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
					edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' }),
					edge({ from_device_id: 3, to_device_id: 1, to_mac: '00:00:00:00:00:01', protocol: 'LLDP' })
				]
			};
			const result = buildGraph(graph);
			// ALL 3 links preserved (tree would drop 1): key graph-vs-tree win.
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
					edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
					edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' }),
					edge({ from_device_id: 2, to_device_id: 4, to_mac: '00:00:00:00:00:04', protocol: 'LLDP' })
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
				edges: [edge({ from_device_id: 1, to_mac: 'ff:ff:ff:ff:ff:ff', protocol: 'LLDP' })]
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
					edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
					edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' })
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
				edges: [edge({ from_device_id: 1, to_device_id: 1, to_mac: '00:00:00:00:00:01', protocol: 'LLDP' })]
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

describe('speaks-with edges (#500)', () => {
	it('carries the byte total through to the link', () => {
		const graph: TopologyGraph = {
			nodes: [node({ id: 1 }), node({ id: 2 })],
			edges: [
				edge({ from_device_id: 1, to_mac: '00:00:00:00:00:02', to_device_id: 2, protocol: 'speaks-with', bytes: 123456 }),
				edge({ from_device_id: 2, to_mac: '00:00:00:00:00:01', to_device_id: 1, protocol: 'speaks-with', bytes: 654321 })
			]
		};
		const res = buildGraph(graph);
		expect(res.links).toHaveLength(2);
		expect(res.links.find((l) => l.source === 1)?.bytes).toBe(123456);
		expect(res.links.find((l) => l.source === 2)?.bytes).toBe(654321);
		// both endpoints known: solid graph edges, not unidentified stubs
		expect(res.links.every((l) => !l.isUnidentified)).toBe(true);
	});
});

describe('cross-segment bridges (#556)', () => {
	const presence = (network_id: number, ip: string, name?: string, cidr?: string) => ({
		network_id,
		ip_address: ip,
		last_seen: '2026-10-13T00:05:00Z',
		vantage: '',
		...(name !== undefined ? { name } : {}),
		...(cidr !== undefined ? { cidr } : {})
	});

	it('isSegmentBridge: only multi-presence nodes are bridges', () => {
		expect(isSegmentBridge(node({ id: 1 }))).toBe(false);
		expect(isSegmentBridge(node({ id: 1, networks: [] }))).toBe(false);
		expect(isSegmentBridge(node({ id: 1, networks: [presence(1, '192.0.2.1')] }))).toBe(false);
		expect(
			isSegmentBridge(node({ id: 1, networks: [presence(1, '192.0.2.1'), presence(2, '198.51.100.1')] }))
		).toBe(true);
	});

	it('formatPresence: name · cidr · ip, with fallbacks when hydration degraded', () => {
		expect(formatPresence(presence(3, '192.0.2.5', 'lan-a', '192.0.2.0/24'))).toBe(
			'lan-a · 192.0.2.0/24 · 192.0.2.5'
		);
		// name lookup failed → raw id, cidr still there
		expect(formatPresence(presence(3, '192.0.2.5', '', '192.0.2.0/24'))).toBe('#3 · 192.0.2.0/24 · 192.0.2.5');
		// no cidr at all → segment + address
		expect(formatPresence(presence(3, '192.0.2.5'))).toBe('#3 · 192.0.2.5');
	});

	it('buildGraph flags bridge nodes so the view can style them', () => {
		const res = buildGraph({
			nodes: [
				node({ id: 1, networks: [presence(1, '192.0.2.1'), presence(2, '198.51.100.1')] }),
				node({ id: 2, networks: [presence(1, '192.0.2.9')] })
			],
			edges: []
		});
		expect(res.nodes.find((n) => n.id === 1)?.isBridge).toBe(true);
		expect(res.nodes.find((n) => n.id === 2)?.isBridge).toBe(false);
	});
});

// #583: the edge-type legend is driven by what actually appears in the graph.
describe('edgeTypeCounts (#583)', () => {
	it('counts per protocol, unknown protocols included, hard facts first', () => {
		const links = [
			{ source: 1, target: 2, protocol: 'ARP' },
			{ source: 1, target: 3, protocol: 'ARP' },
			{ source: 2, target: 3, protocol: 'LLDP' },
			{ source: 4, target: 5, protocol: 'speaks-with' },
			{ source: 6, target: 7, protocol: 'WiFi' },
			{ source: 8, target: 9, protocol: 'ZZZ-future' }
		] as Array<{ source: number; target: number; protocol: string }>;
		const stats = edgeTypeCounts(links as never[]);
		// Hard wiring facts first, weak evidence last, unknown protocols
		// after everything known (alphabetically among themselves).
		expect(stats.map((s) => s.protocol)).toEqual([
			'LLDP',
			'WiFi',
			'ARP',
			'speaks-with',
			'ZZZ-future'
		]);
		expect(stats.find((s) => s.protocol === 'ARP')?.count).toBe(2);
	});

	it('returns an empty list for an empty graph', () => {
		expect(edgeTypeCounts([])).toEqual([]);
	});

	it('weak-evidence set covers ARP and speaks-with only', () => {
		expect(WEAK_PROTOCOLS.has('ARP')).toBe(true);
		expect(WEAK_PROTOCOLS.has('speaks-with')).toBe(true);
		expect(WEAK_PROTOCOLS.has('LLDP')).toBe(false);
		expect(WEAK_PROTOCOLS.has('WiFi')).toBe(false);
	});
});

// #585: edges carry freshness; ghosts fade, unknown age never does.
describe('edge freshness (#585)', () => {
	const now = Date.parse('2026-10-14T12:00:00Z');

	it('buildGraph carries last_seen onto links', () => {
		const g: TopologyGraph = {
			nodes: [node({ id: 1, mac_address: 'aa:aa:aa:aa:aa:01' }), node({ id: 2, mac_address: 'aa:aa:aa:aa:aa:02' })],
			edges: [
				edge({
					from_device_id: 1,
					to_device_id: 2,
					to_mac: 'aa:aa:aa:aa:aa:02',
					protocol: 'WiFi',
					last_seen: '2026-10-14T11:30:00Z'
				})
			]
		} as unknown as TopologyGraph;
		const built = buildGraph(g);
		expect(built.links).toHaveLength(1);
		expect(built.links[0].lastSeen).toBe('2026-10-14T11:30:00Z');
	});

	it('generic edge is stale past 10 minutes', () => {
		expect(isStaleEdge({ protocol: 'LLDP', lastSeen: new Date(now - STALE_EDGE_MS - 1).toISOString() }, now)).toBe(true);
		expect(isStaleEdge({ protocol: 'LLDP', lastSeen: new Date(now - STALE_EDGE_MS + 60000).toISOString() }, now)).toBe(false);
	});

	it('WiFi edges use the shorter 5-minute threshold (associations are volatile)', () => {
		const sixMinAgo = new Date(now - WIFI_STALE_MS - 60000).toISOString();
		expect(isStaleEdge({ protocol: 'WiFi', lastSeen: sixMinAgo }, now)).toBe(true);
		// The same age on a generic edge is still fresh.
		expect(isStaleEdge({ protocol: 'LLDP', lastSeen: sixMinAgo }, now)).toBe(false);
	});

	it('unknown or invalid age is never stale (no fading on missing data)', () => {
		expect(isStaleEdge({ protocol: 'WiFi', lastSeen: null }, now)).toBe(false);
		expect(isStaleEdge({ protocol: 'WiFi', lastSeen: '' }, now)).toBe(false);
		expect(isStaleEdge({ protocol: 'WiFi', lastSeen: 'not-a-date' }, now)).toBe(false);
		expect(edgeAgeMs({ protocol: 'LLDP', lastSeen: null }, now)).toBeNull();
	});
});

// #584: orphan census + enrichment gaps drive the collapsed group node and
// the actionable hints.
describe('orphan grouping and enrichment hints (#584)', () => {
	it('splitOrphans separates degree-0 nodes; the root always stays connected', () => {
		const g: TopologyGraph = {
			nodes: [
				node({ id: 1, mac_address: 'aa:aa:aa:aa:aa:01', inferred_type: 'router' }),
				node({ id: 2, mac_address: 'aa:aa:aa:aa:aa:02' }),
				node({ id: 3, mac_address: 'aa:aa:aa:aa:aa:03' }),
				node({ id: 4, mac_address: 'aa:aa:aa:aa:aa:04' })
			],
			edges: [
				edge({ from_device_id: 1, to_device_id: 2, to_mac: 'aa:aa:aa:aa:aa:02', protocol: 'LLDP' })
			]
		} as unknown as TopologyGraph;
		const built = buildGraph(g);
		const { connected, orphans } = splitOrphans(built.nodes);
		expect(connected.map((n) => n.id).sort()).toEqual([1, 2]);
		expect(orphans.map((n) => n.id).sort()).toEqual([3, 4]);
	});

	it('missingEnrichmentFamilies: empty graph misses all three; full graph misses none', () => {
		expect(missingEnrichmentFamilies([])).toEqual(['wifi', 'traffic', 'snmp']);
		const rich = [
			{ protocol: 'WiFi' },
			{ protocol: 'speaks-with' },
			{ protocol: 'LLDP' }
		].map((p) => ({ ...p, source: 1, target: 2 })) as never[];
		expect(missingEnrichmentFamilies(rich)).toEqual([]);
	});

	it('missingEnrichmentFamilies: WiFi alone lights wifi only (traffic + snmp still missing)', () => {
		const links = [{ source: 1, target: 2, protocol: 'WiFi' }] as never[];
		expect(missingEnrichmentFamilies(links)).toEqual(['traffic', 'snmp']);
	});
});

// #635 PR1: renderer-agnostic style verdicts — the 2D canvas and the future
// 3D renderer consume the same rules so the two views can never drift apart.
describe('shared visual rules (#635)', () => {
	it('protocolStyle: known protocols styled; unknown (incl. route-table today, #640) fall to muted solid', () => {
		const lldp = protocolStyle('LLDP');
		expect(lldp.color.token).toBe('--color-success');
		expect(lldp.dash).toBe('solid');
		expect(lldp.width).toBe(2);
		// route-table has no style entry yet (#640): pin the fallback so the
		// gap stays visible until the entry lands.
		const fallback = protocolStyle('route-table');
		expect(fallback.color.token).toBe('--color-muted');
		expect(fallback.dash).toBe('solid');
		expect(fallback.width).toBe(1);
	});

	it('LAYER_COLORS covers all four layers with token + hex fallback', () => {
		for (const layer of LAYER_ORDER) {
			const c = LAYER_COLORS[layer];
			expect(c.token.startsWith('--color-')).toBe(true);
			expect(c.fallback).toMatch(/^#[0-9a-f]{6}$/i);
		}
		expect(LAYER_COLORS.root.token).toBe('--color-warning'); // gateway = amber
	});

	it('nodeSize: root fixed 44; others scale with degree clamped 16–40', () => {
		expect(nodeSize({ isRoot: true, degree: 0 })).toBe(44);
		expect(nodeSize({ isRoot: false, degree: 0 })).toBe(16);
		expect(nodeSize({ isRoot: false, degree: 5 })).toBe(22);
		expect(nodeSize({ isRoot: false, degree: 99 })).toBe(40);
	});

	it('nodeRing: root wins over bridge; plain nodes get none', () => {
		expect(nodeRing({ isRoot: true, isBridge: true })?.color.token).toBe('--color-warning');
		expect(nodeRing({ isRoot: true, isBridge: true })?.width).toBe(3);
		expect(nodeRing({ isRoot: false, isBridge: true })?.color.token).toBe('--color-primary');
		expect(nodeRing({ isRoot: false, isBridge: true })?.width).toBe(2);
		expect(nodeRing({ isRoot: false, isBridge: false })).toBeNull();
	});

	it('nodeLabelVisible: density budgets gate which layers get labels', () => {
		expect(nodeLabelVisible({ layer: 'edge' }, 'all')).toBe(true);
		expect(nodeLabelVisible({ layer: 'edge' }, 'core')).toBe(false);
		expect(nodeLabelVisible({ layer: 'root' }, 'core')).toBe(true);
		expect(nodeLabelVisible({ layer: 'access' }, 'core')).toBe(false);
		expect(nodeLabelVisible({ layer: 'root' }, 'none')).toBe(false);
	});

	it('edgeOpacity ladder: weak starts fainter; stale/offline multiply in; cross-link replaces; search dims first', () => {
		const hard = { protocol: 'LLDP', isCrossLink: false };
		const weak = { protocol: 'ARP', isCrossLink: false };
		expect(edgeOpacity(hard)).toBe(0.8);
		expect(edgeOpacity(weak)).toBe(0.4);
		// Weak evidence + ghost (#585) compounds.
		expect(edgeOpacity(weak, { stale: true })).toBeCloseTo(0.16);
		// Stale AND offline endpoint: both factors apply.
		expect(edgeOpacity(hard, { stale: true, offlineEnd: true })).toBeCloseTo(0.8 * 0.4 * 0.4);
		// A cross-link is a half-tone secondary line, not the ladder.
		expect(edgeOpacity({ protocol: 'LLDP', isCrossLink: true }, { stale: true })).toBe(0.5);
		// An active search overrides everything.
		expect(edgeOpacity(hard, { dimmed: true })).toBe(0.1);
	});

	it('searchHighlightSet: name/IP/MAC matches + one-hop neighbors; empty query dims nothing', () => {
		const nodes = [
			{ id: 1, value: node({ id: 1, name: 'gateway', ip_address: '192.0.2.1', mac_address: 'aa:00:00:00:00:01' }) },
			{ id: 2, value: node({ id: 2, name: 'ap-2', ip_address: '192.0.2.2', mac_address: 'bb:00:00:00:00:02' }) },
			{ id: 3, value: node({ id: 3, name: 'cam', ip_address: '192.0.2.3', mac_address: 'cc:00:00:00:00:03' }) }
		];
		const links = [
			{ source: 1, target: 2 },
			{ source: 2, target: 3 }
		];
		// Name match, case-insensitive; node 1 is an endpoint of link 1-2.
		expect(searchHighlightSet(nodes, links, 'GATE')).toEqual(new Set([1, 2]));
		// IP match keeps the node + its one-hop neighbor.
		expect(searchHighlightSet(nodes, links, '192.0.2.3')).toEqual(new Set([2, 3]));
		// MAC match on the middle node lights both neighbors.
		expect(searchHighlightSet(nodes, links, 'bb:00')).toEqual(new Set([1, 2, 3]));
		// Empty query → nothing dimmed.
		expect(searchHighlightSet(nodes, links, '')).toEqual(new Set());
	});
});
