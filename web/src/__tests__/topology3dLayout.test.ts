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

import { describe, expect, it } from 'vitest';
import {
	LAYER_Y,
	layerY,
	nodeRadius,
	seedPosition,
	buildTopologyScene
} from '$lib/utils/topology3dLayout';
import { buildGraph, LAYER_ORDER } from '$lib/utils/topologyGraph';
import type { TopologyGraph, TopoNode, TopoEdge } from '$lib/types';

function node(over: Partial<TopoNode> & Pick<TopoNode, 'id'>): TopoNode {
	return {
		name: `node-${over.id}`,
		ip_address: `198.51.100.${over.id}`,
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
	return { to_device_id: null, protocol: 'LLDP', local_port: null, remote_port: null, ...over };
}
const allLayers = { root: true, core: true, access: true, edge: true } as const;
const opts = (over: Partial<Parameters<typeof buildTopologyScene>[1]> = {}) => ({
	search: '',
	layerVisible: { ...allLayers },
	bucketVisible: { network: true, camera: true, computer: true, mobile: true, iot: true, other: true },
	hiddenProtocols: {},
	expandOrphans: false,
	labelDensity: 'all' as const,
	colorMode: 'layer' as const,
	...over
});

describe('topology3dLayout (#635 PR2)', () => {
	it('layer bands: root on top, ordered downward, one band per layer', () => {
		expect(LAYER_Y.root).toBeGreaterThan(LAYER_Y.core);
		expect(LAYER_Y.core).toBeGreaterThan(LAYER_Y.access);
		expect(LAYER_Y.access).toBeGreaterThan(LAYER_Y.edge);
		for (const l of LAYER_ORDER) expect(layerY(l)).toBe(LAYER_Y[l]);
	});

	it('nodeRadius derives from the shared size verdict (root biggest, clamped)', () => {
		expect(nodeRadius({ isRoot: true, degree: 0 })).toBeCloseTo(5.5);
		expect(nodeRadius({ isRoot: false, degree: 0 })).toBeCloseTo(2);
	});

	it('seedPosition is deterministic and lands on the layer band', () => {
		const a = seedPosition(3, 'core');
		const b = seedPosition(3, 'core');
		expect(a).toEqual(b);
		expect(a.y).toBe(LAYER_Y.core);
		expect(seedPosition(0, 'root').x).not.toBe(seedPosition(1, 'root').x);
	});

	it('buildTopologyScene: collapsed orphans → group sphere; expanded → all nodes', () => {
		const g: TopologyGraph = {
			nodes: [
				node({ id: 1, inferred_type: 'router' }),
				node({ id: 2 }),
				node({ id: 3 }),
				node({ id: 4 })
			],
			edges: [edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' })]
		};
		const collapsed = buildTopologyScene(buildGraph(g), opts());
		expect(collapsed.nodes.find((n) => n.kind === 'orphan-group')).toBeTruthy();
		expect(collapsed.nodes.filter((n) => n.kind === 'device')).toHaveLength(2);

		const expanded = buildTopologyScene(buildGraph(g), opts({ expandOrphans: true }));
		expect(expanded.nodes.filter((n) => n.kind === 'device')).toHaveLength(4);
		expect(expanded.nodes.find((n) => n.kind === 'orphan-group')).toBeUndefined();
	});

	it('buildTopologyScene: hidden layer drops its nodes, incident edges, and group sphere when empty', () => {
		const g: TopologyGraph = {
			nodes: [
				node({ id: 1, inferred_type: 'router' }),
				node({ id: 2, inferred_type: 'switch' }),
				node({ id: 3, inferred_type: 'camera' })
			],
			edges: [
				edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
				edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' })
			]
		};
		const scene = buildTopologyScene(buildGraph(g), opts({ layerVisible: { ...allLayers, edge: false } }));
		expect(scene.nodes.find((n) => n.id === '3')).toBeUndefined();
		expect(scene.edges).toHaveLength(1); // camera's edge dropped with it
	});

	it('buildTopologyScene: hidden type bucket drops its nodes + incident edges (chip filter)', () => {
		const g: TopologyGraph = {
			nodes: [
				node({ id: 1, inferred_type: 'router' }),
				node({ id: 2, inferred_type: 'switch' }),
				node({ id: 3, inferred_type: 'pc' })
			],
			edges: [
				edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
				edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' })
			]
		};
		const scene = buildTopologyScene(
			buildGraph(g),
			opts({ bucketVisible: { network: true, camera: true, computer: false, mobile: true, iot: true, other: true } })
		);
		// The pc (computer bucket) is filtered out; its edge drops with it.
		expect(scene.nodes.find((n) => n.id === '3')).toBeUndefined();
		expect(scene.edges).toHaveLength(1);
		// Both routers/switches survive (network bucket still on).
		expect(scene.nodes.filter((n) => n.kind === 'device')).toHaveLength(2);
	});

	it('buildTopologyScene: unidentified edges target stub nodes (#636 parity)', () => {
		const g: TopologyGraph = {
			nodes: [node({ id: 1, inferred_type: 'router' })],
			edges: [edge({ from_device_id: 1, to_mac: 'ff:00:00:00:00:99', protocol: 'LLDP' })]
		};
		const scene = buildTopologyScene(buildGraph(g), opts());
		expect(scene.nodes.find((n) => n.id === 'unknown:ff:00:00:00:00:99')).toBeTruthy();
		expect(scene.edges[0].targetId).toBe('unknown:ff:00:00:00:00:99');
		expect(scene.edges[0].dashed).toBe(true); // unidentified reads dashed
	});

	it('buildTopologyScene: stale edges dim via the shared ladder, cross-links replace it', () => {
		const staleSeen = new Date(Date.now() - 11 * 60 * 1000).toISOString();
		const g: TopologyGraph = {
			nodes: [node({ id: 1, inferred_type: 'router' }), node({ id: 2, inferred_type: 'switch' }), node({ id: 3 })],
			edges: [
				edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP', last_seen: staleSeen }),
				edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' }),
				edge({ from_device_id: 1, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP', last_seen: staleSeen })
			]
		};
		const built = buildGraph(g);
		const scene = buildTopologyScene(built, opts());
		const stale = scene.edges.find((e) => e.sourceId === '1' && e.targetId === '2')!;
		expect(stale.opacity).toBeCloseTo(0.8 * 0.4);
		expect(stale.dashed).toBe(true);
		// The cycle-closing edge (whichever BFS marked) reads as half-tone, not ladder.
		const cross = scene.edges.find((e) => e.link.isCrossLink)!;
		expect(cross).toBeTruthy();
		expect(cross.opacity).toBeCloseTo(0.5);
	});

	it('buildTopologyScene: search dims non-matches and their edges (shared verdicts)', () => {
		const g: TopologyGraph = {
			nodes: [
				node({ id: 1, inferred_type: 'router', name: 'gateway' }),
				node({ id: 2, inferred_type: 'switch', name: 'sw' }),
				node({ id: 3, name: 'cam' })
			],
			edges: [
				edge({ from_device_id: 1, to_device_id: 2, to_mac: '00:00:00:00:00:02', protocol: 'LLDP' }),
				edge({ from_device_id: 2, to_device_id: 3, to_mac: '00:00:00:00:00:03', protocol: 'LLDP' })
			]
		};
		const scene = buildTopologyScene(buildGraph(g), opts({ search: 'cam' }));
		const cam = scene.nodes.find((n) => n.id === '3')!;
		const gw = scene.nodes.find((n) => n.id === '1')!;
		expect(cam.dimmed).toBe(false); // match + its neighbor stay lit
		expect(gw.dimmed).toBe(true);
		const edgeToCam = scene.edges.find((e) => e.targetId === '3')!;
		expect(edgeToCam.opacity).toBeCloseTo(0.8); // not dimmed (one endpoint lit)
	});
});
