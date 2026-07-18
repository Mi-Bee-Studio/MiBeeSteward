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
import { detectRoot, buildTree } from '$lib/utils/topologyTree';

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
}

interface TopologyGraph {
	nodes: TopoNode[];
	edges: TopoEdge[];
}

describe('topologyTree', () => {
	describe('detectRoot', () => {
		it('1. Empty graph → returns null', () => {
			const graph: TopologyGraph = { nodes: [], edges: [] };
			const root = detectRoot(graph);
			expect(root).toBeNull();
		});

		it('2. ARP star → returns gateway with highest ARP in-degree', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'PC1', ip_address: '192.168.1.10', mac_address: '00:11:22:33:44:55', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Dell' },
					{ id: 3, name: 'PC2', ip_address: '192.168.1.11', mac_address: '00:11:22:33:44:66', type: 'device', status: 'online', inferred_type: 'pc', brand: 'HP' },
					{ id: 4, name: 'PC3', ip_address: '192.168.1.12', mac_address: '00:11:22:33:44:77', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Lenovo' }
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
			expect(root!.name).toBe('Gateway');
		});

		it('3. LLDP hierarchy → returns gateway', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'Switch', ip_address: '192.168.1.2', mac_address: '00:11:22:33:44:55', type: 'switch', status: 'online', inferred_type: 'switch', brand: 'Cisco' },
					{ id: 3, name: 'Camera', ip_address: '192.168.1.3', mac_address: '00:11:22:33:44:66', type: 'camera', status: 'online', inferred_type: 'camera', brand: 'Hikvision' },
					{ id: 4, name: 'PC', ip_address: '192.168.1.4', mac_address: '00:11:22:33:44:77', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Dell' }
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:11:22:33:44:55', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:11:22:33:44:66', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 4, to_mac: '00:11:22:33:44:77', protocol: 'LLDP' }
				]
			};
			const root = detectRoot(graph);
			expect(root).not.toBeNull();
			expect(root!.id).toBe(1);
			expect(root!.name).toBe('Gateway');
		});
	});

	describe('buildTree', () => {
		it('1. Empty graph → returns empty result', () => {
			const graph: TopologyGraph = { nodes: [], edges: [] };
			const result = buildTree(graph);
			expect(result.roots).toEqual([]);
			expect(result.crossLinks).toEqual([]);
		});

		it('2. ARP star → 4 roots (gateway + 3 devices, no parent-child from ARP)', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'PC1', ip_address: '192.168.1.10', mac_address: '00:11:22:33:44:55', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Dell' },
					{ id: 3, name: 'PC2', ip_address: '192.168.1.11', mac_address: '00:11:22:33:44:66', type: 'device', status: 'online', inferred_type: 'pc', brand: 'HP' },
					{ id: 4, name: 'PC3', ip_address: '192.168.1.12', mac_address: '00:11:22:33:44:77', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Lenovo' }
				],
				edges: [
					{ from_device_id: 2, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' },
					{ from_device_id: 3, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' },
					{ from_device_id: 4, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' }
				]
			};
			const result = buildTree(graph);
			// ARP edges go device→gateway, so gateway has no outgoing edges
			// All 4 nodes become roots (gateway + 3 unvisited devices)
			expect(result.roots.length).toBe(4);
			const root = result.roots.find((r) => r.value.id === 1);
			expect(root).toBeDefined();
			expect(root!.value.id).toBe(1);
			expect(root!.depth).toBe(0);
			expect(root!.childCount).toBe(0); // No children (no outgoing edges)
			expect(root!.children.length).toBe(0);
		});

		it('3. LLDP hierarchy → gateway→switch→camera+pc', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'Switch', ip_address: '192.168.1.2', mac_address: '00:11:22:33:44:55', type: 'switch', status: 'online', inferred_type: 'switch', brand: 'Cisco' },
					{ id: 3, name: 'Camera', ip_address: '192.168.1.3', mac_address: '00:11:22:33:44:66', type: 'camera', status: 'online', inferred_type: 'camera', brand: 'Hikvision' },
					{ id: 4, name: 'PC', ip_address: '192.168.1.4', mac_address: '00:11:22:33:44:77', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Dell' }
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:11:22:33:44:55', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:11:22:33:44:66', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 4, to_mac: '00:11:22:33:44:77', protocol: 'LLDP' }
				]
			};
			const result = buildTree(graph);
			expect(result.roots.length).toBe(1);
			const root = result.roots[0];
			expect(root.value.id).toBe(1);
			expect(root.name).toBe('Gateway');
			expect(root.depth).toBe(0);
			expect(root.childCount).toBe(3);

			expect(root.children.length).toBe(1);
			const switchNode = root.children[0];
			expect(switchNode.value.id).toBe(2);
			expect(switchNode.depth).toBe(1);
			expect(switchNode.childCount).toBe(2);
			expect(switchNode.children.length).toBe(2);

			const camera = switchNode.children[0];
			expect(camera.value.id).toBe(3);
			expect(camera.depth).toBe(2);
			expect(camera.childCount).toBe(0);

			const pc = switchNode.children[1];
			expect(pc.value.id).toBe(4);
			expect(pc.depth).toBe(2);
			expect(pc.childCount).toBe(0);
		});

		it('4. Cycle → no infinite loop, 1 crossLink', () => {
			const graph: TopologyGraph = {
				nodes: [
					{ id: 1, name: 'A', ip_address: '192.168.1.1', mac_address: 'aa:bb:cc:dd:ee:ff', type: 'device', status: 'online', inferred_type: 'device', brand: 'Unknown' },
					{ id: 2, name: 'B', ip_address: '192.168.1.2', mac_address: '00:11:22:33:44:55', type: 'device', status: 'online', inferred_type: 'device', brand: 'Unknown' },
					{ id: 3, name: 'C', ip_address: '192.168.1.3', mac_address: '00:11:22:33:44:66', type: 'device', status: 'online', inferred_type: 'device', brand: 'Unknown' }
				],
				edges: [
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:11:22:33:44:55', protocol: 'LLDP' },
					{ from_device_id: 2, to_device_id: 3, to_mac: '00:11:22:33:44:66', protocol: 'LLDP' },
					{ from_device_id: 3, to_device_id: 1, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'LLDP' }
				]
			};
			const result = buildTree(graph);
			// Should complete without infinite loop
			expect(result.roots.length).toBeGreaterThanOrEqual(1);
			// Exactly one edge becomes a crossLink (the cycle-closing edge)
			expect(result.crossLinks.length).toBe(1);
			// Verify crossLink format
			expect(result.crossLinks[0]).toHaveProperty('from');
			expect(result.crossLinks[0]).toHaveProperty('to');
			expect(result.crossLinks[0]).toHaveProperty('protocol');
		});

		it('5. Mixed priority → LLDP edge wins over ARP to same child', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'Switch', ip_address: '192.168.1.2', mac_address: '00:11:22:33:44:55', type: 'switch', status: 'online', inferred_type: 'switch', brand: 'Cisco' }
				],
				edges: [
					{ from_device_id: 2, to_device_id: 1, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP', local_port: null },
					{ from_device_id: 1, to_device_id: 2, to_mac: '00:11:22:33:44:55', protocol: 'LLDP', local_port: 'Gi1/0/24' }
				]
			};
			const result = buildTree(graph);
			// Gateway has LLDP edge to switch, ARP is incoming (ignored for tree traversal)
			expect(result.roots.length).toBe(1);
			const root = result.roots[0];
			expect(root.value.id).toBe(1);
			expect(root.children.length).toBe(1);

			const child = root.children[0];
			expect(child.value.id).toBe(2);
			// LLDP edge was used (higher priority than ARP)
			expect(child.edgeProtocol).toBe('LLDP');
			expect(child.parentPort).toBe('Gi1/0/24');
		});

		it('6. Port metadata → parentPort set from local_port', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'Switch', ip_address: '192.168.1.2', mac_address: '00:11:22:33:44:55', type: 'switch', status: 'online', inferred_type: 'switch', brand: 'Cisco' }
				],
				edges: [{ from_device_id: 1, to_device_id: 2, to_mac: '00:11:22:33:44:55', protocol: 'LLDP', local_port: 'Gi1/0/24' }]
			};
			const result = buildTree(graph);
			expect(result.roots.length).toBe(1);
			const root = result.roots[0];
			expect(root.children.length).toBe(1);

			const child = root.children[0];
			expect(child.parentPort).toBe('Gi1/0/24');
			expect(child.edgeProtocol).toBe('LLDP');
		});

		it('7. Orphan cluster → 3 separate roots', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					},
					{ id: 2, name: 'Device1', ip_address: '192.168.1.10', mac_address: '00:11:22:33:44:55', type: 'device', status: 'online', inferred_type: 'pc', brand: 'Dell' },
					{ id: 3, name: 'Switch2', ip_address: '192.168.1.2', mac_address: '00:11:22:33:44:66', type: 'switch', status: 'online', inferred_type: 'switch', brand: 'Cisco' },
					{ id: 4, name: 'Camera2', ip_address: '192.168.1.3', mac_address: '00:11:22:33:44:77', type: 'camera', status: 'online', inferred_type: 'camera', brand: 'Hikvision' }
				],
				edges: [
					{ from_device_id: 2, to_mac: 'aa:bb:cc:dd:ee:ff', protocol: 'ARP' },
					{ from_device_id: 3, to_device_id: 4, to_mac: '00:11:22:33:44:77', protocol: 'LLDP' }
				]
			};
			const result = buildTree(graph);
			// Cluster 1: gateway + device1 (ARP edge device→gateway, so both are roots)
			// Cluster 2: switch2 → camera2 (LLDP edge, switch is parent)
			// Total: gateway(root), device1(root), switch2(root with child) = 3 roots
			expect(result.roots.length).toBe(3);

			// Find the gateway root (Cluster 1)
			const gatewayRoot = result.roots.find((r) => r.value.id === 1);
			expect(gatewayRoot).toBeDefined();
			expect(gatewayRoot!.children.length).toBe(0); // ARP edge goes TO gateway, not from
			expect(gatewayRoot!.childCount).toBe(0);

			// Find the switch2 root (Cluster 2 - has camera2 as child)
			const switchRoot = result.roots.find((r) => r.value.id === 3);
			expect(switchRoot).toBeDefined();
			expect(switchRoot!.children.length).toBe(1);
			expect(switchRoot!.childCount).toBe(1);
			expect(switchRoot!.children[0].value.id).toBe(4); // Camera2
		});

		it('8. Unidentified neighbor → edge with unknown MAC is skipped', () => {
			const graph: TopologyGraph = {
				nodes: [
					{
						id: 1,
						name: 'Gateway',
						ip_address: '192.168.1.1',
						mac_address: 'aa:bb:cc:dd:ee:ff',
						type: 'router',
						status: 'online',
						inferred_type: 'router',
						brand: 'Cisco'
					}
				],
				edges: [{ from_device_id: 1, to_mac: 'ff:ff:ff:ff:ff:ff', protocol: 'LLDP' }]
			};
			// Should not crash, should build successfully
			const result = buildTree(graph);
			expect(result.roots.length).toBe(1);
			const root = result.roots[0];
			expect(root.value.id).toBe(1);
			// No children since the edge points to unknown MAC
			expect(root.children.length).toBe(0);
			expect(root.childCount).toBe(0);
		});
	});
});