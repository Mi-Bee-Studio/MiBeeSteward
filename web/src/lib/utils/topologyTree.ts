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

export interface TreeNode {
	name: string;
	value: TopoNode;
	children: TreeNode[];
	depth: number;
	childCount: number;
	isRoot: boolean;
	parentPort?: string | null;
	edgeProtocol?: string;
}

export interface TreeBuildResult {
	roots: TreeNode[];
	crossLinks: { from: number; to: number; protocol: string }[];
}

export function detectRoot(graph: TopologyGraph): TopoNode | null {
	const { nodes, edges } = graph;

	if (nodes.length === 0) {
		return null;
	}

	const macToNodeId = new Map<string, number>();
	for (const node of nodes) {
		macToNodeId.set(node.mac_address.toLowerCase(), node.id);
	}

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
		const routerCandidate = candidates.find(
			(n) => {
				const infType = n.inferred_type?.toLowerCase() ?? '';
				const type = n.type?.toLowerCase() ?? '';
				return infType.includes('router') || type.includes('router');
			}
		);
		if (routerCandidate) {
			return routerCandidate;
		}
		return candidates[0];
	}

	const routerNode = nodes.find(
		(n) => {
			const infType = n.inferred_type?.toLowerCase() ?? '';
			const type = n.type?.toLowerCase() ?? '';
			return infType === 'router' || type === 'router';
		}
	);
	if (routerNode) {
		return routerNode;
	}

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

export function buildTree(graph: TopologyGraph): TreeBuildResult {
	const { nodes, edges } = graph;

	if (nodes.length === 0) {
		return { roots: [], crossLinks: [] };
	}

	const macToNodeId = new Map<string, number>();
	for (const node of nodes) {
		macToNodeId.set(node.mac_address.toLowerCase(), node.id);
	}

	const priorityMap: Record<string, number> = {
		LLDP: 3,
		CDP: 3,
		'Bridge-MIB': 2,
		ARP: 1
	};

	interface AdjacencyEntry {
		nodeId: number;
		edge: TopoEdge;
		priority: number;
	}

	const adjacency = new Map<number, AdjacencyEntry[]>();
	for (const node of nodes) {
		adjacency.set(node.id, []);
	}

	for (const edge of edges) {
		const from = edge.from_device_id;
		let to: number | undefined;

		if (edge.to_device_id !== null) {
			to = edge.to_device_id;
		} else {
			const toMac = edge.to_mac.toLowerCase();
			to = macToNodeId.get(toMac);
		}

		if (to === undefined) continue;
		if (from === to) continue;

		const priority = priorityMap[edge.protocol] ?? 0;
		adjacency.get(from)?.push({ nodeId: to, edge, priority });
	}

	const treeNodes = new Map<number, TreeNode>();
	for (const node of nodes) {
		treeNodes.set(node.id, {
			name: node.name || node.ip_address || `#${node.id}`,
			value: node,
			children: [],
			depth: 0,
			childCount: 0,
			isRoot: false,
			parentPort: null,
			edgeProtocol: undefined
		});
	}

	const visited = new Set<number>();
	const crossLinks: { from: number; to: number; protocol: string }[] = [];
	const roots: TreeNode[] = [];

	function bfsTree(startNodeId: number, isRoot: boolean): void {
		const queue: Array<{
			nodeId: number;
			depth: number;
			parentEdge: TopoEdge | null;
		}> = [];
		queue.push({ nodeId: startNodeId, depth: 0, parentEdge: null });
		visited.add(startNodeId);

		const startNode = treeNodes.get(startNodeId);
		if (startNode) {
			startNode.isRoot = isRoot;
		}

		while (queue.length > 0) {
			const { nodeId, depth, parentEdge } = queue.shift()!;
			const treeNode = treeNodes.get(nodeId);
			if (!treeNode) continue;

			treeNode.depth = depth;
			if (parentEdge) {
				treeNode.parentPort = parentEdge.local_port;
				treeNode.edgeProtocol = parentEdge.protocol;
			}

			const neighbors = (adjacency.get(nodeId) || []).sort(
				(a, b) => b.priority - a.priority
			);

			for (const { nodeId: neighborId, edge } of neighbors) {
				if (visited.has(neighborId)) {
					crossLinks.push({ from: nodeId, to: neighborId, protocol: edge.protocol });
				} else {
					visited.add(neighborId);
					const neighborNode = treeNodes.get(neighborId);
					if (neighborNode) {
						neighborNode.parentPort = edge.local_port;
						neighborNode.edgeProtocol = edge.protocol;
						treeNode.children.push(neighborNode);
						queue.push({
							nodeId: neighborId,
							depth: depth + 1,
							parentEdge: edge
						});
					}
				}
			}
		}
	}

	const root = detectRoot(graph);

	if (root) {
		bfsTree(root.id, true);
	}

	for (const node of nodes) {
		if (!visited.has(node.id)) {
			bfsTree(node.id, true);
		}
	}

	for (const [, treeNode] of treeNodes) {
		if (treeNode.isRoot) {
			roots.push(treeNode);
		}
	}

	function computeChildCount(node: TreeNode): number {
		let count = 0;
		for (const child of node.children) {
			count += 1 + computeChildCount(child);
		}
		node.childCount = count;
		return count;
	}

	for (const rootNode of roots) {
		computeChildCount(rootNode);
	}

	return { roots, crossLinks };
}