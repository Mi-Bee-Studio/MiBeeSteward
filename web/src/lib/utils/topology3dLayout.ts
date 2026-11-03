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

import type {
	DeviceTypeBucket,
	GraphBuildResult,
	GraphNode,
	GraphLink,
	TokenColor,
	TopoLayer
} from '$lib/utils/topologyGraph';
import {
	LAYER_COLORS,
	typeFillColor,
	edgeOpacity,
	isStaleEdge,
	nodeFilterVisible,
	nodeLabelVisible,
	nodeRing,
	nodeSize,
	protocolStyle,
	searchHighlightSet,
	splitOrphans,
	unknownNeighborStubs
} from '$lib/utils/topologyGraph';

/**
 * Pure 3D scene spec for the topology renderer (#635 PR2).
 *
 * Everything renderer-agnostic lives here and is unit-tested: layer banding,
 * filtering, the shared style verdicts (sizes/rings/colors/opacity ladder,
 * reused verbatim from topologyGraph so 2D and 3D can never drift), search
 * dimming, orphan grouping and unidentified-neighbor stubs. The component
 * only turns specs into three.js objects and runs the force simulation.
 */

/** Y-axis band per layer: root on top, endpoints at the bottom — the layer
 *  separation the 2D comments always promised and 3D finally delivers. */
export const LAYER_Y: Record<TopoLayer, number> = {
	root: 90,
	core: 30,
	access: -30,
	edge: -90
};

export function layerY(layer: TopoLayer): number {
	return LAYER_Y[layer];
}

/** Scene-unit radius from the shared size verdict (2D symbolSize / 8). */
export function nodeRadius(gn: Pick<GraphNode, 'isRoot' | 'degree'>): number {
	return nodeSize(gn) / 8;
}

/** Deterministic seed positions (phyllotaxis on XZ, layer band on Y): the
 *  same graph always lays out the same way — no re-render jump, testable. */
export function seedPosition(i: number, layer: TopoLayer): { x: number; y: number; z: number } {
	const r = 18 * Math.sqrt(i + 0.5);
	const a = i * 2.39996323; // golden angle
	return { x: r * Math.cos(a), y: layerY(layer), z: r * Math.sin(a) };
}

export type SceneNodeKind = 'device' | 'stub' | 'orphan-group';

export interface SceneNodeSpec {
	id: string;
	kind: SceneNodeKind;
	/** The graph node (device kind only) — the component formats labels from it. */
	graphNode?: GraphNode;
	radius: number;
	fill: TokenColor;
	ring: TokenColor | null;
	labelVisible: boolean;
	dimmed: boolean;
	/** Force-simulation position target. */
	layer: TopoLayer;
}

export interface SceneEdgeSpec {
	sourceId: string;
	targetId: string;
	link: GraphLink;
	color: TokenColor;
	dashed: boolean;
	opacity: number;
}

export interface TopologyScene {
	nodes: SceneNodeSpec[];
	edges: SceneEdgeSpec[];
}

export interface SceneOptions {
	search: string;
	layerVisible: Record<TopoLayer, boolean>;
	hiddenProtocols: Record<string, boolean>;
	expandOrphans: boolean;
	labelDensity: 'all' | 'core' | 'none';
	/** Fill colors: by hierarchy layer (default) or by device-type bucket. */
	colorMode: 'layer' | 'type';
}

/**
 * buildTopologyScene: the 3D twin of the 2D buildOption — same filtering,
 * same shared verdicts, but expressed as renderer-neutral specs. Feed the
 * GraphBuildResult; get what to draw.
 */
export function buildTopologyScene(built: GraphBuildResult, opts: SceneOptions): TopologyScene {
	const { search, layerVisible, bucketVisible, hiddenProtocols, expandOrphans, labelDensity, colorMode } = opts;

	// Orphan grouping mirrors the 2D contract (#584).
	const { connected, orphans } = splitOrphans(built.nodes);
	const layoutNodes = expandOrphans ? built.nodes : connected;
	const orphanVisible = orphans.filter((o) => nodeFilterVisible(o, layerVisible, bucketVisible)).length;

	const visibleNodeIds = new Set(layoutNodes.filter((gn) => nodeFilterVisible(gn, layerVisible, bucketVisible)).map((gn) => gn.id));
	const highlighted = searchHighlightSet(built.nodes, built.links, search);

	const statusById = new Map(built.nodes.map((gn) => [gn.id, gn.value.status || '']));

	const nodes: SceneNodeSpec[] = [];
	for (const gn of layoutNodes) {
		if (!visibleNodeIds.has(gn.id)) continue;
		nodes.push({
			id: String(gn.id),
			kind: 'device',
			graphNode: gn,
			radius: nodeRadius(gn),
			fill: colorMode === 'type' ? typeFillColor(gn.value) : LAYER_COLORS[gn.layer],
			ring: nodeRing(gn),
			labelVisible: nodeLabelVisible(gn, labelDensity),
			dimmed: !!search && !highlighted.has(gn.id),
			layer: gn.layer
		});
	}

	// Collapsed orphan group (#584): one translucent sphere in the bottom band.
	if (!expandOrphans && orphanVisible > 0) {
		nodes.push({
			id: 'orphans-group',
			kind: 'orphan-group',
			radius: 7,
			fill: LAYER_COLORS.edge,
			ring: null,
			labelVisible: true,
			dimmed: false,
			layer: 'edge'
		});
	}

	// Visible links first (drives stub creation, same as 2D #636).
	const visibleLinks = built.links.filter(
		(l) =>
			visibleNodeIds.has(l.source) &&
			(l.isUnidentified || visibleNodeIds.has(l.target)) &&
			!hiddenProtocols[l.protocol]
	);

	// Unidentified-neighbor stubs (#636): small spheres per unseen MAC.
	for (const s of unknownNeighborStubs(visibleLinks)) {
		nodes.push({
			id: s.id,
			kind: 'stub',
			radius: 2.2,
			fill: LAYER_COLORS.edge,
			ring: null,
			labelVisible: labelDensity === 'all',
			dimmed: false,
			layer: 'edge'
		});
	}

	const edges: SceneEdgeSpec[] = visibleLinks.map((l) => {
		const style = protocolStyle(l.protocol);
		const dimmed = !!search && !highlighted.has(l.source) && !highlighted.has(l.target);
		const stale = isStaleEdge(l);
		const offlineEnd =
			statusById.get(l.source) === 'offline' ||
			(!l.isUnidentified && statusById.get(l.target) === 'offline');
		return {
			sourceId: String(l.source),
			targetId: l.isUnidentified ? `unknown:${l.toMac || '(unknown)'}` : String(l.target),
			link: l,
			color: style.color,
			dashed: l.isUnidentified || stale,
			opacity: edgeOpacity(l, { stale, offlineEnd, dimmed })
		};
	});

	return { nodes, edges };
}
