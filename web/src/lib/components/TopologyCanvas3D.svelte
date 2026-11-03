<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  TopologyCanvas3D: the three.js renderer for the topology view (#635 PR2).
  Implements the same contract as TopologyCanvas2D (props in: graph / search /
  layerVisible / hiddenProtocols / expandOrphans; callbacks out: onselectnode /
  onselectedge / onopenorphans / onopendevice) so the shell swaps canvases
  freely. This whole module — three.js + d3-force-3d — is loaded lazily on the
  first 2D→3D toggle; keep it out of any eagerly imported module.

  Visual verdicts (sizes, rings, colors, opacity ladder, dimming, layer
  bands, stubs) come from topologyGraph.ts / topology3dLayout.ts — do not add
  renderer-local styling decisions.

  Layout is deterministic: phyllotaxis seeds + manually-ticked force
  simulation, so the same graph always renders the same way (no jump on
  theme/freshness rebuilds — only colors/opacities re-resolve).

  Interactions: drag = orbit, wheel = zoom (OrbitControls, touch-action
  none); click node → panel, click edge (line threshold) → edge panel,
  double-click node → device page, click the translucent group sphere →
  orphan member panel.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { m } from '$lib/i18n-paraglide';
	import { resolveToken } from '$lib/utils/cssVar';
	import type { TopologyGraph } from '$lib/types';
	import {
		buildGraph,
		recommendedForceParams,
		splitOrphans,
		SEARCH_DIM_NODE_OPACITY,
		type GraphNode,
		type GraphLink,
		type TopoLayer
	} from '$lib/utils/topologyGraph';
	import { buildTopologyScene, layerY, seedPosition, type SceneNodeSpec } from '$lib/utils/topology3dLayout';
	import * as THREE from 'three';
	import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
	import { CSS2DRenderer, CSS2DObject } from 'three/examples/jsm/renderers/CSS2DRenderer.js';
	import { forceLink, forceManyBody, forceSimulation, forceY } from 'd3-force-3d';

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

	let container: HTMLDivElement | undefined = $state();
	let webglFailed = $state(false);

	let built = $derived(graph ? buildGraph(graph) : null);
	let force = $derived(built ? recommendedForceParams(built.nodes.length) : null);
	// Visible orphan count for the collapsed group sphere's label (#584).
	let orphanCount = $derived(
		built ? splitOrphans(built.nodes).orphans.filter((o) => layerVisible[o.layer]).length : 0
	);
	let sceneSpec = $derived(
		built && force
			? buildTopologyScene(built, {
					search,
					layerVisible,
					hiddenProtocols,
					expandOrphans,
					labelDensity: force.labelDensity
				})
			: null
	);

	// Freshness + theme ticks (#637/#639 discipline, same as the 2D canvas):
	// time-driven verdicts re-resolve on tick, token colors on theme flips.
	let freshnessTick = $state(0);
	let themeVersion = $state(0);

	// three.js one-time handles.
	let renderer: THREE.WebGLRenderer;
	let labelRenderer: CSS2DRenderer;
	let camera: THREE.PerspectiveCamera;
	let controls: OrbitControls;
	let root = new THREE.Group();
	let raf = 0;
	let resizeObs: ResizeObserver | null = null;
	let themeObs: MutationObserver | null = null;
	// Per-rebuild disposables + node lookup for raycasting.
	let disposables: Array<THREE.BufferGeometry | THREE.Material> = [];
	let nodeMeshes: THREE.Mesh[] = [];
	let edgeLines: THREE.Line[] = [];
	let labels: CSS2DObject[] = [];
	const raycaster = new THREE.Raycaster();

	function disposeScene() {
		root.clear();
		for (const d of disposables) d.dispose();
		disposables = [];
		nodeMeshes = [];
		edgeLines = [];
		// CSS2DRenderer leaves removed labels' DOM elements behind — take them
		// out explicitly or they pile up in the overlay on every rebuild.
		for (const l of labels) l.element.remove();
		labels = [];
	}

	function rebuild(spec: NonNullable<typeof sceneSpec>) {
		disposeScene();

		// Deterministic layout: phyllotaxis seeds on the layer band, then a
		// fixed number of manual force ticks (no timer, no randomness).
		const simNodes = spec.nodes.map((n, i) => {
			const p = seedPosition(i, n.layer);
			return { id: n.id, layer: n.layer, x: p.x, y: p.y, z: p.z };
		});
		const byId = new Map(simNodes.map((n) => [n.id, n]));
		const simLinks = spec.edges
			.map((e) => ({ source: e.sourceId, target: e.targetId }))
			.filter((l) => byId.has(l.source) && byId.has(l.target));
		const sim = forceSimulation(simNodes as never)
			.force('charge', forceManyBody().strength(-140))
			// .id() is REQUIRED: forceLink matches link endpoints by index
			// otherwise, and string ids throw "node not found".
			.force('link', forceLink(simLinks as never).id((d: { id: string }) => d.id).distance(48).strength(0.7))
			.force('y', forceY((d: { layer: TopoLayer }) => layerY(d.layer)).strength(0.45))
			.stop();
		for (let i = 0; i < 260; i++) sim.tick();
		const pos = new Map(simNodes.map((n) => [n.id, new THREE.Vector3(n.x, n.y, n.z)]));

		// One shared unit sphere; per-node scale (cheap, few geometries).
		const sphere = new THREE.SphereGeometry(1, 20, 14);
		disposables.push(sphere);

		for (const n of spec.nodes) {
			const p = pos.get(n.id) ?? new THREE.Vector3(0, layerY(n.layer), 0);
			const fill = new THREE.Color(resolveToken(n.fill));
			const mat = new THREE.MeshBasicMaterial({
				color: fill,
				transparent: true,
				opacity: n.kind === 'orphan-group' ? 0.25 : n.dimmed ? SEARCH_DIM_NODE_OPACITY : 0.95
			});
			disposables.push(mat);
			const mesh = new THREE.Mesh(sphere, mat);
			mesh.scale.setScalar(n.radius);
			mesh.position.copy(p);
			mesh.userData = { kind: 'node', spec: n };
			root.add(mesh);
			nodeMeshes.push(mesh);

			// Ring badge (#556): a wireframe shell slightly larger than the node.
			if (n.ring) {
				const ringMat = new THREE.MeshBasicMaterial({
					color: new THREE.Color(resolveToken(n.ring.color)),
					wireframe: true,
					transparent: true,
					opacity: 0.65
				});
				disposables.push(ringMat);
				const ring = new THREE.Mesh(sphere, ringMat);
				ring.scale.setScalar(n.radius + 0.45);
				ring.position.copy(p);
				ring.userData = { kind: 'deco' };
				root.add(ring);
			}
			// Stubs read as hollow: wireframe the node itself.
			if (n.kind === 'stub') (mesh.material as THREE.MeshBasicMaterial).wireframe = true;

			// Label (CSS2D = real DOM text).
			if (n.labelVisible && !n.dimmed) {
				const el = document.createElement('div');
				el.className = 'text-[10px] text-muted font-mono pointer-events-none whitespace-nowrap';
				if (n.kind === 'device' && n.graphNode) {
					const g = n.graphNode;
					el.textContent = (g.isBridge ? '⇄ ' : '') + (g.value.name || g.value.ip_address || `#${g.value.id}`);
				} else if (n.kind === 'stub') {
					el.textContent = `${m['topology.Unidentified Neighbor']()} ${(n.id.split(':')[1] ?? '').slice(0, 17)}`;
				} else {
					el.textContent = m['topology.Orphan Group Node']({ n: orphanCount });
				}
				const label = new CSS2DObject(el);
				label.position.copy(p);
				label.position.y += n.radius + 1.5;
				root.add(label);
				labels.push(label);
			}
		}

		for (const e of spec.edges) {
			const a = pos.get(e.sourceId);
			const b = pos.get(e.targetId);
			if (!a || !b) continue;
			const geo = new THREE.BufferGeometry().setFromPoints([a, b]);
			disposables.push(geo);
			const mat = e.dashed
				? new THREE.LineDashedMaterial({
						color: new THREE.Color(resolveToken(e.color)),
						transparent: true,
						opacity: e.opacity,
						dashSize: 4,
						gapSize: 3
					})
				: new THREE.LineBasicMaterial({
						color: new THREE.Color(resolveToken(e.color)),
						transparent: true,
						opacity: e.opacity
					});
			disposables.push(mat);
			const line = new THREE.Line(geo, mat);
			if (e.dashed) line.computeLineDistances();
			line.userData = { kind: 'edge', link: e.link };
			root.add(line);
			edgeLines.push(line);
		}
	}

	function pick(ev: PointerEvent): { node?: SceneNodeSpec; edge?: GraphLink } {
		const rect = container!.getBoundingClientRect();
		const ndc = new THREE.Vector2(
			((ev.clientX - rect.left) / rect.width) * 2 - 1,
			-((ev.clientY - rect.top) / rect.height) * 2 + 1
		);
		raycaster.setFromCamera(ndc, camera);
		raycaster.params.Line.threshold = 2.5;
		const hits = raycaster.intersectObjects([...nodeMeshes, ...edgeLines], false);
		for (const h of hits) {
			if (h.object.userData.kind === 'node') return { node: h.object.userData.spec };
			if (h.object.userData.kind === 'edge') return { edge: h.object.userData.link };
		}
		return {};
	}
	onMount(() => {
		if (!container) return;
		try {
			renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
		} catch {
			webglFailed = true;
			return;
		}
		renderer.setPixelRatio(window.devicePixelRatio);
		renderer.domElement.style.width = '100%';
		renderer.domElement.style.height = '100%';
		container.appendChild(renderer.domElement);

		labelRenderer = new CSS2DRenderer();
		labelRenderer.domElement.style.position = 'absolute';
		labelRenderer.domElement.style.inset = '0';
		labelRenderer.domElement.style.pointerEvents = 'none';
		container.appendChild(labelRenderer.domElement);

		camera = new THREE.PerspectiveCamera(55, 1, 0.1, 2000);
		camera.position.set(0, 150, 260);

		controls = new OrbitControls(camera, renderer.domElement);
		controls.enableDamping = true;
		controls.target.set(0, 0, 0);

		const resize = () => {
			const w = container.clientWidth || 1;
			const h = container.clientHeight || 1;
			renderer.setSize(w, h, false);
			labelRenderer.setSize(w, h);
			camera.aspect = w / h;
			camera.updateProjectionMatrix();
		};
		resizeObs = new ResizeObserver(resize);
		resizeObs.observe(container);
		resize();

		themeObs = new MutationObserver(() => (themeVersion += 1));
		themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

		const t = setInterval(() => (freshnessTick += 1), 30_000);

		let downX = 0;
		let downY = 0;
		const onDown = (ev: PointerEvent) => { downX = ev.clientX; downY = ev.clientY; };
		const onUp = (ev: PointerEvent) => {
			if (Math.hypot(ev.clientX - downX, ev.clientY - downY) > 5) return; // drag = orbit
			const hit = pick(ev);
			if (hit.node?.kind === 'orphan-group') { onopenorphans?.(); return; }
			if (hit.node?.graphNode) { onselectnode?.(hit.node.graphNode); return; }
			if (hit.edge) { onselectedge?.(hit.edge); return; }
		};
		const onDbl = (ev: MouseEvent) => {
			const hit = pick(ev as PointerEvent);
			if (hit.node?.graphNode?.value.id) onopendevice?.(hit.node.graphNode.value.id);
		};
		const onMove = (ev: PointerEvent) => {
			renderer.domElement.style.cursor = Object.values(pick(ev))[0] ? 'pointer' : 'grab';
		};
		renderer.domElement.addEventListener('pointerdown', onDown);
		renderer.domElement.addEventListener('pointerup', onUp);
		renderer.domElement.addEventListener('dblclick', onDbl);
		renderer.domElement.addEventListener('pointermove', onMove);

		const loop = () => {
			controls.update();
			renderer.render(root, camera);
			labelRenderer.render(root, camera);
			raf = requestAnimationFrame(loop);
		};
		raf = requestAnimationFrame(loop);

		return () => {
			cancelAnimationFrame(raf);
			clearInterval(t);
			resizeObs?.disconnect();
			themeObs?.disconnect();
			renderer.domElement.removeEventListener('pointerdown', onDown);
			renderer.domElement.removeEventListener('pointerup', onUp);
			renderer.domElement.removeEventListener('dblclick', onDbl);
			renderer.domElement.removeEventListener('pointermove', onMove);
			controls.dispose();
			disposeScene();
			renderer.dispose();
			container?.removeChild(renderer.domElement);
			container?.removeChild(labelRenderer.domElement);
		};
	});

	// Rebuild meshes whenever the spec changes — or the ticks fire (#637/#639).
	$effect(() => {
		void freshnessTick;
		void themeVersion;
		if (sceneSpec && renderer && !webglFailed) rebuild(sceneSpec);
	});
</script>

{#if webglFailed}
	<div class="flex items-center justify-center text-sm text-muted" style="height: {height};">
		{m['common.Chart Unavailable']()}
	</div>
{:else}
	<div bind:this={container} class="relative w-full" style="height: {height}; touch-action: none;"></div>
{/if}
