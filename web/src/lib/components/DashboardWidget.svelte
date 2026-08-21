<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import Chart from './Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import { m } from '$lib/i18n-paraglide';
	import { GripVertical, Pencil, Trash2 } from '@lucide/svelte';
	import type { DashboardWidgetConfig } from '$lib/types';

	// Extends the shared API shape with runtime-only UI state (the ECharts
	// option + a loading flag). Was a full re-declaration of the 10 API fields
	// — deduped against the canonical type (#71).
	interface WidgetState extends DashboardWidgetConfig {
		chartOption: EChartsOption;
		loading?: boolean;
	}

	let {
		widget,
		onEdit,
		onRemove,
		onMove,
		ondragstart,
		ondragover,
		ondrop
	}: {
		widget: WidgetState;
		onEdit: (id: string) => void;
		onRemove: (id: string) => void;
		onMove: (id: string, direction: 'up' | 'down') => void;
		ondragstart: (e: DragEvent, id: string) => void;
		ondragover: (e: DragEvent) => void;
		ondrop: (e: DragEvent, id: string) => void;
	} = $props();

	let dragOver = $state(false);

	function handleDragStart(e: DragEvent) {
		ondragstart(e, widget.id);
	}

	function handleDragOver(e: DragEvent) {
		e.preventDefault();
		dragOver = true;
		ondragover(e);
	}

	function handleDragLeave() {
		dragOver = false;
	}

	function handleDrop(e: DragEvent) {
		e.preventDefault();
		dragOver = false;
		ondrop(e, widget.id);
	}
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- NOTE: the drag-over class must be interpolated, NOT `class:drag-over` —
     the class directive parses dash-names as an expression (drag - over),
     throwing "drag is not defined" during mount and poisoning Svelte's effect
     scheduler (every later reactive update on the page silently stopped —
     the dashboard-custom-layout freeze bug). -->
<div
	class="widget-card {dragOver ? 'drag-over' : ''}"
	draggable="true"
	ondragstart={handleDragStart}
	ondragover={handleDragOver}
	ondragleave={handleDragLeave}
	ondrop={handleDrop}
>
	<div class="widget-header">
		<button
			type="button"
			class="widget-drag-handle"
			aria-label={m['dashboard.Drag to Reorder']()}
			title={m['dashboard.Drag to Reorder']()}
			onkeydown={(e) => {
				// ArrowUp/ArrowDown move the widget one slot; mirrors the drag swap
				// so keyboard users can reorder without a pointer (#71).
				if (e.key === 'ArrowUp') {
					e.preventDefault();
					onMove(widget.id, 'up');
				} else if (e.key === 'ArrowDown') {
					e.preventDefault();
					onMove(widget.id, 'down');
				}
			}}
		>
			<GripVertical class="w-[14px] h-[14px]" />
		</button>
		<h3 class="widget-title">{widget.name}</h3>
		<div class="widget-actions">
			<button class="widget-action-btn" onclick={() => onEdit(widget.id)} title={m['common.Edit Widget']()} aria-label={m['common.Edit Widget']()}>
				<Pencil class="w-[14px] h-[14px]" />
			</button>
			<button class="widget-action-btn widget-action-danger" onclick={() => onRemove(widget.id)} title={m['common.Remove Widget']()} aria-label={m['common.Remove Widget']()}>
				<Trash2 class="w-[14px] h-[14px]" />
			</button>
		</div>
	</div>
	<div class="widget-chart">
		{#if widget.loading}
			<div class="widget-loading">
				<div class="widget-spinner"></div>
			</div>
		{:else}
			<Chart option={widget.chartOption} height="100%" />
		{/if}
	</div>
</div>

<style>
	.widget-card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		overflow: hidden;
		cursor: grab;
		transition: box-shadow 0.2s ease, border-color 0.2s ease, transform 0.15s ease;
	}

	.widget-card:active {
		cursor: grabbing;
	}

	.widget-card.drag-over {
		border-color: var(--color-primary);
		box-shadow: var(--glow-primary);
		transform: scale(1.01);
	}

	.widget-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.625rem 0.75rem;
		border-bottom: 1px solid var(--color-border);
		background: var(--color-surface);
	}

	.widget-drag-handle {
		display: flex;
		align-items: center;
		justify-content: center;
		/* ≥44px touch target (WCAG 2.5.5) — the grip icon stays 14px, only the
		   clickable area grows so it's reachable on touch / by shaky pointers. */
		min-width: 2.75rem;
		min-height: 2.75rem;
		padding: 0;
		border: none;
		background: transparent;
		color: var(--color-text-muted);
		opacity: 0.4;
		transition: opacity 0.15s ease;
		flex-shrink: 0;
		cursor: grab;
	}

	.widget-card:hover .widget-drag-handle {
		opacity: 0.8;
	}

	.widget-title {
		flex: 1;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		line-height: 1.4;
	}

	.widget-actions {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		flex-shrink: 0;
		opacity: 0;
		transition: opacity 0.15s ease;
	}

	.widget-card:hover .widget-actions {
		opacity: 1;
	}

	.widget-action-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		/* ≥44×44px touch target (WCAG 2.5.5) — was 1.75rem (28px), too small
		   for touch. The icon stays 14px; only the hit area grows. */
		min-width: 2.75rem;
		min-height: 2.75rem;
		border-radius: var(--radius-sm);
		border: none;
		background: transparent;
		color: var(--color-text-muted);
		cursor: pointer;
		transition: background 0.15s ease, color 0.15s ease;
	}

	.widget-action-btn:hover {
		background: var(--color-surface-2);
		color: var(--color-text);
	}

	.widget-action-danger:hover {
		background: color-mix(in srgb, var(--color-error) 15%, transparent);
		color: var(--color-error);
	}

	.widget-chart {
		padding: 0.5rem;
		height: 260px;
		position: relative;
	}

	.widget-loading {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
	}

	.widget-spinner {
		width: 1.5rem;
		height: 1.5rem;
		border: 2px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}
</style>
