<script lang="ts">
	import Chart from './Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import { GripVertical, Pencil, Trash2 } from '@lucide/svelte';

	interface WidgetState {
		id: string;
		name: string;
		type: string;
		data_source: string;
		query: string;
		refresh_interval: number;
		position: number;
		chartOption: EChartsOption;
		loading?: boolean;
		created_at: string;
		updated_at: string;
	}

	let {
		widget,
		onEdit,
		onRemove,
		ondragstart,
		ondragover,
		ondrop
	}: {
		widget: WidgetState;
		onEdit: (id: string) => void;
		onRemove: (id: string) => void;
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
<div
	class="widget-card"
	class:drag-over
	draggable="true"
	ondragstart={handleDragStart}
	ondragover={handleDragOver}
	ondragleave={handleDragLeave}
	ondrop={handleDrop}
>
	<div class="widget-header">
		<div class="widget-drag-handle" title="Drag to reorder">
			<GripVertical class="w-[14px] h-[14px]" />
		</div>
		<h3 class="widget-title">{widget.name}</h3>
		<div class="widget-actions">
			<button class="widget-action-btn" onclick={() => onEdit(widget.id)} title="Edit widget" aria-label="Edit widget">
				<Pencil class="w-[14px] h-[14px]" />
			</button>
			<button class="widget-action-btn widget-action-danger" onclick={() => onRemove(widget.id)} title="Remove widget" aria-label="Remove widget">
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
		color: var(--color-text-muted);
		opacity: 0.4;
		transition: opacity 0.15s ease;
		flex-shrink: 0;
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
		width: 1.75rem;
		height: 1.75rem;
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
