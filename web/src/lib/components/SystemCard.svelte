<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import type { System } from '$lib/types';
	import { Pencil, Trash2, Link2, ExternalLink } from '@lucide/svelte';

	let {
		system,
		onEdit,
		onDelete
	}: {
		system: System;
		onEdit: () => void;
		onDelete: () => void;
	} = $props();

	const categoryStyles: Record<string, string> = {
		web_app: 'bg-accent/15 text-accent',
		database: 'bg-success/15 text-success',
		middleware: 'bg-accent-purple/15 text-accent-purple',
		custom: 'bg-text-muted/15 text-muted'
	};

	const categoryLabels: Record<string, string> = {
		web_app: m['systems.Web Application'](),
		database: m['systems.Database'](),
		middleware: m['systems.Middleware'](),
		custom: m['systems.Custom']()
	};

	function getCategoryClass(cat: string): string {
		return categoryStyles[cat] ?? categoryStyles['custom']!;
	}

	function getCategoryLabel(cat: string): string {
		return categoryLabels[cat] ?? categoryLabels['custom']!;
	}
</script>

<article class="system-card">
	<!-- Header row: name + action buttons -->
	<div class="system-card-header">
		<h4 class="system-card-name">{system.name}</h4>
		<div class="system-card-actions">
			<button
				class="system-card-btn"
				onclick={onEdit}
				aria-label={m['common.Edit']()}
				title={m['common.Edit']()}
			>
				<Pencil class="w-3.5 h-3.5" />
			</button>
			<button
				class="system-card-btn system-card-btn-danger"
				onclick={onDelete}
				aria-label={m['common.Delete']()}
				title={m['common.Delete']()}
			>
				<Trash2 class="w-3.5 h-3.5" />
			</button>
		</div>
	</div>

	<!-- Category badge -->
	<span class="system-card-badge {getCategoryClass(system.category)}">
		{getCategoryLabel(system.category)}
	</span>

	<!-- Entry URL -->
	{#if system.entry_url}
		<a
			href={system.entry_url}
			target="_blank"
			rel="noopener noreferrer"
			class="system-card-url"
		>
			<Link2 class="w-3.5 h-3.5 shrink-0" />
			<span class="truncate">{system.entry_url}</span>
			<ExternalLink class="w-3 h-3 shrink-0 text-muted" />
		</a>
	{/if}

	<!-- Description -->
	{#if system.description}
		<p class="system-card-desc">{system.description}</p>
	{/if}

	<!-- Metrics indicator -->
	{#if system.metrics_enabled}
		<div class="system-card-metrics">
			<span class="system-card-metrics-dot"></span>
			<span>{m['systems.Metrics Enabled']()}</span>
		</div>
	{/if}
</article>

<style>
	.system-card {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
		padding: 1rem;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		transition: box-shadow 0.2s ease, border-color 0.2s ease;
	}

	.system-card:hover {
		box-shadow: var(--shadow-md);
		border-color: var(--color-primary);
	}

	.system-card-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 0.5rem;
	}

	.system-card-name {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0;
		line-height: 1.4;
		word-break: break-word;
	}

	.system-card-actions {
		display: flex;
		gap: 0.25rem;
		flex-shrink: 0;
		opacity: 0;
		transition: opacity 0.15s ease;
	}

	.system-card:hover .system-card-actions {
		opacity: 1;
	}

	.system-card-btn {
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

	.system-card-btn:hover {
		background: var(--color-surface-2);
		color: var(--color-text);
	}

	.system-card-btn-danger:hover {
		background: color-mix(in srgb, var(--color-error) 15%, transparent);
		color: var(--color-error);
	}

	.system-card-badge {
		display: inline-block;
		width: fit-content;
		padding: 0.125rem 0.5rem;
		font-size: 0.6875rem;
		font-weight: 500;
		border-radius: 9999px;
		letter-spacing: 0.02em;
	}

	.system-card-url {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.8125rem;
		color: var(--color-accent);
		text-decoration: none;
		padding: 0.375rem 0.5rem;
		border-radius: var(--radius-sm);
		background: color-mix(in srgb, var(--color-accent) 6%, transparent);
		transition: background 0.15s ease;
	}

	.system-card-url:hover {
		background: color-mix(in srgb, var(--color-accent) 12%, transparent);
		text-decoration: none;
	}

	.system-card-desc {
		font-size: 0.8125rem;
		color: var(--color-text-muted);
		line-height: 1.5;
		margin: 0;
		display: -webkit-box;
		-webkit-line-clamp: 2;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}

	.system-card-metrics {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.75rem;
		color: var(--color-success);
	}

	.system-card-metrics-dot {
		width: 0.5rem;
		height: 0.5rem;
		border-radius: 50%;
		background: var(--color-success);
		animation: pulse-green 2s infinite;
	}
</style>
