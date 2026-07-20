<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import { X, Plus, LoaderCircle } from '@lucide/svelte';

	let {
		labels = {},
		staticLabels = {},
		dynamicLabels = {},
		onSave,
		readonly = false
	}: {
		labels: Record<string, string>;
		staticLabels?: Record<string, string>;
		dynamicLabels?: Record<string, string>;
		onSave: (labels: Record<string, string>) => void;
		readonly?: boolean;
	} = $props();

	type LabelEntry = { key: string; value: string; id: number };
	let nextId = $state(0);

	let entries = $state<LabelEntry[]>([]);
	let saving = $state(false);
	let hasChanges = $state(false);

	// Initialize entries from labels prop
	$effect(() => {
		const keys = Object.keys(labels);
		if (keys.length === 0 && entries.length === 0) return;
		// Rebuild only if external labels changed (not from our own edits)
		const current = new Map(entries.map((e) => [e.key, e.value]));
		const incoming = new Map(keys.map((k) => [k, labels[k]]));
		let mismatch = current.size !== incoming.size;
		if (!mismatch) {
			for (const [k, v] of incoming) {
				if (current.get(k) !== v) {
					mismatch = true;
					break;
				}
			}
		}
		if (mismatch) {
			entries = Object.entries(labels).map(([key, value]) => ({ key, value, id: nextId++ }));
			hasChanges = false;
		}
	});

	// Build merged preview: per-device > dynamic > static
	let merged = $derived.by(() => {
		const result: Record<string, { value: string; source: 'static' | 'dynamic' | 'device' }> = {};
		for (const [k, v] of Object.entries(staticLabels)) {
			result[k] = { value: v, source: 'static' };
		}
		for (const [k, v] of Object.entries(dynamicLabels)) {
			result[k] = { value: v, source: 'dynamic' };
		}
		for (const e of entries) {
			if (e.key.trim()) {
				result[e.key.trim()] = { value: e.value, source: 'device' };
			}
		}
		return result;
	});

	function addEntry() {
		entries = [...entries, { key: '', value: '', id: nextId++ }];
		hasChanges = true;
	}

	function removeEntry(id: number) {
		entries = entries.filter((e) => e.id !== id);
		hasChanges = true;
	}

	function updateKey(id: number, newKey: string) {
		entries = entries.map((e) => (e.id === id ? { ...e, key: newKey } : e));
		hasChanges = true;
	}

	function updateValue(id: number, newValue: string) {
		entries = entries.map((e) => (e.id === id ? { ...e, value: newValue } : e));
		hasChanges = true;
	}

	async function handleSave() {
		const result: Record<string, string> = {};
		for (const e of entries) {
			const k = e.key.trim();
			if (k) result[k] = e.value;
		}
		saving = true;
		try {
			await onSave(result);
			hasChanges = false;
		} finally {
			saving = false;
		}
	}

	const sourceColors: Record<string, string> = {
		static: 'bg-accent/15 text-accent',
		dynamic: 'bg-accent-cyan/15 text-accent-cyan',
		device: 'bg-primary/15 text-primary'
	};

	const sourceLabels: Record<string, string> = {
		static: m['labels.Source Static'](),
		dynamic: m['labels.Source Dynamic'](),
		device: m['labels.Source Device']()
	};
</script>

<div class="label-editor">
	<!-- Editable per-device labels -->
	<div class="mb-4">
		<h4 class="text-sm font-semibold text-text mb-3">{m['labels.Per Device Labels']()}</h4>

		{#if entries.length === 0}
			<p class="text-xs text-muted italic mb-3">{m['labels.No Device Labels']()}</p>
		{:else}
			<div class="space-y-2 mb-3">
				{#each entries as entry (entry.id)}
					<div class="label-row">
						{#if readonly}
							<span class="label-key-readonly">{entry.key || '...'}</span>
							<span class="label-sep">=</span>
							<span class="label-value-readonly">{entry.value}</span>
						{:else}
							<input
								type="text"
								placeholder="key"
								value={entry.key}
								oninput={(e) => updateKey(entry.id, (e.target as HTMLInputElement).value)}
								class="label-input"
							/>
							<span class="label-sep">=</span>
							<input
								type="text"
								placeholder="value"
								value={entry.value}
								oninput={(e) => updateValue(entry.id, (e.target as HTMLInputElement).value)}
								class="label-input"
							/>
							<button
								onclick={() => removeEntry(entry.id)}
								class="label-remove-btn"
								title={m['common.Delete']()}
								aria-label={m['common.Delete']()}
							>
								<X class="w-3.5 h-3.5" />
							</button>
						{/if}
					</div>
				{/each}
			</div>
		{/if}

		{#if !readonly}
			<button onclick={addEntry} class="label-add-btn">
				<Plus class="w-3.5 h-3.5" />
				{m['labels.Add Label']()}
			</button>
		{/if}
	</div>

	<!-- Merged label preview -->
	<div class="label-preview">
		<h4 class="text-sm font-semibold text-text mb-2">{m['labels.Merged Preview']()}</h4>

		{#if Object.keys(merged).length === 0}
			<p class="text-xs text-muted italic">{m['labels.No Labels']()}</p>
		{:else}
			<div class="space-y-1.5">
				{#each Object.entries(merged).sort(([a], [b]) => a.localeCompare(b)) as [key, info]}
					<div class="label-preview-row">
						<span class="label-preview-key">{key}</span>
						<span class="label-preview-sep">=</span>
						<span class="label-preview-value">{info.value}</span>
						<span class="label-source-badge {sourceColors[info.source]}">
							{sourceLabels[info.source]}
						</span>
					</div>
				{/each}
			</div>
		{/if}
	</div>

	<!-- Save button -->
	{#if !readonly}
		<div class="mt-4 flex justify-end">
			<button
				onclick={handleSave}
				disabled={!hasChanges || saving}
				class="px-5 py-2 bg-primary text-inverse font-semibold rounded-lg
					hover:bg-primary-hover transition-colors disabled:opacity-40
					disabled:cursor-not-allowed text-sm inline-flex items-center gap-2"
			>
				{#if saving}<LoaderCircle class="w-4 h-4 animate-spin" aria-hidden="true" />{/if}
				<span>{m['common.Save']()}</span>
			</button>
		</div>
	{/if}
</div>

<style>
	.label-editor {
		padding: 0;
	}

	.label-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.label-input {
		flex: 1;
		padding: 0.375rem 0.625rem;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		font-size: 0.8125rem;
		color: var(--color-text);
		font-family: var(--font-mono);
		transition: border-color 0.15s ease;
	}

	.label-input:focus {
		border-color: var(--color-primary);
		outline: none;
	}

	.label-input::placeholder {
		color: var(--color-text-muted);
		opacity: 0.5;
	}

	.label-key-readonly,
	.label-value-readonly {
		font-size: 0.8125rem;
		color: var(--color-text);
		font-family: var(--font-mono);
		padding: 0.375rem 0.625rem;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
	}

	.label-key-readonly {
		flex: 1;
		font-weight: 500;
	}

	.label-value-readonly {
		flex: 1;
	}

	.label-sep {
		color: var(--color-text-muted);
		font-size: 0.75rem;
		flex-shrink: 0;
	}

	.label-remove-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 1.5rem;
		height: 1.5rem;
		border-radius: var(--radius-sm);
		border: none;
		background: transparent;
		color: var(--color-text-muted);
		cursor: pointer;
		flex-shrink: 0;
		transition: background 0.15s ease, color 0.15s ease;
	}

	.label-remove-btn:hover {
		background: color-mix(in srgb, var(--color-error) 15%, transparent);
		color: var(--color-error);
	}

	.label-add-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.375rem 0.75rem;
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--color-primary);
		background: transparent;
		border: 1px dashed var(--color-border);
		border-radius: var(--radius-md);
		cursor: pointer;
		transition: border-color 0.15s ease, background 0.15s ease;
	}

	.label-add-btn:hover {
		border-color: var(--color-primary);
		background: color-mix(in srgb, var(--color-primary) 6%, transparent);
	}

	.label-preview {
		padding: 0.75rem 1rem;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
	}

	.label-preview-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.8125rem;
		font-family: var(--font-mono);
		line-height: 1.6;
	}

	.label-preview-key {
		color: var(--color-text);
		font-weight: 500;
		min-width: 0;
	}

	.label-preview-sep {
		color: var(--color-text-muted);
		flex-shrink: 0;
	}

	.label-preview-value {
		color: var(--color-text-muted);
		flex: 1;
		min-width: 0;
		word-break: break-all;
	}

	.label-source-badge {
		display: inline-block;
		padding: 0.0625rem 0.375rem;
		font-size: 0.625rem;
		font-weight: 500;
		border-radius: 9999px;
		white-space: nowrap;
		flex-shrink: 0;
		font-family: inherit;
		letter-spacing: 0.02em;
	}
</style>
