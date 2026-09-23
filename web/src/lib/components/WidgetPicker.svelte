<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import Modal from './Modal.svelte';
	import LoadingButton from './LoadingButton.svelte';
	import { m } from '$lib/i18n-paraglide';
	import { addToast } from '$lib/stores/toast';
	import { api } from '$lib/api/client';
	import { getErrorMessage } from '$lib/utils/error';
	import type { DashboardWidgetConfig } from '$lib/types';
	import {
		PieChart,
		Gauge,
		MapPin,
		History,
		Power,
		ScanSearch,
		HeartPulse,
		Activity
	} from '@lucide/svelte';
	import type { Component } from 'svelte';

	let {
		open = $bindable(false),
		editWidget = null,
		onSaved
	}: {
		open?: boolean;
		editWidget?: DashboardWidgetConfig | null;
		onSaved: () => void;
	} = $props();

	// ── Preset gallery ──
	// Each entry maps 1:1 to a key in the backend's builtinWidgetTemplates
	// whitelist (internal/api/handler/dashboard.go): query carries the
	// "builtin:<key>" template id and type must match the backend's expected
	// rendering type or the API rejects the request. Labels/descs are thunks
	// (not keys) so the paraglide call sites stay statically typed.
	interface PresetDef {
		key: string;
		type: 'pie' | 'bar' | 'gauge' | 'list';
		icon: Component<{ class?: string }>;
		label: () => string;
		desc: () => string;
	}

	const presets: PresetDef[] = [
		{ key: 'builtin:device_status', type: 'pie', icon: PieChart, label: () => m["dashboard.Preset Device Status"](), desc: () => m["dashboard.Preset Device Status Desc"]() },
		{ key: 'builtin:device_types', type: 'pie', icon: Activity, label: () => m["dashboard.Preset Device Types"](), desc: () => m["dashboard.Preset Device Types Desc"]() },
		{ key: 'builtin:device_locations', type: 'bar', icon: MapPin, label: () => m["dashboard.Preset Device Locations"](), desc: () => m["dashboard.Preset Device Locations Desc"]() },
		{ key: 'builtin:online_rate', type: 'gauge', icon: Gauge, label: () => m["dashboard.Preset Online Rate"](), desc: () => m["dashboard.Preset Online Rate Desc"]() },
		{ key: 'builtin:recent_changes', type: 'list', icon: History, label: () => m["dashboard.Preset Recent Changes"](), desc: () => m["dashboard.Preset Recent Changes Desc"]() },
		{ key: 'builtin:offline_devices', type: 'list', icon: Power, label: () => m["dashboard.Preset Offline Devices"](), desc: () => m["dashboard.Preset Offline Devices Desc"]() },
		{ key: 'builtin:scan_activity', type: 'list', icon: ScanSearch, label: () => m["dashboard.Preset Scan Activity"](), desc: () => m["dashboard.Preset Scan Activity Desc"]() },
		{ key: 'builtin:probe_status', type: 'list', icon: HeartPulse, label: () => m["dashboard.Preset Probe Status"](), desc: () => m["dashboard.Preset Probe Status Desc"]() }
	];

	const isEditing = $derived(editWidget !== null);
	const editingBuiltin = $derived(editWidget !== null && editWidget.data_source === 'builtin');

	function typeLabel(t: string): string {
		switch (t) {
			case 'pie': return m["dashboard.Pie"]();
			case 'bar': return m["dashboard.Bar"]();
			case 'line': return m["dashboard.Line"]();
			case 'gauge': return m["dashboard.Gauge"]();
			case 'list': return m["dashboard.Type List"]();
			default: return t;
		}
	}

	let tab: 'presets' | 'advanced' = $state('presets');
	let addingKey = $state<string | null>(null);

	// ── Form state (advanced tab + builtin rename) ──
	let name = $state('');
	let type = $state('gauge');
	let query = $state('');
	let refreshInterval = $state(30);
	let saving = $state(false);

	const widgetTypes = [
		{ value: 'gauge', label: m["dashboard.Gauge"]() },
		{ value: 'line', label: m["dashboard.Line Chart"]() },
		{ value: 'bar', label: m["dashboard.Bar Chart"]() },
		{ value: 'pie', label: m["dashboard.Pie Chart"]() }
	];

	$effect(() => {
		if (open) {
			if (editWidget) {
				name = editWidget.name;
				type = editWidget.type;
				query = editWidget.query;
				refreshInterval = editWidget.refresh_interval;
				// Editing always lands on the tab that owns the widget: builtin
				// widgets offer rename-only, prometheus widgets the full form.
				tab = editWidget.data_source === 'builtin' ? 'presets' : 'advanced';
			} else {
				name = '';
				type = 'gauge';
				query = '';
				refreshInterval = 30;
				tab = 'presets';
			}
			addingKey = null;
		}
	});

	// addPreset creates a builtin widget immediately with its default name;
	// one click, no form. Renaming afterwards goes through edit.
	async function addPreset(p: PresetDef) {
		addingKey = p.key;
		saving = true;
		try {
			await api.post('/dashboard/configs', {
				name: p.label(),
				type: p.type,
				data_source: 'builtin',
				query: p.key
			});
			addToast('success', m["dashboard.Widget Created"]());
			open = false;
			onSaved();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			saving = false;
			addingKey = null;
		}
	}

	async function handleSubmit() {
		if (!name.trim() || !query.trim()) {
			addToast('error', m["dashboard.Widget Name"]() + ' & ' + m["dashboard.Query"]() + ' required');
			return;
		}
		saving = true;
		try {
			if (isEditing && editWidget) {
				await api.put(`/dashboard/configs/${editWidget.id}`, {
					name: name.trim(),
					type,
					data_source: 'prometheus',
					query: query.trim(),
					refresh_interval: refreshInterval,
					position: editWidget.position
				});
				addToast('success', m["dashboard.Widget Updated"]());
			} else {
				await api.post('/dashboard/configs', {
					name: name.trim(),
					type,
					data_source: 'prometheus',
					query: query.trim(),
					refresh_interval: refreshInterval
				});
				addToast('success', m["dashboard.Widget Created"]());
			}
			open = false;
			onSaved();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			saving = false;
		}
	}

	// saveBuiltinRename edits ONLY the name of a builtin widget: the template
	// key/type/data_source are passed through untouched (the API would reject
	// a builtin row whose type drifts from the template's).
	async function saveBuiltinRename() {
		if (!editWidget || !name.trim()) return;
		saving = true;
		try {
			await api.put(`/dashboard/configs/${editWidget.id}`, {
				name: name.trim(),
				type: editWidget.type,
				data_source: editWidget.data_source,
				query: editWidget.query,
				refresh_interval: editWidget.refresh_interval,
				position: editWidget.position
			});
			addToast('success', m["dashboard.Widget Updated"]());
			open = false;
			onSaved();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			saving = false;
		}
	}
</script>

<Modal bind:open title={isEditing ? m["dashboard.Edit Widget"]() : m["dashboard.Add Widget"]()} maxWidth={editingBuiltin ? '28rem' : '40rem'}>
	{#if editingBuiltin}
		<!-- Builtin widgets: rename only: the data comes from the system itself. -->
		<form onsubmit={(e) => { e.preventDefault(); saveBuiltinRename(); }} class="widget-form">
			<p class="hint">{m["dashboard.Builtin Edit Hint"]()}</p>
			<div class="form-group">
				<label class="label" for="widget-name">{m["dashboard.Display Name"]()}</label>
				<input id="widget-name" type="text" class="input" bind:value={name} required />
			</div>
			<div class="form-actions">
				<button type="button" class="btn btn-secondary" onclick={() => open = false}>
					{m["common.Cancel"]()}
				</button>
				<LoadingButton type="submit" loading={saving} variant="primary" label={m["common.Save"]()} />
			</div>
		</form>
	{:else}
		<div class="picker-tabs" role="tablist">
			<button
				type="button"
				role="tab"
				aria-selected={tab === 'presets'}
				class="picker-tab {tab === 'presets' ? 'active' : ''}"
				onclick={() => (tab = 'presets')}
			>
				{m["dashboard.Presets"]()}
			</button>
			<button
				type="button"
				role="tab"
				aria-selected={tab === 'advanced'}
				class="picker-tab {tab === 'advanced' ? 'active' : ''}"
				onclick={() => (tab = 'advanced')}
			>
				{m["dashboard.Advanced PromQL"]()}
			</button>
		</div>

		{#if tab === 'presets'}
			<p class="hint">{m["dashboard.Presets Desc"]()}</p>
			<div class="preset-grid">
				{#each presets as p (p.key)}
					<div class="preset-card">
						<div class="preset-head">
							<span class="preset-icon"><p.icon class="w-[18px] h-[18px]" /></span>
							<span class="preset-title">{p.label()}</span>
							<span class="preset-kind">{typeLabel(p.type)}</span>
						</div>
						<p class="preset-desc">{p.desc()}</p>
						<button
							type="button"
							class="btn btn-secondary preset-add"
							disabled={saving}
							onclick={() => addPreset(p)}
						>
							{addingKey === p.key ? m["dashboard.Adding"]() : m["dashboard.Add"]()}
						</button>
					</div>
				{/each}
			</div>
		{:else}
			<p class="hint">{m["dashboard.Advanced Desc"]()}</p>
			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="widget-form">
				<div class="form-group">
					<label class="label" for="widget-name">{m["dashboard.Widget Name"]()}</label>
					<input
						id="widget-name"
						type="text"
						class="input"
						bind:value={name}
						placeholder="e.g. CPU Usage"
						required
					/>
				</div>

				<div class="form-group">
					<label class="label" for="widget-type">{m["dashboard.Widget Type"]()}</label>
					<select id="widget-type" class="select" bind:value={type}>
						{#each widgetTypes as t}
							<option value={t.value}>{t.label}</option>
						{/each}
					</select>
				</div>

				<div class="form-group">
					<label class="label" for="widget-query">{m["dashboard.Query (PromQL)"]()}</label>
					<input
						id="widget-query"
						type="text"
						class="input font-mono"
						bind:value={query}
						placeholder={"e.g. up{job='node'}"}
						required
					/>
					<span class="hint-inline">{m["dashboard.Advanced Needs Prom"]()}</span>
				</div>

				<div class="form-group">
					<label class="label" for="widget-refresh">{m["dashboard.Refresh Interval (s)"]()}</label>
					<input
						id="widget-refresh"
						type="number"
						class="input"
						bind:value={refreshInterval}
						min="5"
						max="300"
						step="5"
					/>
				</div>

				<div class="form-actions">
					<button type="button" class="btn btn-secondary" onclick={() => open = false}>
						{m["common.Cancel"]()}
					</button>
					<LoadingButton type="submit" loading={saving} variant="primary" label={isEditing ? m["common.Save"]() : m["common.Create"]()} />
				</div>
			</form>
		{/if}
	{/if}
</Modal>

<style>
	.picker-tabs {
		display: flex;
		gap: 0.25rem;
		border-bottom: 1px solid var(--color-border);
		margin-bottom: 0.75rem;
	}

	.picker-tab {
		padding: 0.5rem 0.875rem;
		border: none;
		background: transparent;
		color: var(--color-text-muted);
		font-size: 0.8125rem;
		font-weight: 500;
		cursor: pointer;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
		transition: color 0.15s ease, border-color 0.15s ease;
	}

	.picker-tab:hover {
		color: var(--color-text);
	}

	.picker-tab.active {
		color: var(--color-primary);
		border-bottom-color: var(--color-primary);
	}

	.hint {
		margin: 0 0 0.75rem;
		font-size: 0.75rem;
		color: var(--color-text-muted);
		line-height: 1.5;
	}

	.hint-inline {
		font-size: 0.6875rem;
		color: var(--color-text-muted);
	}

	.preset-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 0.625rem;
	}

	.preset-card {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0.75rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md, 8px);
		background: var(--color-surface-2, var(--color-surface));
	}

	.preset-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.preset-icon {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		border-radius: var(--radius-sm);
		background: color-mix(in srgb, var(--color-primary) 12%, transparent);
		color: var(--color-primary);
		flex-shrink: 0;
	}

	.preset-title {
		flex: 1;
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--color-text);
	}

	.preset-kind {
		font-size: 0.625rem;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
	}

	.preset-desc {
		margin: 0;
		font-size: 0.75rem;
		color: var(--color-text-muted);
		line-height: 1.45;
		flex: 1;
	}

	.preset-add {
		align-self: flex-end;
		font-size: 0.75rem;
		padding: 0.3rem 0.75rem;
	}

	.widget-form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.form-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.75rem;
		margin-top: 0.5rem;
	}

	@media (max-width: 560px) {
		.preset-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
