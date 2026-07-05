<script lang="ts">
	import Modal from './Modal.svelte';
	import { m } from '$lib/i18n-paraglide';
	import { addToast } from '$lib/stores/toast';
	import { api } from '$lib/api/client';
	import { getErrorMessage } from '$lib/utils/error';

	interface DashboardConfig {
		id: string;
		name: string;
		type: string;
		data_source: string;
		query: string;
		refresh_interval: number;
		position: number;
		created_at: string;
		updated_at: string;
	}

	let {
		open = $bindable(false),
		editWidget = null,
		onSaved
	}: {
		open?: boolean;
		editWidget?: DashboardConfig | null;
		onSaved: () => void;
	} = $props();

	let name = $state('');
	let type = $state('gauge');
	let query = $state('');
	let refreshInterval = $state(30);
	let saving = $state(false);

	const isEditing = $derived(editWidget !== null);

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
			} else {
				name = '';
				type = 'gauge';
				query = '';
				refreshInterval = 30;
			}
		}
	});

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
</script>

	<Modal bind:open title={isEditing ? m["dashboard.Edit Widget"]() : m["dashboard.Add Widget"]()} maxWidth="28rem">
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
				<label class="label" for="widget-query">{m["dashboard.Query"]} (PromQL)</label>
				<input
					id="widget-query"
					type="text"
					class="input font-mono"
					bind:value={query}
					placeholder={"e.g. up{job='node'}"}
					required
				/>
			</div>

			<div class="form-group">
				<label class="label" for="widget-refresh">{m["dashboard.Refresh Interval"]} (s)</label>
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
				<button type="submit" class="btn btn-primary" disabled={saving}>
					{saving ? m["common.Loading"]() + '...' : (isEditing ? m["common.Save"]() : m["common.Create"]())}
				</button>
			</div>
		</form>
	</Modal>

	<style>
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
	</style>
