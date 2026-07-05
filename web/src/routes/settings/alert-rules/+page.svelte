<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';

	interface AlertRule {
		id: number;
		name: string;
		device_id: number | null;
		condition_type: string;
		threshold: number;
		channel_id: number;
		enabled: boolean;
		cooldown_seconds: number;
		last_triggered_at: string | null;
		created_at: string;
		updated_at: string;
	}

	interface Channel {
		id: number;
		name: string;
		type: string;
		enabled: boolean;
	}

	interface Device {
		id: number;
		name: string;
	}

	let rules = $state<AlertRule[]>([]);
	let channels = $state<Channel[]>([]);
	let devices = $state<Device[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Auth
	let authState = $state<{ user: { username: string; role: string } | null; token: string | null }>({
		user: null,
		token: null
	});

	// Modal state
	let modalOpen = $state(false);
	let editingRule = $state<AlertRule | null>(null);
	let deleteDialogOpen = $state(false);
	let deleteTarget = $state<AlertRule | null>(null);
	let formLoading = $state(false);

	// Form fields
	let formName = $state('');
	let formConditionType = $state('device_offline');
	let formDeviceId = $state<string>('');
	let formChannelId = $state<number>(0);
	let formThreshold = $state(3);
	let formCooldown = $state(300);
	let formEnabled = $state(true);

	const conditionTypes = [
		{ value: 'device_offline', label: () => m["notifications.Device Offline"]() },
		{ value: 'heartbeat_fail', label: () => m["notifications.Heartbeat Fail"]() },
		{ value: 'heartbeat_timeout', label: () => m["notifications.Heartbeat Timeout"]() }
	];

	onMount(() => {
		const unsub = auth.subscribe((v) => {
			authState = v;
		});
		if (get(auth).token) {
			Promise.all([fetchRules(), fetchChannels(), fetchDevices()]);
		}
		return unsub;
	});

	async function fetchRules() {
		loading = true;
		error = '';
		try {
			const res = await api.get<{ rules: AlertRule[]; total: number }>('/alert-rules');
			rules = res.rules || [];
		} catch (err: unknown) {
			error = getErrorMessage(err);
			addToast('error', error);
		} finally {
			loading = false;
		}
	}

	async function fetchChannels() {
		try {
			const res = await api.get<{ channels: Channel[]; total: number }>('/notification/channels');
			channels = res.channels || [];
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	async function fetchDevices() {
		try {
			const res = await api.get<{ devices: Device[]; total: number }>('/devices?limit=100');
			devices = res.devices || [];
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function resetForm() {
		formName = '';
		formConditionType = 'device_offline';
		formDeviceId = '';
		formChannelId = channels.length > 0 ? channels[0].id : 0;
		formThreshold = 3;
		formCooldown = 300;
		formEnabled = true;
		editingRule = null;
	}

	function openCreate() {
		resetForm();
		modalOpen = true;
	}

	function openEdit(rule: AlertRule) {
		editingRule = rule;
		formName = rule.name;
		formConditionType = rule.condition_type;
		formDeviceId = rule.device_id ? String(rule.device_id) : '';
		formChannelId = rule.channel_id;
		formThreshold = rule.threshold;
		formCooldown = rule.cooldown_seconds;
		formEnabled = rule.enabled;
		modalOpen = true;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;

		const body = {
			name: formName,
			condition_type: formConditionType,
			device_id: formDeviceId ? Number(formDeviceId) : null,
			channel_id: formChannelId,
			threshold: formThreshold,
			cooldown_seconds: formCooldown,
			enabled: formEnabled
		};

		try {
			if (editingRule) {
				await api.put(`/alert-rules/${editingRule.id}`, body);
				addToast('success', m["notifications.Rule Updated"]());
			} else {
				await api.post('/alert-rules', body);
				addToast('success', m["notifications.Rule Created"]());
			}
			modalOpen = false;
			resetForm();
			fetchRules();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			formLoading = false;
		}
	}

	async function toggleEnabled(rule: AlertRule) {
		try {
			await api.put(`/alert-rules/${rule.id}`, { enabled: !rule.enabled });
			fetchRules();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function openDelete(rule: AlertRule) {
		deleteTarget = rule;
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/alert-rules/${deleteTarget.id}`);
			deleteTarget = null;
			addToast('success', m["notifications.Rule Deleted"]());
			fetchRules();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function formatTime(iso: string | null): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	function getChannelName(id: number): string {
		const ch = channels.find((c) => c.id === id);
		return ch ? ch.name : `#${id}`;
	}

	function getDeviceName(id: number | null): string {
		if (!id) return m["notifications.Global"]();
		const dev = devices.find((d) => d.id === id);
		return dev ? dev.name : `#${id}`;
	}

	function getConditionLabel(type: string): string {
		const ct = conditionTypes.find((c) => c.value === type);
		return ct ? ct.label() : type;
	}

	let isAdmin = $derived(authState.user?.role === 'admin');

	const columns = $derived([
		{
			key: 'name',
			label: m["notifications.Rule Name"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text">${String(row.name)}</span>`
		},
		{
			key: 'condition_type',
			label: m["notifications.Condition Type"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const label = getConditionLabel(String(row.condition_type));
				return `<span class="text-xs px-2 py-0.5 rounded font-mono bg-accent/10 text-accent">${label}</span>`;
			}
		},
		{
			key: 'device_id',
			label: m["notifications.Device"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-sm text-text-muted">${getDeviceName(row.device_id as number | null)}</span>`
		},
		{
			key: 'channel_id',
			label: m["notifications.Channel"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-sm text-text-muted">${getChannelName(row.channel_id as number)}</span>`
		},
		{
			key: 'enabled',
			label: m["notifications.Enabled"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const enabled = row.enabled;
				const id = row.id;
				return `<button data-toggle-id="${id}" class="text-xs px-2 py-0.5 rounded cursor-pointer transition-colors ${enabled
					? 'bg-success/15 text-success hover:bg-success/25'
					: 'bg-border/30 text-text-muted hover:bg-border/50'
				}">${enabled ? m["notifications.Enabled"]() : m["notifications.Disabled"]()}</button>`;
			}
		},
		{
			key: 'last_triggered_at',
			label: m["notifications.Last Triggered"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted">${formatTime(row.last_triggered_at as string | null)}</span>`
		},
		{
			key: 'actions',
			label: m["common.Actions"](),
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				return `<div class="flex items-center gap-2">
					<button data-edit-id="${id}" class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10 transition-colors">${m["common.Edit"]()}</button>
					<button data-delete-id="${id}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors">${m["common.Delete"]()}</button>
				</div>`;
			}
		}
	]);
</script>

{#if !authState.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m["errors.Unauthorized Desc"]()}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m["navigation.Login"]()}</a>
	</div>
{:else if !isAdmin}
	<div class="p-6 text-center text-text-muted">
		<p>{m["errors.Forbidden Desc"]()}</p>
	</div>
{:else}
<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<div class="flex items-center gap-3">
			<a href="/settings" class="text-text-muted hover:text-text transition-colors">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
				</svg>
			</a>
			<h2 class="text-2xl font-bold text-primary">{m["notifications.Alert Rules"]()}</h2>
		</div>
		<button
			onclick={openCreate}
			class="px-4 py-2 bg-primary text-bg font-semibold rounded-lg
				hover:bg-primary-hover transition-colors text-sm"
		>
			+ {m["notifications.Create Rule"]()}
		</button>
	</div>

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	<!-- Loading skeleton -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else if rules.length === 0}
		<EmptyState
			icon="⚡"
			title={m["notifications.No Rules"]()}
			description={m["notifications.No Rules Desc"]()}
			actionLabel={m["notifications.Create Rule"]()}
			onAction={openCreate}
		/>
	{:else}
		<!-- Rules table -->
		<div class="bg-surface border border-border rounded-lg p-4">
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<div onclick={(e) => {
				const target = e.target as HTMLElement;
				const btn = target.closest('[data-delete-id],[data-edit-id],[data-toggle-id]') as HTMLElement | null;
				if (!btn) return;
				const id = Number(btn.dataset.deleteId || btn.dataset.editId || btn.dataset.toggleId);
				const rule = rules.find((r) => r.id === id);
				if (!rule) return;
				if (btn.dataset.deleteId !== undefined) openDelete(rule);
				else if (btn.dataset.editId !== undefined) openEdit(rule);
				else if (btn.dataset.toggleId !== undefined) toggleEnabled(rule);
			}}>
				<DataTable
					{columns}
					rows={rules as unknown as Record<string, unknown>[]}
					searchPlaceholder={m["notifications.Search Rules"]()}
					searchableKeys={['name', 'condition_type']}
					emptyTitle={m["common.No Results"]()}
				/>
			</div>
		</div>
	{/if}
</div>
{/if}

<!-- Create/Edit Rule Modal -->
<Modal bind:open={modalOpen} title={editingRule ? m["notifications.Edit Rule"]() : m["notifications.Create Rule"]()} onClose={resetForm} maxWidth="36rem">
	<form onsubmit={handleSubmit} class="space-y-4">
		<!-- Name -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Rule Name"]()} *</label>
			<input
				bind:value={formName}
				required
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:outline-none focus:border-primary transition-colors"
			/>
		</div>

		<!-- Condition Type -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Condition Type"]()}</label>
			<select
				bind:value={formConditionType}
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none"
			>
				{#each conditionTypes as ct}
					<option value={ct.value}>{ct.label()}</option>
				{/each}
			</select>
		</div>

		<!-- Device -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Device"]()}</label>
			<select
				bind:value={formDeviceId}
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none"
			>
				<option value="">{m["notifications.Global"]()}</option>
				{#each devices as dev}
					<option value={String(dev.id)}>{dev.name}</option>
				{/each}
			</select>
		</div>

		<!-- Channel -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Channel"]()} *</label>
			<select
				bind:value={formChannelId}
				required
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none"
			>
				{#each channels as ch}
					<option value={ch.id}>{ch.name} ({ch.type})</option>
				{/each}
			</select>
		</div>

		<!-- Threshold + Cooldown -->
		<div class="grid grid-cols-2 gap-3">
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.Threshold"]()}</label>
				<input
					bind:value={formThreshold}
					type="number"
					min="1"
					required
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.Cooldown"]()}</label>
				<input
					bind:value={formCooldown}
					type="number"
					min="0"
					required
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
			</div>
		</div>

		<!-- Enabled -->
		<div class="flex items-center gap-2">
			<input
				type="checkbox"
				bind:checked={formEnabled}
				class="w-4 h-4 rounded border-border accent-[var(--color-primary)]"
			/>
			<label class="text-sm text-text">{m["notifications.Enabled"]()}</label>
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<button
				type="submit"
				disabled={formLoading}
				class="px-6 py-2 bg-primary text-bg font-semibold rounded-lg
					hover:bg-primary-hover transition-colors disabled:opacity-50 text-sm"
			>
				{formLoading ? '...' : m["common.Save"]()}
			</button>
			<button
				type="button"
				onclick={() => { modalOpen = false; resetForm(); }}
				class="px-6 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary transition-colors text-sm"
			>
				{m["common.Cancel"]()}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteDialogOpen}
	title={m["notifications.Delete Rule"]()}
	message={deleteTarget ? `${m["common.Are you sure?"]()} "${deleteTarget.name}"` : ''}
	confirmLabel={m["common.Delete"]()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>
