<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import { LoaderCircle } from '@lucide/svelte';

	interface ChannelConfig {
		url?: string;
		headers?: Record<string, string>;
		host?: string;
		port?: number;
		username?: string;
		password?: string;
		from?: string;
		to?: string;
	}

	interface Channel {
		id: number;
		name: string;
		type: string;
		config: ChannelConfig;
		enabled: boolean;
		created_at: string;
		updated_at: string;
	}

	let channels = $state<Channel[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Auth is consumed directly via the $auth store (auto-subscribed in .svelte).

	// Modal state
	let modalOpen = $state(false);
	let editingChannel = $state<Channel | null>(null);
	let deleteDialogOpen = $state(false);
	let deleteTarget = $state<Channel | null>(null);
	let formLoading = $state(false);

	// Form fields
	let formName = $state('');
	let formType = $state<'webhook' | 'email'>('webhook');
	let formEnabled = $state(true);

	// Webhook fields
	let formUrl = $state('');
	let formHeaders = $state<{ key: string; value: string }[]>([{ key: '', value: '' }]);

	// Email fields
	let formSmtpHost = $state('');
	let formSmtpPort = $state(587);
	let formSmtpUsername = $state('');
	let formSmtpPassword = $state('');
	let formFromAddress = $state('');
	let formToAddress = $state('');

	onMount(() => {
		fetchChannels();
	});

	async function fetchChannels() {
		loading = true;
		error = '';
		try {
			const res = await api.get<{ channels: Channel[]; total: number }>('/notification/channels');
			channels = res.channels || [];
		} catch (err: unknown) {
			// Inline banner only on initial load (parallel toast was noisy).
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		formName = '';
		formType = 'webhook';
		formEnabled = true;
		formUrl = '';
		formHeaders = [{ key: '', value: '' }];
		formSmtpHost = '';
		formSmtpPort = 587;
		formSmtpUsername = '';
		formSmtpPassword = '';
		formFromAddress = '';
		formToAddress = '';
		editingChannel = null;
	}

	function openCreate() {
		resetForm();
		modalOpen = true;
	}

	function openEdit(channel: Channel) {
		editingChannel = channel;
		formName = channel.name;
		formType = channel.type as 'webhook' | 'email';
		formEnabled = channel.enabled;

		if (channel.type === 'webhook') {
			const cfg = channel.config as ChannelConfig;
			formUrl = cfg.url || '';
			const hdrs = cfg.headers || {};
			const entries = Object.entries(hdrs);
			formHeaders = entries.length > 0
				? entries.map(([key, value]) => ({ key, value }))
				: [{ key: '', value: '' }];
			formSmtpHost = '';
			formSmtpPort = 587;
			formSmtpUsername = '';
			formSmtpPassword = '';
			formFromAddress = '';
			formToAddress = '';
		} else {
			const cfg = channel.config as ChannelConfig;
			formSmtpHost = cfg.host || '';
			formSmtpPort = cfg.port || 587;
			formSmtpUsername = cfg.username || '';
			formSmtpPassword = ''; // masked, leave blank to keep
			formFromAddress = cfg.from || '';
			formToAddress = cfg.to || '';
			formUrl = '';
			formHeaders = [{ key: '', value: '' }];
		}

		modalOpen = true;
	}

	function addHeaderRow() {
		formHeaders = [...formHeaders, { key: '', value: '' }];
	}

	function removeHeaderRow(index: number) {
		formHeaders = formHeaders.filter((_, i) => i !== index);
	}

	function buildConfig(): Record<string, unknown> {
		if (formType === 'webhook') {
			const headers: Record<string, string> = {};
			for (const h of formHeaders) {
				if (h.key.trim()) {
					headers[h.key.trim()] = h.value;
				}
			}
			return { url: formUrl, headers };
		}
		const cfg: Record<string, unknown> = {
			host: formSmtpHost,
			port: formSmtpPort,
			username: formSmtpUsername,
			from: formFromAddress,
			to: formToAddress
		};
		if (formSmtpPassword) {
			cfg.password = formSmtpPassword;
		}
		return cfg;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;

		const body = {
			name: formName,
			type: formType,
			config: buildConfig(),
			enabled: formEnabled
		};

		try {
			if (editingChannel) {
				// Build update body with pointer fields
				const updateBody: Record<string, unknown> = {
					name: formName,
					type: formType,
					config: buildConfig(),
					enabled: formEnabled
				};
				await api.put(`/notification/channels/${editingChannel.id}`, updateBody);
				addToast('success', m["notifications.Channel Updated"]());
			} else {
				await api.post('/notification/channels', body);
				addToast('success', m["notifications.Channel Created"]());
			}
			modalOpen = false;
			resetForm();
			fetchChannels();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			formLoading = false;
		}
	}

	async function toggleEnabled(channel: Channel) {
		try {
			await api.put(`/notification/channels/${channel.id}`, { enabled: !channel.enabled });
			fetchChannels();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	async function testChannel(channel: Channel) {
		if (!channel.enabled) {
			addToast('info', m["notifications.Test Disabled"]());
			return;
		}
		try {
			await api.post(`/notification/channels/${channel.id}/test`, {});
			addToast('success', m["notifications.Test Dispatched"]());
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function openDelete(channel: Channel) {
		deleteTarget = channel;
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/notification/channels/${deleteTarget.id}`);
			deleteTarget = null;
			addToast('success', m["notifications.Channel Deleted"]());
			fetchChannels();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function formatTime(iso: string): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	let isAdmin = $derived($auth.user?.role === 'admin');

	const columns = $derived([
		{
			key: 'name',
			label: m["notifications.Channel Name"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text">${String(row.name)}</span>`
		},
		{
			key: 'type',
			label: m["notifications.Channel Type"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = String(row.type);
				const color = t === 'webhook' ? 'var(--color-accent)' : 'var(--color-primary)';
				return `<span class="text-xs px-2 py-0.5 rounded font-mono" style="background: ${color}10; color: ${color}">${t}</span>`;
			}
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
			key: 'created_at',
			label: m["users.Created At"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted">${formatTime(String(row.created_at))}</span>`
		},
		{
			key: 'actions',
			label: m["common.Actions"](),
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				return `<div class="flex items-center gap-2">
					<button data-test-id="${id}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors">${m["notifications.Test Channel"]()}</button>
					<button data-edit-id="${id}" class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10 transition-colors">${m["common.Edit"]()}</button>
					<button data-delete-id="${id}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors">${m["common.Delete"]()}</button>
				</div>`;
			}
		}
	]);
</script>

{#if !$auth.token}
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
			<h2 class="text-2xl font-bold text-primary">{m["notifications.Channels"]()}</h2>
		</div>
		<button
			onclick={openCreate}
			class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
				hover:bg-primary-hover transition-colors text-sm"
		>
			+ {m["notifications.Create Channel"]()}
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
	{:else if channels.length === 0}
		<EmptyState
			icon="🔔"
			title={m["notifications.No Channels"]()}
			description={m["notifications.No Channels Desc"]()}
			actionLabel={m["notifications.Create Channel"]()}
			onAction={openCreate}
		/>
	{:else}
		<!-- Channel table -->
		<div class="bg-surface border border-border rounded-lg p-4">
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<div onclick={(e) => {
				const target = e.target as HTMLElement;
				const btn = target.closest('[data-delete-id],[data-edit-id],[data-test-id],[data-toggle-id]') as HTMLElement | null;
				if (!btn) return;
				const id = Number(btn.dataset.deleteId || btn.dataset.editId || btn.dataset.testId || btn.dataset.toggleId);
				const channel = channels.find((c) => c.id === id);
				if (!channel) return;
				if (btn.dataset.deleteId !== undefined) openDelete(channel);
				else if (btn.dataset.editId !== undefined) openEdit(channel);
				else if (btn.dataset.testId !== undefined) testChannel(channel);
				else if (btn.dataset.toggleId !== undefined) toggleEnabled(channel);
			}}>
				<DataTable
					{columns}
					rows={channels as unknown as Record<string, unknown>[]}
					searchPlaceholder={m["notifications.Search Channels"]()}
					searchableKeys={['name', 'type']}
					emptyTitle={m["common.No Results"]()}
				/>
			</div>
		</div>
	{/if}
</div>
{/if}

<!-- Create/Edit Channel Modal -->
<Modal bind:open={modalOpen} title={editingChannel ? m["notifications.Edit Channel"]() : m["notifications.Create Channel"]()} onClose={resetForm} maxWidth="36rem">
	<form onsubmit={handleSubmit} class="space-y-4">
		<!-- Name -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Channel Name"]()} *</label>
			<input
				bind:value={formName}
				required
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:outline-none focus:border-primary transition-colors"
			/>
		</div>

		<!-- Type -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Channel Type"]()}</label>
			<select
				bind:value={formType}
				disabled={!!editingChannel}
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none disabled:opacity-60 disabled:cursor-not-allowed"
			>
				<option value="webhook">{m["notifications.Webhook"]()}</option>
				<option value="email">{m["notifications.Email"]()}</option>
			</select>
		</div>

		<!-- Webhook config -->
		{#if formType === 'webhook'}
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.Webhook URL"]()} *</label>
				<input
					bind:value={formUrl}
					type="url"
					required
					placeholder="https://hooks.example.com/..."
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
			</div>
			<div>
				<div class="flex items-center justify-between mb-1">
					<label class="text-xs text-text-muted">{m["notifications.Headers"]()}</label>
					<button type="button" onclick={addHeaderRow}
						class="text-xs text-primary hover:underline">+ Add</button>
				</div>
				{#each formHeaders as hdr, i}
					<div class="flex gap-2 mb-2">
						<input
							bind:value={formHeaders[i].key}
							placeholder="Key"
							class="flex-1 px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
								focus:outline-none focus:border-primary transition-colors"
						/>
						<input
							bind:value={formHeaders[i].value}
							placeholder="Value"
							class="flex-1 px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
								focus:outline-none focus:border-primary transition-colors"
						/>
						{#if formHeaders.length > 1}
							<button type="button" onclick={() => removeHeaderRow(i)}
								class="px-2 py-1 text-error hover:bg-error/10 rounded transition-colors text-sm">&times;</button>
						{/if}
					</div>
				{/each}
			</div>
		{/if}

		<!-- Email config -->
		{#if formType === 'email'}
			<div class="grid grid-cols-2 gap-3">
				<div>
					<label class="block text-xs text-text-muted mb-1">{m["notifications.SMTP Host"]()} *</label>
					<input
						bind:value={formSmtpHost}
						required
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
							focus:outline-none focus:border-primary transition-colors"
					/>
				</div>
				<div>
					<label class="block text-xs text-text-muted mb-1">{m["notifications.SMTP Port"]()}</label>
					<input
						bind:value={formSmtpPort}
						type="number"
						min="1"
						max="65535"
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
							focus:outline-none focus:border-primary transition-colors"
					/>
				</div>
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.SMTP Username"]()}</label>
				<input
					bind:value={formSmtpUsername}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.SMTP Password"]()}</label>
				<input
					bind:value={formSmtpPassword}
					type="password"
					placeholder={editingChannel ? '*****' : ''}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
				{#if editingChannel}
					<p class="mt-1 text-xs text-text-muted">{m["notifications.Keep Password Hint"]()}</p>
				{/if}
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.From Address"]()} *</label>
				<input
					bind:value={formFromAddress}
					type="email"
					required
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.To Address"]()} *</label>
				<input
					bind:value={formToAddress}
					type="email"
					required
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors"
				/>
			</div>
		{/if}

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
				class="px-6 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover transition-colors disabled:opacity-50 text-sm inline-flex items-center gap-2"
			>
				{#if formLoading}<LoaderCircle class="w-4 h-4 animate-spin" aria-hidden="true" />{/if}
				<span>{m["common.Save"]()}</span>
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
	title={m["notifications.Delete Channel"]()}
	message={deleteTarget ? `${m["common.Are you sure?"]()} "${deleteTarget.name}"` : ''}
	confirmLabel={m["common.Delete"]()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>
