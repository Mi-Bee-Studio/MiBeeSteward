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
	import { html } from '$lib/utils/index';
	import { channelTypeBadge } from '$lib/utils/badges';
	import { notificationChannelSchema, notificationRuleSchema, validateField, validateForm } from '$lib/utils/validation';
	import { addToast } from '$lib/stores/toast';
	import type { NotificationRule, NotificationRuleRequest } from '$lib/types';

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
	let fieldErrors = $state<Record<string, string>>({});

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
				// Only include headers where both key and value are non-empty;
				// an empty-value header is a half-typed row the user didn't
				// finish and shouldn't be sent to the webhook target.
				if (h.key.trim() && h.value.trim()) {
					headers[h.key.trim()] = h.value.trim();
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

		// Validate the channel via notificationChannelSchema. The schema is flat
		// (form state is flat); type-conditional required fields (webhook url /
		// email host+from+to) are enforced by the refine on full-form validation.
		const validation = validateForm(notificationChannelSchema, {
			name: formName,
			type: formType,
			webhook_url: formUrl,
			smtp_host: formSmtpHost,
			smtp_port: formSmtpPort,
			smtp_from: formFromAddress,
			smtp_to: formToAddress
		});
		if (!validation.valid) {
			fieldErrors = validation.errors;
			return;
		}
		fieldErrors = {};
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
		// Dedicated PATCH endpoint — writes only `enabled` (single-field UPDATE),
		// so name/type/config (and any SMTP password) are never rewritten. The
		// generic PUT is reserved for the edit form, which intentionally replaces
		// the full body.
		const target = !channel.enabled;
		try {
			await api.patch(`/notification/channels/${channel.id}`, { enabled: target });
			addToast('success', target ? m["notifications.Channel Enabled"]() : m["notifications.Channel Disabled"]());
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

	// --- Rules tab (#139) ---
	// In-page tab toggle (no route split — keeps the page self-contained). The
	// channels view above stays the default; rules is a sibling view.
	let tab = $state<'channels' | 'rules'>('channels');

	let rules = $state<NotificationRule[]>([]);
	let rulesLoading = $state(false);
	// Networks + devices lists for the scope dropdowns (loaded on first rules open).
	let networks = $state<{ id: number; name: string; cidr: string }[]>([]);
	let devices = $state<{ id: number; name: string; ip_address: string; device_uuid: string }[]>([]);

	// Rule modal state
	let ruleModalOpen = $state(false);
	let editingRule = $state<NotificationRule | null>(null);
	let ruleDeleteDialogOpen = $state(false);
	let ruleDeleteTarget = $state<NotificationRule | null>(null);
	let ruleFormLoading = $state(false);
	let ruleFieldErrors = $state<Record<string, string>>({});

	// Rule form fields
	let ruleName = $state('');
	let ruleEventType = $state('device_lost');
	let ruleScopeType = $state<'all' | 'network' | 'device'>('all');
	let ruleScopeNetworkId = $state<number | null>(null);
	let ruleScopeDeviceUuid = $state('');
	let ruleChannelId = $state<number | null>(null);
	let ruleCooldown = $state(30);

	async function fetchRules() {
		rulesLoading = true;
		try {
			const res = await api.get<{ rules: NotificationRule[]; total: number }>('/notification/rules');
			rules = res.rules || [];
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			rulesLoading = false;
		}
	}

	// Lazy-load the networks/devices/channels reference data the rule form needs.
	// Done once on first switch to the rules tab (not on page load — channels-only
	// users never pay this cost).
	let refLoaded = $state(false);
	async function ensureRefData() {
		if (refLoaded) return;
		refLoaded = true;
		try {
			const [nets, devs] = await Promise.all([
				api.get<{ networks: { id: number; name: string; cidr: string }[] }>('/networks'),
				api.get<{ devices: { id: number; name: string; ip_address: string; device_uuid: string }[] }>('/devices?limit=500')
			]);
			networks = nets.networks || [];
			devices = devs.devices || [];
		} catch {
			// Non-fatal: the dropdowns will just be empty.
		}
	}

	function switchTab(next: 'channels' | 'rules') {
		tab = next;
		if (next === 'rules') {
			fetchRules();
			ensureRefData();
		}
	}

	function resetRuleForm() {
		ruleName = '';
		ruleEventType = 'device_lost';
		ruleScopeType = 'all';
		ruleScopeNetworkId = null;
		ruleScopeDeviceUuid = '';
		ruleChannelId = null;
		ruleCooldown = 30;
		editingRule = null;
		ruleFieldErrors = {};
	}

	function openCreateRule() {
		resetRuleForm();
		ruleModalOpen = true;
	}

	function openEditRule(rule: NotificationRule) {
		editingRule = rule;
		ruleName = rule.name;
		ruleEventType = rule.event_type;
		ruleScopeType = rule.scope_type as 'all' | 'network' | 'device';
		ruleScopeNetworkId = rule.scope_network_id ?? null;
		ruleScopeDeviceUuid = rule.scope_device_uuid ?? '';
		ruleChannelId = rule.channel_id;
		ruleCooldown = rule.cooldown_minutes;
		ruleFieldErrors = {};
		ruleModalOpen = true;
	}

	function eventLabel(t: string): string {
		switch (t) {
			case 'device_lost': return m["notifications.Event Device Lost"]();
			case 'device_recovered': return m["notifications.Event Device Recovered"]();
			case 'device_added': return m["notifications.Event Device Added"]();
			case 'device_changed': return m["notifications.Event Device Changed"]();
		}
		return t;
	}

	function scopeLabel(rule: NotificationRule): string {
		switch (rule.scope_type) {
			case 'all': return m["notifications.Scope All"]();
			case 'network': {
				const n = networks.find((x) => x.id === rule.scope_network_id);
				return n ? `${m["notifications.Scope Network"]()}: ${n.name}` : m["notifications.Scope Network"]();
			}
			case 'device': {
				const d = devices.find((x) => x.device_uuid === rule.scope_device_uuid);
				return d ? `${m["notifications.Scope Device"]()}: ${d.name || d.ip_address}` : m["notifications.Scope Device"]();
			}
		}
		return rule.scope_type;
	}

	function channelName(id: number): string {
		const c = channels.find((x) => x.id === id);
		return c ? c.name : `#${id}`;
	}

	async function handleRuleSubmit(e: Event) {
		e.preventDefault();
		const validation = validateForm(notificationRuleSchema, {
			name: ruleName,
			event_type: ruleEventType,
			scope_type: ruleScopeType,
			scope_network_id: ruleScopeNetworkId,
			scope_device_uuid: ruleScopeDeviceUuid,
			channel_id: ruleChannelId ?? 0,
			cooldown_minutes: ruleCooldown
		});
		if (!validation.valid) {
			ruleFieldErrors = validation.errors;
			return;
		}
		ruleFieldErrors = {};
		ruleFormLoading = true;
		const body: NotificationRuleRequest = {
			name: ruleName,
			event_type: ruleEventType,
			scope_type: ruleScopeType,
			scope_network_id: ruleScopeType === 'network' ? ruleScopeNetworkId : null,
			scope_device_uuid: ruleScopeType === 'device' ? ruleScopeDeviceUuid : '',
			channel_id: ruleChannelId!,
			cooldown_minutes: ruleCooldown
		};
		try {
			if (editingRule) {
				await api.put(`/notification/rules/${editingRule.id}`, body);
				addToast('success', m["notifications.Rule Updated"]());
			} else {
				await api.post('/notification/rules', body);
				addToast('success', m["notifications.Rule Created"]());
			}
			ruleModalOpen = false;
			resetRuleForm();
			fetchRules();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			ruleFormLoading = false;
		}
	}

	async function toggleRuleEnabled(rule: NotificationRule) {
		try {
			await api.patch(`/notification/rules/${rule.id}`, { enabled: !rule.enabled });
			addToast('success', rule.enabled ? m["notifications.Rule Disabled"]() : m["notifications.Rule Enabled"]());
			fetchRules();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function openDeleteRule(rule: NotificationRule) {
		ruleDeleteTarget = rule;
		ruleDeleteDialogOpen = true;
	}

	async function confirmDeleteRule() {
		if (!ruleDeleteTarget) return;
		try {
			await api.delete(`/notification/rules/${ruleDeleteTarget.id}`);
			ruleDeleteTarget = null;
			addToast('success', m["notifications.Rule Deleted"]());
			fetchRules();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	const ruleColumns = $derived([
		{
			key: 'name',
			label: m["notifications.Rule Name"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				html`<span class="font-medium text-text">${row.name}</span>`
		},
		{
			key: 'event_type',
			label: m["notifications.Event Type"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				html`<span class="text-xs px-2 py-0.5 rounded bg-accent-purple/15 text-accent-purple font-mono">${eventLabel(String(row.event_type))}</span>`
		},
		{
			key: 'scope',
			label: m["notifications.Scope"](),
			render: (row: Record<string, unknown>) => {
				const r = rules.find((x) => x.id === row.id);
				return html`<span class="text-xs text-text-muted">${r ? scopeLabel(r) : row.scope_type}</span>`;
			}
		},
		{
			key: 'channel_id',
			label: m["notifications.Channel"](),
			render: (row: Record<string, unknown>) =>
				html`<span class="text-sm text-text">${channelName(Number(row.channel_id))}</span>`
		},
		{
			key: 'cooldown_minutes',
			label: m["notifications.Cooldown Minutes"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				html`<span class="text-text-muted">${row.cooldown_minutes}m</span>`
		},
		{
			key: 'enabled',
			label: m["notifications.Enabled"](),
			sortable: true,
			interactive: true
		},
		{
			key: 'actions',
			label: m["common.Actions"](),
			interactive: true
		}
	]);

	const columns = $derived([
		{
			key: 'name',
			label: m["notifications.Channel Name"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				html`<span class="font-medium text-text">${row.name}</span>`
		},
		{
			key: 'type',
			label: m["notifications.Channel Type"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = String(row.type);
				const b = channelTypeBadge(t);
				return html`<span class="text-xs px-2 py-0.5 rounded font-mono ${b.cls}">${b.label}</span>`;
			}
		},
		{
			key: 'enabled',
			label: m["notifications.Enabled"](),
			sortable: true,
			interactive: true
		},
		{
			key: 'created_at',
			label: m["users.Created At"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				html`<span class="text-text-muted">${formatTime(String(row.created_at))}</span>`
		},
		{
			key: 'actions',
			label: m["common.Actions"](),
			interactive: true
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
	<div class="flex items-center justify-between mb-4">
		<div class="flex items-center gap-3">
			<a href="/settings" class="text-text-muted hover:text-text transition-colors">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
				</svg>
			</a>
			<h2 class="text-2xl font-bold text-primary">{m["notifications.Notification Settings"]()}</h2>
		</div>
		{#if tab === 'channels'}
			<button
				onclick={openCreate}
				class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover transition-colors text-sm"
			>
				+ {m["notifications.Create Channel"]()}
			</button>
		{:else}
			<button
				onclick={openCreateRule}
				class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover transition-colors text-sm"
				disabled={channels.length === 0}
				title={channels.length === 0 ? m["notifications.No Channels For Rules"]() : ''}
			>
				+ {m["notifications.Create Rule"]()}
			</button>
		{/if}
	</div>

	<!-- Tab switcher: Channels | Rules -->
	<div class="flex border-b border-border mb-6">
		<button
			onclick={() => switchTab('channels')}
			class="px-4 py-2 text-sm font-medium transition-colors border-b-2 {tab === 'channels'
				? 'border-primary text-primary'
				: 'border-transparent text-text-muted hover:text-text'}"
		>{m["notifications.Channels"]()}</button>
		<button
			onclick={() => switchTab('rules')}
			class="px-4 py-2 text-sm font-medium transition-colors border-b-2 {tab === 'rules'
				? 'border-primary text-primary'
				: 'border-transparent text-text-muted hover:text-text'}"
		>{m["notifications.Rules"]()}</button>
	</div>

	{#if tab === 'channels'}
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
					<DataTable
						{columns}
						rows={channels as unknown as Record<string, unknown>[]}
						searchPlaceholder={m["notifications.Search Channels"]()}
						searchableKeys={['name', 'type']}
						emptyTitle={m["common.No Results"]()}
					>
						{#snippet cell(row, col)}
							{@const channel = channels.find((c) => c.id === row.id)}
							{#if channel}
								{#if col.key === 'enabled'}
									<button
										onclick={() => toggleEnabled(channel)}
										class="text-xs px-2 py-0.5 rounded cursor-pointer transition-colors {channel.enabled
											? 'bg-success/15 text-success hover:bg-success/25'
											: 'bg-border/30 text-text-muted hover:bg-border/50'
										}"
									>{channel.enabled ? m["notifications.Enabled"]() : m["notifications.Disabled"]()}</button>
								{:else if col.key === 'actions'}
									<div class="flex items-center gap-2">
										<button
											onclick={() => testChannel(channel)}
											class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
										>{m["notifications.Test Channel"]()}</button>
										<button
											onclick={() => openEdit(channel)}
											class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10 transition-colors"
										>{m["common.Edit"]()}</button>
										<button
											onclick={() => openDelete(channel)}
											class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors"
										>{m["common.Delete"]()}</button>
									</div>
								{/if}
							{/if}
						{/snippet}
					</DataTable>
			</div>
		{/if}
	{:else}
		<!-- Rules tab -->
		{#if channels.length === 0}
			<EmptyState
				icon="🔔"
				title={m["notifications.No Channels For Rules"]()}
				description={m["notifications.No Channels For Rules Desc"]()}
			/>
		{:else if rulesLoading}
			<PageSkeleton type="table" />
		{:else if rules.length === 0}
			<EmptyState
				icon="📨"
				title={m["notifications.No Rules"]()}
				description={m["notifications.No Rules Desc"]()}
				actionLabel={m["notifications.Create Rule"]()}
				onAction={openCreateRule}
			/>
		{:else}
			<div class="bg-surface border border-border rounded-lg p-4">
					<DataTable
						columns={ruleColumns}
						rows={rules as unknown as Record<string, unknown>[]}
						searchPlaceholder={m["common.Search"]() + '…'}
						searchableKeys={['name', 'event_type']}
						emptyTitle={m["common.No Results"]()}
					>
						{#snippet cell(row, col)}
							{@const rule = rules.find((r) => r.id === row.id)}
							{#if rule}
								{#if col.key === 'enabled'}
									<button
										onclick={() => toggleRuleEnabled(rule)}
										class="text-xs px-2 py-0.5 rounded cursor-pointer transition-colors {rule.enabled
											? 'bg-success/15 text-success hover:bg-success/25'
											: 'bg-border/30 text-text-muted hover:bg-border/50'
										}"
									>{rule.enabled ? m["notifications.Enabled"]() : m["notifications.Disabled"]()}</button>
								{:else if col.key === 'actions'}
									<div class="flex items-center gap-2">
										<button
											onclick={() => openEditRule(rule)}
											class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10 transition-colors"
										>{m["common.Edit"]()}</button>
										<button
											onclick={() => openDeleteRule(rule)}
											class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors"
										>{m["common.Delete"]()}</button>
									</div>
								{/if}
							{/if}
						{/snippet}
					</DataTable>
			</div>
		{/if}
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
					placeholder={m["notifications.Webhook URL Placeholder"]()}
					onblur={() => {
						const r = validateField(notificationChannelSchema, 'webhook_url', formUrl);
						fieldErrors = r.valid
							? (() => { const { webhook_url: _, ...rest } = fieldErrors; return rest; })()
							: { ...fieldErrors, webhook_url: r.error ?? '' };
					}}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:outline-none focus:border-primary transition-colors {fieldErrors.webhook_url ? '!border-error' : ''}"
				/>
				{#if fieldErrors.webhook_url}
					<p class="mt-1 text-xs text-error">{fieldErrors.webhook_url}</p>
				{/if}
			</div>
			<div>
				<div class="flex items-center justify-between mb-1">
					<label class="text-xs text-text-muted">{m["notifications.Headers"]()}</label>
					<button type="button" onclick={addHeaderRow}
						class="text-xs text-primary hover:underline">{m['notifications.Add Header']()}</button>
				</div>
				{#each formHeaders as hdr, i}
					<div class="flex gap-2 mb-2">
						<input
							bind:value={formHeaders[i].key}
							placeholder={m["notifications.Header Key Placeholder"]()}
							class="flex-1 px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
								focus:outline-none focus:border-primary transition-colors"
						/>
						<input
							bind:value={formHeaders[i].value}
							placeholder={m["notifications.Header Value Placeholder"]()}
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
						onblur={() => {
							const r = validateField(notificationChannelSchema, 'smtp_host', formSmtpHost);
							fieldErrors = r.valid
								? (() => { const { smtp_host: _, ...rest } = fieldErrors; return rest; })()
								: { ...fieldErrors, smtp_host: r.error ?? '' };
						}}
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
							focus:outline-none focus:border-primary transition-colors {fieldErrors.smtp_host ? '!border-error' : ''}"
					/>
					{#if fieldErrors.smtp_host}
						<p class="mt-1 text-xs text-error">{fieldErrors.smtp_host}</p>
					{/if}
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
						onblur={() => {
							const r = validateField(notificationChannelSchema, 'smtp_from', formFromAddress);
							fieldErrors = r.valid
								? (() => { const { smtp_from: _, ...rest } = fieldErrors; return rest; })()
								: { ...fieldErrors, smtp_from: r.error ?? '' };
						}}
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
							focus:outline-none focus:border-primary transition-colors {fieldErrors.smtp_from ? '!border-error' : ''}"
					/>
					{#if fieldErrors.smtp_from}
						<p class="mt-1 text-xs text-error">{fieldErrors.smtp_from}</p>
					{/if}
				</div>
				<div>
					<label class="block text-xs text-text-muted mb-1">{m["notifications.To Address"]()} *</label>
					<input
						bind:value={formToAddress}
						type="email"
						required
						onblur={() => {
							const r = validateField(notificationChannelSchema, 'smtp_to', formToAddress);
							fieldErrors = r.valid
								? (() => { const { smtp_to: _, ...rest } = fieldErrors; return rest; })()
								: { ...fieldErrors, smtp_to: r.error ?? '' };
						}}
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
							focus:outline-none focus:border-primary transition-colors {fieldErrors.smtp_to ? '!border-error' : ''}"
					/>
					{#if fieldErrors.smtp_to}
						<p class="mt-1 text-xs text-error">{fieldErrors.smtp_to}</p>
					{/if}
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

<!-- Rule create/edit modal (#139) -->
<Modal bind:open={ruleModalOpen} title={editingRule ? m["notifications.Edit Rule"]() : m["notifications.Create Rule"]()} onClose={resetRuleForm} maxWidth="36rem">
	<form onsubmit={handleRuleSubmit} class="space-y-4">
		<!-- Name -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Rule Name"]()} *</label>
			<input bind:value={ruleName} required class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:outline-none focus:border-primary transition-colors" />
		</div>

		<!-- Event type -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Event Type"]()}</label>
			<select bind:value={ruleEventType} class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none">
				<option value="device_lost">{m["notifications.Event Device Lost"]()}</option>
				<option value="device_recovered">{m["notifications.Event Device Recovered"]()}</option>
				<option value="device_added">{m["notifications.Event Device Added"]()}</option>
				<option value="device_changed">{m["notifications.Event Device Changed"]()}</option>
			</select>
		</div>

		<!-- Scope -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Scope"]()}</label>
			<select bind:value={ruleScopeType} class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none">
				<option value="all">{m["notifications.Scope All"]()}</option>
				<option value="network">{m["notifications.Scope Network"]()}</option>
				<option value="device">{m["notifications.Scope Device"]()}</option>
			</select>
		</div>
		{#if ruleScopeType === 'network'}
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.Select Network"]()}</label>
				<select bind:value={ruleScopeNetworkId} class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none {ruleFieldErrors.scope_network_id ? '!border-error' : ''}">
					<option value={null}>{m["notifications.Select Network"]()}</option>
					{#each networks as n}
						<option value={n.id}>{n.name} ({n.cidr})</option>
					{/each}
				</select>
				{#if ruleFieldErrors.scope_network_id}<p class="mt-1 text-xs text-error">{ruleFieldErrors.scope_network_id}</p>{/if}
			</div>
		{/if}
		{#if ruleScopeType === 'device'}
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["notifications.Select Device"]()}</label>
				<select bind:value={ruleScopeDeviceUuid} class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none {ruleFieldErrors.scope_device_uuid ? '!border-error' : ''}">
					<option value="">{m["notifications.Select Device"]()}</option>
					{#each devices as d}
						<option value={d.device_uuid}>{d.name || d.ip_address} ({d.ip_address})</option>
					{/each}
				</select>
				{#if ruleFieldErrors.scope_device_uuid}<p class="mt-1 text-xs text-error">{ruleFieldErrors.scope_device_uuid}</p>{/if}
			</div>
		{/if}

		<!-- Channel -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Channel"]()} *</label>
			<select bind:value={ruleChannelId} class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none {ruleFieldErrors.channel_id ? '!border-error' : ''}">
				<option value={null}>{m["notifications.Select Channel"]()}</option>
				{#each channels as c}
					<option value={c.id}>{c.name} ({c.type})</option>
				{/each}
			</select>
			{#if ruleFieldErrors.channel_id}<p class="mt-1 text-xs text-error">{ruleFieldErrors.channel_id}</p>{/if}
		</div>

		<!-- Cooldown -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["notifications.Cooldown Minutes"]()} *</label>
			<input bind:value={ruleCooldown} type="number" min="1" max="10080" required class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:outline-none focus:border-primary transition-colors" />
			<p class="mt-1 text-xs text-text-muted">{m["notifications.Cooldown Hint"]()}</p>
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<button type="submit" disabled={ruleFormLoading} class="px-6 py-2 bg-primary text-text-inverse font-semibold rounded-lg hover:bg-primary-hover transition-colors disabled:opacity-50 text-sm inline-flex items-center gap-2">
				{#if ruleFormLoading}<LoaderCircle class="w-4 h-4 animate-spin" aria-hidden="true" />{/if}
				<span>{m["common.Save"]()}</span>
			</button>
			<button type="button" onclick={() => { ruleModalOpen = false; resetRuleForm(); }} class="px-6 py-2 border border-border text-text-muted rounded-lg hover:border-primary transition-colors text-sm">
				{m["common.Cancel"]()}
			</button>
		</div>
	</form>
</Modal>

<!-- Rule delete confirmation -->
<ConfirmDialog
	bind:open={ruleDeleteDialogOpen}
	title={m["notifications.Delete Rule"]()}
	message={ruleDeleteTarget ? `${m["common.Are you sure?"]()} "${ruleDeleteTarget.name}"` : ''}
	confirmLabel={m["common.Delete"]()}
	confirmVariant="danger"
	onConfirm={confirmDeleteRule}
	onCancel={() => { ruleDeleteTarget = null; }}
/>
