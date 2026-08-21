<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later; see LICENSE for the full text. A commercial
  license is available for use cases the AGPL does not accommodate; see
  LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { html, formatDateTime as formatTime } from '$lib/utils/index';
	import { probeTargetSchema, validateField, validateForm } from '$lib/utils/validation';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import CertificateModal from '$lib/components/CertificateModal.svelte';
	import { Activity as ActivityIcon } from '@lucide/svelte';

	import type {
		ProbeTarget,
		ProbeTargetListResponse,
		ProbeResult,
		ProbeResultListResponse,
		ProbeTriggerResponse,
		TLSPortCerts,
		DeviceCertificatesResponse
	} from '$lib/types';
	import { certDayDelta } from '$lib/utils/certs';

	// --- State ---
	let targets = $state<ProbeTarget[]>([]);
	let loading = $state(true);
	let error = $state('');
	// Leaf-cert expiry per target id (for the table's certificate badge). Fetched
	// from /certificates after each list refresh — only tls/http targets have any.
	let certExpiry = $state<Record<number, string>>({});

	// --- Batch operations (#276): multi-select + toolbar actions -------------
	let selectedIds = $state<Set<number>>(new Set());
	let batchBusy = $state(false);

	function toggleSelected(id: number) {
		const next = new Set(selectedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		selectedIds = next;
	}

	function toggleSelectAll() {
		selectedIds = selectedIds.size === targets.length ? new Set() : new Set(targets.map((t) => t.id));
	}

	async function runBatch(op: (t: ProbeTarget) => Promise<unknown>, label: string) {
		const list = targets.filter((t) => selectedIds.has(t.id));
		if (list.length === 0) return;
		batchBusy = true;
		let ok = 0;
		await Promise.all(
			list.map(async (t) => {
				try {
					await op(t);
					ok++;
				} catch (err) {
					addToast('error', `${t.name}: ${getErrorMessage(err)}`);
				}
			})
		);
		batchBusy = false;
		selectedIds = new Set();
		addToast(ok === list.length ? 'success' : 'warning', `${label}: ${ok}/${list.length}`);
		fetchTargets();
	}

	const batchEnable = () => runBatch((t) => api.put(`/probe-targets/${t.id}`, { enabled: true }), m['probes.Batch Enable']());
	const batchDisable = () => runBatch((t) => api.put(`/probe-targets/${t.id}`, { enabled: false }), m['probes.Batch Disable']());

	function batchInterval() {
		const v = prompt(m['probes.Batch Interval Prompt'](), '60');
		const n = Number(v);
		if (!v || !Number.isFinite(n) || n < 10 || n > 86400) {
			if (v !== null) addToast('error', m['probes.Batch Interval Invalid']());
			return;
		}
		runBatch((t) => api.put(`/probe-targets/${t.id}`, { interval_seconds: n }), `${m['probes.Batch Interval']()}=${n}s`);
	}

	function batchDelete() {
		if (!confirm(m['probes.Batch Delete Confirm']({ count: selectedIds.size }))) return;
		runBatch((t) => api.delete(`/probe-targets/${t.id}`), m['common.Delete']());
	}

	// --- Module overview cards (#276): per-module success rate + avg latency --
	interface ModuleStat {
		module: string;
		total: number;
		enabled: number;
		successRate: number | null;
		avgLatency: number | null;
	}
	const moduleStats = $derived.by<ModuleStat[]>(() => {
		const mods = ['http', 'tls', 'tcp', 'icmp'];
		return mods.map((mod) => {
			const rows = targets.filter((t) => t.module === mod);
			const ran = rows.filter((t) => t.last_status);
			const ok = ran.filter((t) => t.last_status === 'success');
			const lat = ok.map((t) => t.last_latency_ms).filter((v) => v > 0);
			return {
				module: mod,
				total: rows.length,
				enabled: rows.filter((t) => t.enabled).length,
				successRate: ran.length ? Math.round((ok.length / ran.length) * 100) : null,
				avgLatency: lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : null
			};
		});
	});

	// --- Cert expiry timeline (#276): TLS/http targets on a 0..90d+ scale -----
	interface TimelineEntry {
		t: ProbeTarget;
		days: number;
		notAfter: string;
	}
	const certTimeline = $derived.by<TimelineEntry[]>(() => {
		const entries: TimelineEntry[] = [];
		for (const t of targets) {
			if (t.module !== 'tls' && t.module !== 'http') continue;
			const notAfter = certExpiry[t.id];
			if (!notAfter) continue;
			entries.push({ t, days: certDayDelta(notAfter), notAfter });
		}
		return entries.sort((a, b) => a.days - b.days);
	});
	// Expiry warning threshold (days) — persisted per browser (#276 goal: configurable).
	let expiryWarnDays = $state<number>(
		Number(localStorage.getItem('probes.expiryWarnDays')) || 30
	);
	function setExpiryWarn(n: number) {
		expiryWarnDays = n;
		localStorage.setItem('probes.expiryWarnDays', String(n));
	}
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	// --- Create/Edit modal ---
	let editModalOpen = $state(false);
	let editingId = $state<number | null>(null); // null = create
	let formName = $state('');
	let formModule = $state<'http' | 'tls' | 'tcp' | 'icmp'>('http');
	let formTarget = $state('');
	let formInterval = $state(60);
	let formTimeout = $state(10);
	let formNotes = $state('');
	let formEnabled = $state(true);
	let formLoading = $state(false);
	let fieldErrors = $state<Record<string, string>>({});

	// --- Trigger (per-row, in-flight marker disables just that row's button) ---
	let triggeringId = $state<number | null>(null);

	// --- Delete confirm ---
	let deleteDialogOpen = $state(false);
	let deleteTarget: ProbeTarget | null = null;

	// --- Results history modal ---
	let resultsModalOpen = $state(false);
	let resultsTarget = $state<ProbeTarget | null>(null);
	let results = $state<ProbeResult[]>([]);
	let resultsTotal = $state(0);
	let resultsLoading = $state(false);

	// --- Certificate modal (reuses the shared component — same DTO shape) ---
	let certModalOpen = $state(false);
	let certPortCerts = $state<TLSPortCerts | null>(null);

	onMount(() => {
		fetchTargets();
		pollTimer = setInterval(fetchTargets, 10000);
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	async function fetchTargets() {
		try {
			const res = await api.get<ProbeTargetListResponse>('/probe-targets/?limit=100');
			targets = res.targets || [];
			error = '';
			fetchCertSummaries();
		} catch (err: unknown) {
			// Only surface the error banner on the first load; later poll
			// failures would flash the banner every 10s.
			if (loading) error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	// Per-target certificate leaf expiry for the table badge. N small requests
	// (one per tls/http target) — the list endpoint doesn't carry cert state and
	// the target count is user-configured-small by nature.
	async function fetchCertSummaries() {
		const tlsLike = targets.filter((t) => t.module === 'tls' || t.module === 'http');
		const entries = await Promise.all(
			tlsLike.map(async (t) => {
				try {
					const res = await api.get<DeviceCertificatesResponse>(`/probe-targets/${t.id}/certificates`);
					const leaf = res.certificates?.[0]?.leaf;
					return [t.id, leaf ? leaf.not_after : ''] as const;
				} catch {
					return [t.id, ''] as const;
				}
			})
		);
		const map: Record<number, string> = {};
		for (const [id, notAfter] of entries) {
			if (notAfter) map[id] = notAfter;
		}
		certExpiry = map;
	}

	// --- Create / Edit ---
	function openCreate() {
		editingId = null;
		formName = '';
		formModule = 'http';
		formTarget = '';
		formInterval = 60;
		formTimeout = 10;
		formNotes = '';
		formEnabled = true;
		fieldErrors = {};
		editModalOpen = true;
	}

	function openEdit(t: ProbeTarget) {
		editingId = t.id;
		formName = t.name;
		formModule = t.module;
		formTarget = t.target;
		formInterval = t.interval_seconds;
		formTimeout = t.timeout_seconds;
		formNotes = t.notes || '';
		formEnabled = t.enabled;
		fieldErrors = {};
		editModalOpen = true;
	}

	const moduleHelpKeys: Record<string, string> = {
		http: 'probes.Module http Help',
		tls: 'probes.Module tls Help',
		tcp: 'probes.Module tcp Help',
		icmp: 'probes.Module icmp Help'
	};

	function moduleHelp(mod: string): string {
		switch (mod) {
			case 'tls':
				return m['probes.Module tls Help']();
			case 'tcp':
				return m['probes.Module tcp Help']();
			case 'icmp':
				return m['probes.Module icmp Help']();
			default:
				return m['probes.Module http Help']();
		}
	}

	function targetPlaceholder(mod: string): string {
		switch (mod) {
			case 'http':
				return 'https://example.com/healthz';
			case 'tls':
				return 'example.com:443';
			case 'tcp':
				return 'example.com:80';
			default:
				return 'example.com';
		}
	}

	function validate(field: string, value: unknown) {
		const res = validateField(probeTargetSchema, field as never, value);
		if (!res.valid) fieldErrors[field] = res.error || '';
		else delete fieldErrors[field];
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		const validation = validateForm(probeTargetSchema, {
			name: formName,
			module: formModule,
			target: formTarget.trim(),
			interval_seconds: formInterval,
			timeout_seconds: formTimeout,
			notes: formNotes
		});
		if (!validation.valid) {
			fieldErrors = validation.errors;
			return;
		}
		fieldErrors = {};
		formLoading = true;
		try {
			const body = {
				name: formName.trim(),
				module: formModule,
				target: formTarget.trim(),
				interval_seconds: formInterval,
				timeout_seconds: formTimeout,
				notes: formNotes,
				enabled: formEnabled
			};
			if (editingId === null) {
				await api.post('/probe-targets/', body);
				addToast('success', m['probes.Target Created']());
			} else {
				await api.put(`/probe-targets/${editingId}`, body);
				addToast('success', m['probes.Target Updated']());
			}
			editModalOpen = false;
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			formLoading = false;
		}
	}

	// --- Enabled toggle (partial update) ---
	async function toggleEnabled(t: ProbeTarget) {
		try {
			await api.put(`/probe-targets/${t.id}`, { enabled: !t.enabled });
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Trigger now (synchronous — response carries the just-recorded result) ---
	async function triggerNow(t: ProbeTarget) {
		triggeringId = t.id;
		try {
			const res = await api.post<ProbeTriggerResponse>(`/probe-targets/${t.id}/trigger`, {});
			const status = res.status === 'success' ? '✓' : '✗';
			addToast(res.status === 'success' ? 'success' : 'error', `${status} ${m['probes.Trigger Done']({ status: res.status })}`);
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			triggeringId = null;
		}
	}

	// --- Delete ---
	function openDelete(t: ProbeTarget) {
		deleteTarget = t;
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/probe-targets/${deleteTarget.id}`);
			addToast('success', m['probes.Target Deleted']());
			deleteTarget = null;
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Results history ---
	async function openResults(t: ProbeTarget) {
		resultsTarget = t;
		results = [];
		resultsTotal = 0;
		resultsModalOpen = true;
		resultsLoading = true;
		try {
			const res = await api.get<ProbeResultListResponse>(`/probe-targets/${t.id}/results?limit=50`);
			results = res.results || [];
			resultsTotal = res.total || 0;
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			resultsLoading = false;
		}
	}

	// --- Certificate chain (shared CertificateModal; response DTO is the same
	// tlsPortCerts shape as the device endpoint) ---
	async function openCerts(t: ProbeTarget) {
		try {
			const res = await api.get<DeviceCertificatesResponse>(`/probe-targets/${t.id}/certificates`);
			certPortCerts = res.certificates?.[0] ?? null;
			certModalOpen = true;
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Table columns (render path uses the auto-escaping html helper) ---
	const statusBadge = (s: string) => {
		if (!s) return html`<span class="text-text-muted text-xs">${m['probes.Never Run']()}</span>`;
		const cls = s === 'success' ? 'badge-success' : s === 'timeout' ? 'badge-warning' : 'badge-error';
		return html`<span class="badge ${cls}">${s}</span>`;
	};

	const columns = $derived([
		{ key: 'select', label: m['probes.Batch Select'](), interactive: true },
		{ key: 'name', label: m['probes.Name'](), sortable: true, render: (row: Record<string, unknown>) => html`<span class="font-medium">${row.name}</span>` },
		{ key: 'module', label: m['probes.Module'](), render: (row: Record<string, unknown>) => html`<span class="badge badge-info uppercase">${row.module}</span>` },
		{ key: 'target', label: m['probes.Target'](), render: (row: Record<string, unknown>) => html`<span class="font-mono text-xs">${row.target}</span>` },
		{ key: 'interval_seconds', label: m['probes.Interval'](), render: (row: Record<string, unknown>) => html`<span class="text-xs">${row.interval_seconds}s</span>` },
		{ key: 'last_status', label: m['probes.Last Status'](), sortable: true, render: (row: Record<string, unknown>) => statusBadge(String(row.last_status || '')) },
		{
			key: 'last_latency_ms',
			label: m['probes.Latency'](),
			render: (row: Record<string, unknown>) => {
				const v = row.last_latency_ms as number;
				if (!row.last_status || !v) return html`<span class="text-text-muted text-xs">-</span>`;
				return html`<span class="text-xs font-mono">${v < 1000 ? `${Math.round(v)}ms` : `${(v / 1000).toFixed(2)}s`}</span>`;
			}
		},
		{
			key: 'cert',
			label: m['probes.Cert Expiry'](),
			render: (row: Record<string, unknown>) => {
				const id = row.id as number;
				const mod = row.module as string;
				if (mod !== 'tls' && mod !== 'http') return html`<span class="text-text-muted text-xs">-</span>`;
				const notAfter = certExpiry[id];
				if (!notAfter) return html`<span class="text-text-muted text-xs">-</span>`;
				const days = certDayDelta(notAfter);
				const cls = days < 0 ? 'badge-error' : days < 15 ? 'badge-warning' : 'badge-success';
				return html`<span class="badge ${cls}" title="${notAfter}">${m['probes.Cert Days']({ days })}</span>`;
			}
		},
		{ key: 'enabled', label: m['probes.Enabled'](), interactive: true },
		{ key: 'actions', label: m['probes.Actions'](), interactive: true }
	]);

	const resultColumns = $derived([
		{ key: 'checked_at', label: m['probes.Checked At'](), render: (row: Record<string, unknown>) => html`<span class="text-xs text-text-muted">${formatTime(String(row.checked_at))}</span>` },
		{ key: 'status', label: m['probes.Status'](), render: (row: Record<string, unknown>) => statusBadge(String(row.status)) },
		{
			key: 'latency_ms',
			label: m['probes.Latency'](),
			render: (row: Record<string, unknown>) => {
				const v = row.latency_ms as number;
				return html`<span class="text-xs font-mono">${v < 1000 ? `${Math.round(v)}ms` : `${(v / 1000).toFixed(2)}s`}</span>`;
			}
		},
		{
			key: 'status_code',
			label: m['probes.Status Code'](),
			render: (row: Record<string, unknown>) => {
				const v = row.status_code as number;
				return v ? html`<span class="text-xs font-mono">${v}</span>` : html`<span class="text-text-muted text-xs">-</span>`;
			}
		},
		{ key: 'tls_version', label: m['probes.TLS Version'](), render: (row: Record<string, unknown>) => html`<span class="text-xs">${row.tls_version || '-'}</span>` },
		{
			key: 'cert_not_after',
			label: m['probes.Cert Not After'](),
			render: (row: Record<string, unknown>) => {
				const v = row.cert_not_after as string | undefined;
				return v ? html`<span class="text-xs">${v.slice(0, 10)}</span>` : html`<span class="text-text-muted text-xs">-</span>`;
			}
		},
		{
			key: 'error_message',
			label: m['probes.Error'](),
			render: (row: Record<string, unknown>) => {
				const v = row.error_message as string | undefined;
				return v ? html`<span class="text-xs text-error" title="${v}">${v.length > 40 ? v.slice(0, 40) + '…' : v}</span>` : html`<span class="text-text-muted text-xs">-</span>`;
			}
		}
	]);
</script>

{#if !$auth.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m['errors.Unauthorized Desc']()}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m['navigation.Login']()}</a>
	</div>
{:else}
	<div class="p-6">
		<!-- Header -->
		<div class="flex items-center justify-between mb-1">
			<h2 class="text-2xl font-bold text-primary">{m['probes.Title']()}</h2>
			<button onclick={openCreate} class="btn btn-primary">
				+ {m['probes.Add Target']()}
			</button>
		</div>
		<p class="text-sm text-text-muted mb-6">{m['probes.Subtitle']()}</p>

		<!-- Module overview cards (#276): per-module success rate + avg latency -->
		<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
			{#each moduleStats as ms (ms.module)}
				<div class="bg-surface border border-border rounded-lg px-4 py-3">
					<div class="flex items-center justify-between">
						<span class="badge badge-info uppercase">{ms.module}</span>
						<span class="text-xs text-muted">{ms.enabled}/{ms.total}</span>
					</div>
					<p class="mt-2 text-lg font-semibold {ms.successRate === null ? 'text-muted' : ms.successRate >= 90 ? 'text-success' : ms.successRate >= 50 ? 'text-warning' : 'text-error'}">
						{ms.successRate === null ? '-' : ms.successRate + '%'}
					</p>
					<p class="text-xs text-muted">{m['probes.Avg Latency']()}: {ms.avgLatency === null ? '-' : ms.avgLatency < 1000 ? Math.round(ms.avgLatency) + 'ms' : (ms.avgLatency / 1000).toFixed(2) + 's'}</p>
				</div>
			{/each}
		</div>

		<!-- Cert expiry timeline (#276): TLS/http targets sorted by days-left -->
		{#if certTimeline.length > 0}
			<div class="bg-surface border border-border rounded-lg p-4 mb-6">
				<div class="flex items-center justify-between mb-3">
					<div>
						<h3 class="text-sm font-semibold text-text">{m['probes.Cert Timeline']()}</h3>
						<p class="text-xs text-muted">{m['probes.Cert Timeline Desc']()}</p>
					</div>
					<select
						value={expiryWarnDays}
						onchange={(e) => setExpiryWarn(Number((e.target as HTMLSelectElement).value))}
						class="input !w-auto text-xs"
						aria-label={m['probes.Expiry Threshold']()}
					>
						{#each [15, 30, 60, 90] as d (d)}
							<option value={d}>{m['probes.Expiry Threshold Option']({ days: d })}</option>
						{/each}
					</select>
				</div>
				<div class="space-y-1.5">
					{#each certTimeline as e (e.t.id)}
						{@const pct = Math.max(2, Math.min(100, (e.days / 90) * 100))}
						{@const cls = e.days < 0 ? 'bg-error' : e.days < expiryWarnDays ? 'bg-warning' : 'bg-success'}
						<button
							type="button"
							onclick={() => openCerts(e.t)}
							class="w-full flex items-center gap-3 group text-left"
							title={e.notAfter}
						>
							<span class="w-40 shrink-0 truncate text-xs font-medium group-hover:text-primary">{e.t.name}</span>
							<span class="flex-1 h-3 rounded-full bg-border/50 overflow-hidden">
								<span class="block h-full {cls} rounded-full transition-all" style="width: {pct}%"></span>
							</span>
							<span class="w-20 shrink-0 text-right text-xs font-mono {e.days < expiryWarnDays ? 'text-warning' : 'text-muted'}">
								{e.days < 0 ? m['probes.Cert Expired']() : m['probes.Cert Days']({ days: e.days })}
							</span>
						</button>
					{/each}
				</div>
				{#if certTimeline.some((e) => e.days >= 0 && e.days < expiryWarnDays)}
					<p class="mt-3 text-xs text-warning">
						{m['probes.Cert Expiring Hint']()}
						<a href="/settings/notifications" class="text-primary hover:underline">{m['probes.Cert Configure Rule']()}</a>
					</p>
				{/if}
			</div>
		{/if}

		<!-- Batch toolbar (#276) -->
		{#if selectedIds.size > 0}
			<div class="mb-4 flex flex-wrap items-center gap-2 px-4 py-2.5 bg-primary/5 border border-primary/20 rounded-lg">
				<span class="text-sm font-medium text-primary">{m['probes.Batch Selected']({ count: selectedIds.size })}</span>
				<div class="flex-1"></div>
				<button onclick={batchEnable} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['probes.Batch Enable']()}</button>
				<button onclick={batchDisable} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['probes.Batch Disable']()}</button>
				<button onclick={batchInterval} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['probes.Batch Interval']()}</button>
				<button onclick={batchDelete} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs !text-error !border-error/30">{m['common.Delete']()}</button>
				<button onclick={() => (selectedIds = new Set())} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['common.Cancel']()}</button>
			</div>
		{/if}

		{#if error}
			<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
				{error}
			</div>
		{/if}

		{#if loading}
			<PageSkeleton type="table" />
		{:else if targets.length === 0}
			<EmptyState
				icon={ActivityIcon}
				title={m['probes.No Targets']()}
				description={m['probes.No Targets Desc']()}
				actionLabel={m['probes.Add Target']()}
				onAction={openCreate}
			/>
		{:else}
			<div class="bg-surface border border-border rounded-lg p-4">
				<DataTable
					{columns}
					rows={targets as unknown as Record<string, unknown>[]}
					searchableKeys={['name', 'target']}
					emptyTitle={m['probes.No Targets']()}
				>
					{#snippet cell(row, col)}
						{#if col.key === 'select'}
							{@const t = targets.find((x) => x.id === row.id)}
							{#if t}
								<input
									type="checkbox"
									checked={selectedIds.has(t.id)}
									onchange={() => toggleSelected(t.id)}
									aria-label={m['probes.Batch Select Row']({ name: t.name })}
									class="checkbox"
								/>
							{/if}
						{:else if col.key === 'enabled'}
							{@const t = targets.find((x) => x.id === row.id)}
							{#if t}
								<button
									onclick={() => toggleEnabled(t)}
									role="switch"
									aria-checked={t.enabled}
									aria-label={t.enabled ? m['probes.Enabled']() : m['probes.Disabled']()}
									class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors
										{t.enabled ? 'bg-success' : 'bg-border'}"
								>
									<span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform
										{t.enabled ? 'translate-x-4.5' : 'translate-x-0.5'}"></span>
								</button>
							{/if}
						{:else if col.key === 'actions'}
							{@const t = targets.find((x) => x.id === row.id)}
							{#if t}
								<div class="flex items-center gap-2">
									<button
										onclick={() => triggerNow(t)}
										disabled={triggeringId !== null}
										class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors disabled:opacity-50"
									>{triggeringId === t.id ? m['probes.Triggering']() : m['probes.Trigger']()}</button>
									{#if t.module === 'tls' || t.module === 'http'}
										<button
											onclick={() => openCerts(t)}
											class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
										>{m['probes.View Cert']()}</button>
									{/if}
									<button
										onclick={() => openResults(t)}
										class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
									>{m['probes.View Results']()}</button>
									<button
										onclick={() => openEdit(t)}
										class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
									>{m['common.Edit']()}</button>
									<button
										onclick={() => openDelete(t)}
										class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors"
									>{m['probes.Delete Target']()}</button>
								</div>
							{/if}
						{/if}
					{/snippet}
				</DataTable>
			</div>
		{/if}
	</div>
{/if}

<!-- Create/Edit Modal -->
<Modal
	bind:open={editModalOpen}
	title={editingId === null ? m['probes.Add Target']() : m['probes.Edit Target']()}
>
	<form onsubmit={handleSubmit} class="space-y-4">
		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-name">{m['probes.Name']()}</label>
			<input
				id="probe-name"
				class="input"
				class:input-error={!!fieldErrors.name}
				bind:value={formName}
				onblur={() => validate('name', formName)}
				placeholder="github-tls"
			/>
			{#if fieldErrors.name}<p class="text-xs text-error mt-1">{fieldErrors.name}</p>{/if}
		</div>

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-module">{m['probes.Module']()}</label>
			<select id="probe-module" class="input" bind:value={formModule}>
				<option value="http">http</option>
				<option value="tls">tls</option>
				<option value="tcp">tcp</option>
				<option value="icmp">icmp</option>
			</select>
			<p class="text-xs text-text-muted mt-1">{moduleHelp(formModule)}</p>
		</div>

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-target">{m['probes.Target']()}</label>
			<input
				id="probe-target"
				class="input font-mono text-xs"
				class:input-error={!!fieldErrors.target}
				bind:value={formTarget}
				onblur={() => validate('target', formTarget.trim())}
				placeholder={targetPlaceholder(formModule)}
			/>
			{#if fieldErrors.target}<p class="text-xs text-error mt-1">{fieldErrors.target}</p>{/if}
		</div>

		<div class="grid grid-cols-2 gap-4">
			<div>
				<label class="block text-xs text-text-muted mb-1" for="probe-interval">{m['probes.Interval']()}</label>
				<input
					id="probe-interval"
					type="number"
					class="input"
					class:input-error={!!fieldErrors.interval_seconds}
					bind:value={formInterval}
					onblur={() => validate('interval_seconds', formInterval)}
					min="10"
					max="86400"
				/>
				{#if fieldErrors.interval_seconds}
					<p class="text-xs text-error mt-1">{fieldErrors.interval_seconds}</p>
				{:else}
					<p class="text-xs text-text-muted mt-1">{m['probes.Interval Help']()}</p>
				{/if}
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1" for="probe-timeout">{m['heartbeat.Timeout']()}</label>
				<input
					id="probe-timeout"
					type="number"
					class="input"
					class:input-error={!!fieldErrors.timeout_seconds}
					bind:value={formTimeout}
					onblur={() => validate('timeout_seconds', formTimeout)}
					min="1"
					max="60"
				/>
				{#if fieldErrors.timeout_seconds}
					<p class="text-xs text-error mt-1">{fieldErrors.timeout_seconds}</p>
				{:else}
					<p class="text-xs text-text-muted mt-1">{m['probes.Timeout Help']()}</p>
				{/if}
			</div>
		</div>

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-notes">{m['probes.Notes']()}</label>
			<textarea id="probe-notes" class="input" rows="2" bind:value={formNotes} onblur={() => validate('notes', formNotes)}></textarea>
			{#if fieldErrors.notes}<p class="text-xs text-error mt-1">{fieldErrors.notes}</p>{/if}
		</div>

		<label class="flex items-center gap-2 text-sm text-text">
			<input type="checkbox" bind:checked={formEnabled} class="checkbox" />
			{m['probes.Enabled']()}
		</label>

		<div class="flex justify-end gap-2 pt-2">
			<button type="button" class="btn btn-secondary" onclick={() => (editModalOpen = false)}>{m['common.Cancel']()}</button>
			<button type="submit" class="btn btn-primary" disabled={formLoading}>
				{editingId === null ? m['probes.Add Target']() : m['common.Save']()}
			</button>
		</div>
	</form>
</Modal>

<!-- Results history Modal -->
<Modal bind:open={resultsModalOpen} title={m['probes.Results Title']({ name: resultsTarget?.name || '' })}>
	{#if resultsLoading}
		<div class="py-8 text-center text-sm text-text-muted">…</div>
	{:else if results.length === 0}
		<div class="py-8 text-center">
			<p class="text-sm text-text-muted">{m['probes.No Results']()}</p>
			<p class="text-xs text-text-muted mt-1">{m['probes.No Results Desc']()}</p>
		</div>
	{:else}
		<p class="text-xs text-text-muted mb-2">{resultsTotal}</p>
		<div class="max-h-[60vh] overflow-y-auto">
			<DataTable
				columns={resultColumns}
				rows={results as unknown as Record<string, unknown>[]}
				searchableKeys={[]}
				emptyTitle={m['probes.No Results']()}
			/>
		</div>
	{/if}
</Modal>

<!-- Delete confirm -->
<ConfirmDialog
	bind:open={deleteDialogOpen}
	title={m['probes.Delete Title']()}
	message={m['probes.Delete Message']({ name: deleteTarget?.name || '' })}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>

<!-- Certificate chain (shared component, same DTO as the device endpoint) -->
<CertificateModal bind:open={certModalOpen} portCerts={certPortCerts} />
