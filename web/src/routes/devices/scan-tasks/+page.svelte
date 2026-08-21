<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { validateScanTarget, validateCronExpr, scannerTaskSchema, validateField, validateForm } from '$lib/utils/validation';
	import type { ScannerTask, PipelineConfig, ScanRun } from '$lib/types';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PipelineConfigEditor from '$lib/components/scanner/PipelineConfigEditor.svelte';
	import { Radar, LoaderCircle, ChevronRight } from '@lucide/svelte';

	// --- Core state ---
	let tasks = $state<ScannerTask[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');

	// --- Pagination ---
	let offset = $state(0);
	const limit = 20;
	// --- Search (server-side) ---
	// searchInput is the live textbox value; searchQuery is the term committed to
	// the backend after a 400ms debounce. The old client-side filter only searched
	// the current 20-row page, so tasks on other pages were unreachable. Server-
	// side search matches how devices/+page.svelte does it.
	let searchInput = $state('');
	let searchQuery = $state('');
	let searchTimer: ReturnType<typeof setTimeout> | null = null;

	// onSearchInput debounces the search box: 400ms after the last keystroke the
	// term is committed to searchQuery and a backend fetch fires. Clearing the
	// box commits an empty search immediately so "clear" feels responsive.
	function onSearchInput() {
		if (searchTimer) clearTimeout(searchTimer);
		const v = searchInput.trim();
		if (v === '') {
			searchQuery = '';
			offset = 0;
			fetchTasks();
			return;
		}
		searchTimer = setTimeout(() => {
			searchQuery = v;
			offset = 0;
			fetchTasks();
		}, 400);
	}

	// --- Form modal ---
	let formOpen = $state(false);
	let editingTask = $state<ScannerTask | null>(null);
	let formError = $state('');
	let formLoading = $state(false);

	let formName = $state('');
	let formTargets = $state('');
	let formCronExpr = $state('');
	let formTimeout = $state(300);
	let formConcurrentHosts = $state(16);
	let formCommunity = $state('public');
	let formEnabled = $state(true);
	let formPipelineConfig = $state<PipelineConfig>(defaultPipeline());
	// Unified field-error map for the whole form (targets / cron / name /
	// timeout all read/write here — #154 part 1). Previously targets + cron
	// used two dedicated state vars while name + timeout used fieldErrors,
	// giving three different error-display patterns in one form.
	let fieldErrors = $state<Record<string, string>>({});
	// SNMP credential binding (issue #135). null = use the global community.
	let credentials = $state<Array<{ id: number; name: string; security_level: string }>>([]);
	let formCredentialId = $state<number | null>(null);

	// --- Delete confirmation ---
	let deleteOpen = $state(false);
	let deleteTarget = $state<ScannerTask | null>(null);

	// --- Trigger feedback ---
	let triggeringId = $state<number | null>(null);
	let cancellingId = $state<number | null>(null);
	let activeRuns = $state<Map<number, ScanRun>>(new Map());
	let pollingTimers = new Map<number, ReturnType<typeof setTimeout>>();

	function defaultPipeline(): PipelineConfig {
		return {
			icmp: { enabled: true, timeout: 2 },
			snmp: { enabled: true, community: 'public', timeout: 5 },
			port_scan: { enabled: true, ports: '22,80,443,8080,9100', scan_type: 'connect' },
			service_detect: { enabled: true },
			prometheus: { enabled: true, ports: '9090' },
			node_exporter: { enabled: true }
		};
	}

	// --- Lifecycle ---
	onMount(async () => {
		// Best-effort load of SNMP credentials for the task-binding selector.
		// Silently degrades (selector hidden) for non-admins or when v3 disabled.
		try {
			const res = await api.get<{ credentials: Array<{ id: number; name: string; security_level: string }> }>('/snmp-credentials');
			credentials = res.credentials ?? [];
		} catch {
			// non-admin / disabled — leave empty
		}
		await fetchTasks();
	});

	// Clear all in-flight poll timers on unmount so navigating away mid-run
	// does not keep firing requests (and writing toasts/state) against a
	// destroyed component. Each timer otherwise self-reschedules for up to ~5min.
	onDestroy(() => {
		for (const timer of pollingTimers.values()) {
			clearTimeout(timer);
		}
		pollingTimers.clear();
		if (searchTimer) clearTimeout(searchTimer);
	});

	// --- Data fetching ---
	async function fetchTasks() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			if (searchQuery) params.set('search', searchQuery);
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			const res = await api.get<{ tasks: ScannerTask[]; total: number }>(
				`/scanner/tasks?${params}`
			);
			tasks = res.tasks || [];
			total = res.total || 0;
		} catch (err: unknown) {
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}

		// Auto-detect running tasks and start polling
		for (const task of tasks) {
			if (task.last_run_status === 'running' && !activeRuns.has(task.id)) {
				const stubRun: ScanRun = {
					id: 0, task_id: task.id, status: 'running',
					total_hosts: 0, alive_hosts: 0, new_hosts: 0, updated_hosts: 0,
					duration_ms: 0, created_at: new Date().toISOString()
				};
				activeRuns.set(task.id, stubRun);
				activeRuns = new Map(activeRuns);
				pollRunStatus(task.id);
			}
		}
	}
	// --- Form helpers ---
	// Snapshot of the form state captured when the modal opens. Used by
	// formDirty ($derived) to detect unsaved edits so the Modal can warn
	// before discarding them (Esc / backdrop / X). #151.
	let formSnapshot = $state('');

	function snapshotForm(): string {
		return JSON.stringify([formName, formTargets, formCronExpr, formTimeout,
			formCommunity, formEnabled, formPipelineConfig, formCredentialId]);
	}

	const formDirty = $derived(formOpen && snapshotForm() !== formSnapshot);

	function resetForm() {
		formName = '';
		formTargets = '';
		formCronExpr = '';
		formTimeout = 300;
		formConcurrentHosts = 16;
		formCommunity = 'public';
		formCredentialId = null;
		formEnabled = true;
		formPipelineConfig = defaultPipeline();
		formError = '';
		fieldErrors = {};
		editingTask = null;
	}

	function openCreate() {
		resetForm();
		formSnapshot = snapshotForm();
		formOpen = true;
	}

	function openEdit(task: ScannerTask) {
		editingTask = task;
		formName = task.name;
		formTargets = task.targets;
		formCronExpr = task.cron_expr;
		formTimeout = task.timeout;
		formConcurrentHosts = task.concurrent_hosts ?? 16;
		formCommunity = task.community;
		formCredentialId = task.credential_id ?? null;
		formEnabled = task.enabled;
		// Parse pipeline_config if it's a string
		if (task.pipeline_config) {
			if (typeof task.pipeline_config === 'string') {
				try {
					formPipelineConfig = JSON.parse(task.pipeline_config as unknown as string);
				} catch {
					formPipelineConfig = defaultPipeline();
				}
			} else {
				formPipelineConfig = task.pipeline_config;
			}
		} else {
			formPipelineConfig = defaultPipeline();
		}
		formError = '';
		formSnapshot = snapshotForm();
		formOpen = true;
	}

	function validateTargets(): string | null {
		const err = validateScanTarget(formTargets);
		fieldErrors = err
			? { ...fieldErrors, targets: err }
			: (() => { const { targets: _, ...rest } = fieldErrors; return rest; })();
		return err;
	}

	function validateCron(): string | null {
		const err = validateCronExpr(formCronExpr);
		fieldErrors = err
			? { ...fieldErrors, cron: err }
			: (() => { const { cron: _, ...rest } = fieldErrors; return rest; })();
		return err;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();

		fieldErrors = {};

		// Validate targets + cron via the standalone validators (return localized
		// strings, wired to onblur). Then name + timeout range via scannerTaskSchema.
		// All four fields now write to the same fieldErrors map (previously
		// targets/cron used dedicated vars — #154 part 1).
		const targetsErr = validateTargets();
		const cronErr = validateCron();
		const taskValidation = validateForm(scannerTaskSchema, { name: formName, timeout: formTimeout });
		fieldErrors = { ...fieldErrors, ...taskValidation.errors };
		if (targetsErr || cronErr || !taskValidation.valid) {
			return;
		}

		formLoading = true;
		formError = '';

		const body = {
			name: formName,
			targets: formTargets,
			cron_expr: formCronExpr,
			timeout: formTimeout,
			concurrent_hosts: formConcurrentHosts,
			community: formCommunity,
			credential_id: formCredentialId,
			enabled: formEnabled,
			pipeline_config: formPipelineConfig
		};

		try {
			if (editingTask) {
				await api.put(`/scanner/tasks/${editingTask.id}`, body);
				addToast('success', m['scanner.Task Updated']());
			} else {
				await api.post('/scanner/tasks', body);
				addToast('success', m['scanner.Task Created']());
			}
			formOpen = false;
			resetForm();
			fetchTasks();
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			formError = msg;
			addToast('error', msg);
		} finally {
			formLoading = false;
		}
	}

	// --- Trigger ---
	async function triggerTask(task: ScannerTask) {
		triggeringId = task.id;
		try {
			await api.post(`/scanner/tasks/${task.id}/trigger`, {});
			addToast('info', m['scanner.Scan Triggered']({ name: task.name }));
			// Start polling for run status
			const stubRun: ScanRun = {
				id: 0, task_id: task.id, status: 'running',
				total_hosts: 0, alive_hosts: 0, new_hosts: 0, updated_hosts: 0,
				duration_ms: 0, created_at: new Date().toISOString()
			};
			activeRuns.set(task.id, stubRun);
			activeRuns = new Map(activeRuns); // trigger reactivity
			pollRunStatus(task.id);
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			triggeringId = null;
		}
	}

	function pollRunStatus(taskId: number) {
		if (pollingTimers.has(taskId)) return;
		let pollCount = 0;
		// Track consecutive poll failures so a dead backend doesn't leave the
		// spinner sweeping silently — after a few in a row, surface a warning
		// (once, not per failure). Reset on any successful poll (#65).
		let consecutiveErrors = 0;
		let errorToasted = false;
		const maxPolls = 100; // ~300s with 3s interval
		const poll = async () => {
			pollCount++;
			try {
				const res = await api.get<{ runs: ScanRun[]; total: number }>(`/scanner/tasks/${taskId}/runs?limit=1`);
				consecutiveErrors = 0;
				errorToasted = false;
				if (res.runs && res.runs.length > 0) {
					const run = res.runs[0];
					if (run.status === 'completed' || run.status === 'failed' || run.status === 'cancelled') {
						stopPolling(taskId);
						activeRuns.set(taskId, run);
						activeRuns = new Map(activeRuns);
						if (run.status === 'completed') {
							addToast('success', m['scanner.Scan Done']({ alive: run.alive_hosts, total: run.total_hosts, new: run.new_hosts, duration: run.duration_ms }));
						} else if (run.status === 'cancelled') {
							addToast('info', m['scanner.Scan Cancelled']());
						} else {
							addToast('error', m['scanner.Scan Failed']({ error: run.error_message || 'unknown error' }));
						}
						setTimeout(() => {
							activeRuns.delete(taskId);
							activeRuns = new Map(activeRuns);
						}, 5000);
						fetchTasks();
					} else {
						activeRuns.set(taskId, run);
						activeRuns = new Map(activeRuns);
					}
				} else if (pollCount >= maxPolls) {
					stopPolling(taskId);
					activeRuns.delete(taskId);
					activeRuns = new Map(activeRuns);
					// No run row appeared after ~5min of polling. The backend now
					// records a failed run when the engine is unavailable (so this
					// path is rarer), but a scheduler that never picked up the
					// trigger can still land here — point the user at the runs list
					// / server logs rather than claiming the scheduler is unwired.
					addToast('warning', m['scanner.Scan No Run']());
					fetchTasks();
				}
			} catch (err: unknown) {
				// Poll errors are non-critical — keep trying — but after several in
				// a row the live-progress spinner is lying to the user. Surface one
				// warning so they know to refresh manually (the loop keeps running).
				consecutiveErrors++;
				if (consecutiveErrors >= 3 && !errorToasted) {
					errorToasted = true;
					addToast('warning', getErrorMessage(err));
				}
			}
			if (pollingTimers.has(taskId)) {
				pollingTimers.set(taskId, setTimeout(poll, 3000));
			}
		};
		pollingTimers.set(taskId, setTimeout(poll, 3000));
	}

	function stopPolling(taskId: number) {
		const timer = pollingTimers.get(taskId);
		if (timer) {
			clearTimeout(timer);
			pollingTimers.delete(taskId);
		}
	}

	// --- Toggle enabled ---
	async function toggleEnabled(task: ScannerTask) {
		try {
			await api.put(`/scanner/tasks/${task.id}`, {
				enabled: !task.enabled
			});
			fetchTasks();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Delete ---
	function openDelete(task: ScannerTask) {
		deleteTarget = task;
		deleteOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/scanner/tasks/${deleteTarget.id}`);
			addToast('success', m['scanner.Task Deleted']());
			deleteTarget = null;
			fetchTasks();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Cancel running scan ---
	async function cancelTask(taskId: number) {
		cancellingId = taskId;
		try {
			await api.post(`/scanner/tasks/${taskId}/cancel`, {});
			addToast('success', m['scanner.Scan Cancelled']());
			stopPolling(taskId);
			activeRuns.delete(taskId);
			activeRuns = new Map(activeRuns);
			fetchTasks();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			cancellingId = null;
		}
	}

	// --- Relative time ---
	function formatRelative(iso: string | null): string {
		if (!iso) return m['scanner.Never']();
		try {
			const date = new Date(iso);
			const now = new Date();
			const diffMs = now.getTime() - date.getTime();
			const diffMin = Math.floor(diffMs / 60000);
			const diffHr = Math.floor(diffMs / 3600000);
			const diffDay = Math.floor(diffMs / 86400000);
			if (diffMin < 1) return m['scanner.Just Now']();
			if (diffMin < 60) return m['scanner.Minutes Ago']({ n: diffMin });
			if (diffHr < 24) return m['scanner.Hours Ago']({ n: diffHr });
			return m['scanner.Days Ago']({ n: diffDay });
		} catch {
			return iso;
		}
	}

	function truncateTargets(targets: string, maxLen: number = 30): string {
		return targets.length > maxLen ? targets.slice(0, maxLen) + '...' : targets;
	}
</script>

<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<div>
			<h2 class="text-2xl font-bold text-primary">{m['scanner.Task Title']()}</h2>
		</div>
		<button
			onclick={openCreate}
			class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
				hover:bg-primary-hover transition-colors text-sm"
		>
			+ {m['scanner.New Task']()}
		</button>
	</div>
	<!-- Search (server-side). Keep the box visible while a search is active even
	     if the current page is empty, so the user can edit/clear the query. -->
	{#if tasks.length > 0 || searchQuery}
	<div class="relative mb-4">
		<svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none"
			fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
				d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
		</svg>
		<input
			type="text"
			bind:value={searchInput}
			oninput={onSearchInput}
			placeholder={m['scanner.Search Tasks']()}
			class="pl-10 pr-4 py-2 w-full max-w-sm bg-surface border border-border rounded-lg text-sm text-text
				placeholder:text-text-muted/40 focus:border-primary focus:outline-none"
		/>
	</div>
	{/if}

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite">
			{error}
		</div>
	{/if}

	<!-- Loading skeleton -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else}
		<!-- Empty state -->
			{#if tasks.length === 0 && searchQuery}
				<EmptyState
					title={m['common.No Results']()}
					description={m['scanner.No Tasks Match']({ query: searchQuery })}
				/>
			{:else if tasks.length === 0}
				<EmptyState
					icon={Radar}
					title={m['scanner.No Tasks']()}
					description={m['scanner.No Tasks Desc']()}
					actionLabel={m['scanner.New Task']()}
					onAction={openCreate}
				/>
			{:else}
			<!-- Task table -->
			<div class="overflow-x-auto rounded-lg border border-border">
				<table class="w-full">
					<thead>
						<tr class="border-b border-border text-left text-xs text-text-muted bg-surface">
							<th class="px-4 py-3">{m['scanner.Task Name']()}</th>
							<th class="px-4 py-3">{m['scanner.Targets']()}</th>
							<th class="px-4 py-3">{m['scanner.Cron Expression']()}</th>
							<th class="px-4 py-3">{m['scanner.Status']()}</th>
							<th class="px-4 py-3">{m['scanner.Last Run']()}</th>
							<th class="px-4 py-3 text-right">{m['common.Actions']()}</th>
						</tr>
					</thead>
					<tbody>
						{#each tasks as task}
							<tr class="border-b border-border last:border-b-0 hover:bg-border/30 transition-colors">
								<!-- Name -->
								<td class="px-4 py-3 text-sm font-medium text-text">{task.name}</td>

								<!-- Targets (truncated) -->
								<td class="px-4 py-3 text-sm text-text-muted font-mono max-w-[200px] truncate"
									title={task.targets}>
									{truncateTargets(task.targets)}
								</td>

								<!-- Cron -->
								<td class="px-4 py-3 text-sm font-mono text-accent">{task.cron_expr}</td>

								<!-- Status (enabled/disabled badge with toggle) -->
								<td class="px-4 py-3">
									<button
										onclick={() => toggleEnabled(task)}
										class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium cursor-pointer transition-colors
											{task.enabled
												? 'text-success bg-success/10 hover:bg-success/20'
												: 'text-text-muted bg-border hover:bg-border/80'}"
										title={task.enabled ? m['scanner.Disable']?.() || 'Disable' : m['scanner.Enable']?.() || 'Enable'}
									>
										<span class="w-1.5 h-1.5 rounded-full {task.enabled ? 'bg-success' : 'bg-text-muted'}"></span>
										{task.enabled ? m['scanner.Enabled']() : m['scanner.Disabled']()}
									</button>
								</td>

								<!-- Last run -->
								<td class="px-4 py-3 text-xs text-text-muted whitespace-nowrap">
									{#if activeRuns.has(task.id)}
										{@const run = activeRuns.get(task.id)}
										{#if run?.status === 'running' || run?.status === 'triggered'}
											<div>
												<span class="inline-flex items-center gap-1.5 text-accent">
													<svg class="w-3 h-3 animate-spin" viewBox="0 0 24 24" fill="none">
														<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
														<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
													</svg>
													{m['scanner.Running']()}
												</span>
												<!-- Indeterminate progress bar: a scan's true progress isn't known until
												     it finishes, so we show an animated sweep rather than a fake "60%"
												     that misleads users into thinking completion is near. -->
												<div class="mt-1.5 w-full max-w-[120px] h-1.5 bg-border rounded-full overflow-hidden relative">
													<div class="absolute inset-y-0 left-0 w-1/3 bg-accent rounded-full scan-progress-sweep"></div>
												</div>
											</div>
										{:else if run?.status === 'completed'}
											<span class="inline-flex items-center gap-1 text-success">
												✓ {m['scanner.Scan Done']({ alive: run.alive_hosts, total: run.total_hosts, new: run.new_hosts, duration: run.duration_ms })}
											</span>
										{:else if run?.status === 'cancelled'}
											<span class="inline-flex items-center gap-1 text-text-muted">
												⊘ {m['scanner.Cancelled']()}
											</span>
										{:else if run?.status === 'failed'}
											<span class="text-error">✗ {run.error_message || m['scanner.Failed']()}</span>
										{/if}
									{:else}
										{formatRelative(task.last_run_at)}
									{/if}
								</td>

								<!-- Actions -->
								<td class="px-4 py-3">
									<div class="flex gap-2 justify-end">
										<button
											onclick={() => triggerTask(task)}
											aria-label={m['scanner.Trigger']()}
											disabled={triggeringId === task.id || activeRuns.has(task.id)}
											class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10
												transition-colors disabled:opacity-50"
										>
									{#if triggeringId === task.id || activeRuns.has(task.id)}
										<span aria-hidden="true">⏳</span>
										<span class="sr-only">{m['scanner.Trigger']()}</span>
									{:else}
										{m['scanner.Trigger']()}
									{/if}
											</button>
											{#if activeRuns.has(task.id) && (activeRuns.get(task.id)?.status === 'running' || activeRuns.get(task.id)?.status === 'triggered')}
												<button
													onclick={() => cancelTask(task.id)}
													disabled={cancellingId === task.id}
													class="text-xs px-2 py-1 rounded text-error hover:bg-error/10
														transition-colors disabled:opacity-50 inline-flex items-center gap-1"
												>
													{#if cancellingId === task.id}<LoaderCircle class="w-3 h-3 animate-spin" aria-hidden="true" />{/if}
													<span>✕ {m['common.Cancel']()}</span>
												</button>
											{/if}
										<button
											onclick={() => openEdit(task)}
											class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10 transition-colors"
										>{m['common.Edit']()}</button>
										<button
											onclick={() => openDelete(task)}
											class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors"
										>{m['common.Delete']()}</button>
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			<!-- Pagination -->
			<Pagination {total} {limit} {offset} onPageChange={(o) => { offset = o; fetchTasks(); }} />
		{/if}
	{/if}
</div>

<!-- Create/Edit Modal -->
<Modal bind:open={formOpen} title={editingTask ? m['scanner.Edit Task']() : m['scanner.Create Task']()} maxWidth="48rem" onClose={resetForm} confirmDiscard={() => formDirty}>
	{#if formError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{formError}
		</div>
	{/if}

	<form onsubmit={handleSubmit} class="space-y-4">
		<div class="grid grid-cols-2 gap-4">
			<!-- Name -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Task Name']()} *</label>
				<input
					bind:value={formName}
					required
					placeholder={m['scanner.Task Name Placeholder']()}
					onblur={() => {
						const r = validateField(scannerTaskSchema, 'name', formName);
						fieldErrors = r.valid
							? (() => { const { name: _, ...rest } = fieldErrors; return rest; })()
							: { ...fieldErrors, name: r.error ?? '' };
					}}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none {fieldErrors.name ? '!border-error' : ''}"
				/>
				{#if fieldErrors.name}
					<p class="mt-1 text-xs text-error">{fieldErrors.name}</p>
				{/if}
			</div>

			<!-- Targets -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Targets']()} *</label>
				<input
					bind:value={formTargets}
					required
					placeholder={m['scanner.Targets Placeholder']()}
					class="w-full px-3 py-2 bg-bg border rounded-lg text-sm text-text font-mono
					focus:border-primary focus:outline-none
					{fieldErrors.targets ? 'border-error' : 'border-border'}"
					onblur={validateTargets}
				/>
				{#if fieldErrors.targets}
					<p class="text-error text-xs mt-1">{fieldErrors.targets}</p>
				{/if}
			</div>

			<!-- Cron -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Cron Expression']()} *</label>
				<input
					bind:value={formCronExpr}
					required
					placeholder={m['scanner.Cron Placeholder']()}
					class="w-full px-3 py-2 bg-bg border rounded-lg text-sm text-text font-mono
					focus:border-primary focus:outline-none
					{fieldErrors.cron ? 'border-error' : 'border-border'}"
					onblur={validateCron}
				/>
				{#if fieldErrors.cron}
					<p class="text-error text-xs mt-1">{fieldErrors.cron}</p>
				{/if}
			</div>

			<!-- Advanced: timeout + concurrency (#275) — collapsed by default -->
			<details class="group">
				<summary class="cursor-pointer select-none text-xs text-text-muted hover:text-text mb-2 flex items-center gap-1">
					<ChevronRight class="w-3 h-3 transition-transform group-open:rotate-90" />
					{m['scanner.Advanced Options']()}
				</summary>
			<!-- Timeout -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Timeout Seconds']()}</label>
				<input
					type="number"
					bind:value={formTimeout}
					min="1"
					max="3600"
					onblur={() => {
						const r = validateField(scannerTaskSchema, 'timeout', formTimeout);
						fieldErrors = r.valid
							? (() => { const { timeout: _, ...rest } = fieldErrors; return rest; })()
							: { ...fieldErrors, timeout: r.error ?? '' };
					}}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none {fieldErrors.timeout ? '!border-error' : ''}"
				/>
				{#if fieldErrors.timeout}
					<p class="mt-1 text-xs text-error">{fieldErrors.timeout}</p>
				{/if}
			</div>

			<!-- Concurrent hosts -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Concurrent Hosts']()}</label>
				<input
					type="number"
					bind:value={formConcurrentHosts}
					min="1"
					max="200"
					required
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				/>
			</div>

			</details>

			<!-- Community -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Community']()}</label>
				<input
					bind:value={formCommunity}
					placeholder="public"
					disabled={formCredentialId !== null}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none disabled:opacity-60"
				/>
			</div>

			<!-- SNMP credential (issue #135) — shown only when credentials exist -->
			{#if credentials.length > 0}
				<div>
					<label class="block text-xs text-text-muted mb-1">{m['snmpCredentials.Title']()}</label>
					<select
						bind:value={formCredentialId}
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
							focus:border-primary focus:outline-none"
					>
						<option value={null}>— {m['snmpCredentials.Community']()} —</option>
						{#each credentials as c (c.id)}
							<option value={c.id}>{c.name} ({c.security_level})</option>
						{/each}
					</select>
				</div>
			{/if}

			<!-- Enabled toggle -->
			<div class="flex items-end gap-2 pb-1">
				<label class="text-xs text-text-muted">{m['scanner.Enabled']()}</label>
				<button
					type="button"
					onclick={() => { formEnabled = !formEnabled; }}
					class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors
						{formEnabled ? 'bg-primary' : 'bg-border'}"
					role="switch"
					aria-checked={formEnabled}
				>
					<span class="inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform
						{formEnabled ? 'translate-x-4' : 'translate-x-0.5'}"></span>
				</button>
			</div>
		</div>

		<!-- Pipeline config -->
		<div>
			<label class="block text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
				{m['scanner.pipeline.title']()}
			</label>
			<PipelineConfigEditor bind:config={formPipelineConfig} />
		</div>

		<!-- Submit -->
		<div class="flex gap-3 pt-2 border-t border-border">
			<button type="submit" disabled={formLoading}
				class="px-6 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover transition-colors disabled:opacity-50 text-sm inline-flex items-center gap-2">
				{#if formLoading}<LoaderCircle class="w-4 h-4 animate-spin" aria-hidden="true" />{/if}
				<span>{m['common.Save']()}</span>
			</button>
			<button type="button" onclick={() => { formOpen = false; resetForm(); }}
				class="px-6 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary transition-colors text-sm">
				{m['common.Cancel']()}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteOpen}
	title={m['scanner.Delete Task']()}
	message={`${m['scanner.Delete Confirm']()}"${deleteTarget?.name ?? ''}"`}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>
