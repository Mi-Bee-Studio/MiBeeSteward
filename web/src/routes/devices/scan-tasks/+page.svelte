<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { validateScanTarget, validateCronExpr } from '$lib/utils/validation';
	import type { ScannerTask, PipelineConfig, ScanRun } from '$lib/types';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import PipelineConfigEditor from '$lib/components/scanner/PipelineConfigEditor.svelte';

	// --- Core state ---
	let tasks = $state<ScannerTask[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');

	// --- Pagination ---
	let offset = $state(0);
	const limit = 20;
	// --- Search ---
	let searchQuery = $state('');

	let filteredTasks = $derived.by<ScannerTask[]>(() => {
		if (!searchQuery.trim()) return tasks;
		const q = searchQuery.toLowerCase();
		return tasks.filter(t =>
			t.name.toLowerCase().includes(q) || t.targets.toLowerCase().includes(q)
		);
	});

	// --- Form modal ---
	let formOpen = $state(false);
	let editingTask = $state<ScannerTask | null>(null);
	let formError = $state('');
	let formLoading = $state(false);

	let formName = $state('');
	let formTargets = $state('');
	let formCronExpr = $state('');
	let formTimeout = $state(300);
	let formCommunity = $state('public');
	let formEnabled = $state(true);
	let formPipelineConfig = $state<PipelineConfig>(defaultPipeline());
	let formTargetsError = $state('');
	let formCronError = $state('');

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
	onMount(fetchTasks);

	// --- Data fetching ---
	async function fetchTasks() {
		loading = true;
		error = '';
		try {
			const res = await api.get<{ tasks: ScannerTask[]; total: number }>(
				`/scanner/tasks?limit=${limit}&offset=${offset}`
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
	function resetForm() {
		formName = '';
		formTargets = '';
		formCronExpr = '';
		formTimeout = 300;
		formCommunity = 'public';
		formEnabled = true;
		formPipelineConfig = defaultPipeline();
		formError = '';
		formTargetsError = '';
		formCronError = '';
		editingTask = null;
	}

	function openCreate() {
		resetForm();
		formOpen = true;
	}

	function openEdit(task: ScannerTask) {
		editingTask = task;
		formName = task.name;
		formTargets = task.targets;
		formCronExpr = task.cron_expr;
		formTimeout = task.timeout;
		formCommunity = task.community;
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
		formOpen = true;
	}

	function validateTargets(): string | null {
		const err = validateScanTarget(formTargets);
		formTargetsError = err || '';
		return err;
	}

	function validateCron(): string | null {
		const err = validateCronExpr(formCronExpr);
		formCronError = err || '';
		return err;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();

		formTargetsError = '';
		formCronError = '';

		// Validate before submit
		const targetsErr = validateTargets();
		const cronErr = validateCron();
		if (targetsErr || cronErr) {
			return;
		}

		formLoading = true;
		formError = '';

		const body = {
			name: formName,
			targets: formTargets,
			cron_expr: formCronExpr,
			timeout: formTimeout,
			community: formCommunity,
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
			addToast('info', `Scan triggered: ${task.name}`);
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
		const maxPolls = 100; // ~300s with 3s interval
		const poll = async () => {
			pollCount++;
			try {
				const res = await api.get<{ runs: ScanRun[]; total: number }>(`/scanner/tasks/${taskId}/runs?limit=1`);
				if (res.runs && res.runs.length > 0) {
					const run = res.runs[0];
					if (run.status === 'completed' || run.status === 'failed' || run.status === 'cancelled') {
						stopPolling(taskId);
						activeRuns.set(taskId, run);
						activeRuns = new Map(activeRuns);
						if (run.status === 'completed') {
							addToast('success', `Scan done: ${run.alive_hosts}/${run.total_hosts} alive, ${run.new_hosts} new (${run.duration_ms}ms)`);
						} else if (run.status === 'cancelled') {
							addToast('info', 'Scan cancelled');
						} else {
							addToast('error', `Scan failed: ${run.error_message || 'unknown error'}`);
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
					addToast('warning', 'Scan triggered but no run appeared — check the Runs list or server logs.');
					fetchTasks();
				}
			} catch {
				// Poll errors are non-critical, keep trying
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
			addToast('success', 'Scan cancelled');
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
			if (diffMin < 1) return 'just now';
			if (diffMin < 60) return `${diffMin}m ago`;
			if (diffHr < 24) return `${diffHr}h ago`;
			return `${diffDay}d ago`;
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
			<h2 class="text-2xl font-bold text-text">{m['scanner.Task Title']()}</h2>
		</div>
		<button
			onclick={openCreate}
			class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
				hover:bg-primary-hover transition-colors text-sm"
		>
			+ {m['scanner.New Task']()}
		</button>
	</div>
	<!-- Search -->
	{#if tasks.length > 0}
	<div class="relative mb-4">
		<svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none"
			fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
				d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
		</svg>
		<input
			type="text"
			bind:value={searchQuery}
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
		{#if filteredTasks.length === 0 && tasks.length > 0}
			<div class="flex flex-col items-center justify-center py-12 text-center">
				<p class="text-sm text-text-muted">No tasks match "{searchQuery}"</p>
			</div>
		{:else if tasks.length === 0}
			<div class="flex flex-col items-center justify-center py-16 text-center">
				<svg class="w-12 h-12 mb-3 text-text-muted opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
						d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
				</svg>
				<h3 class="text-sm font-medium text-text mb-1">{m['scanner.No Tasks']()}</h3>
				<p class="text-xs text-text-muted">{m['scanner.No Tasks Desc']()}</p>
			</div>
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
						{#each filteredTasks as task}
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
												✓ {run.alive_hosts}/{run.total_hosts} alive ({run.duration_ms}ms)
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
											disabled={triggeringId === task.id}
											class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10
												transition-colors disabled:opacity-50"
										>
									{#if triggeringId === task.id || activeRuns.has(task.id)}
										⏳
									{:else}
										{m['scanner.Trigger']()}
									{/if}
											</button>
											{#if activeRuns.has(task.id) && (activeRuns.get(task.id)?.status === 'running' || activeRuns.get(task.id)?.status === 'triggered')}
												<button
													onclick={() => cancelTask(task.id)}
													disabled={cancellingId === task.id}
													class="text-xs px-2 py-1 rounded text-error hover:bg-error/10
														transition-colors disabled:opacity-50"
												>
													{cancellingId === task.id ? '...' : '✕ Cancel'}
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
<Modal bind:open={formOpen} title={editingTask ? m['scanner.Edit Task']() : m['scanner.Create Task']()} maxWidth="48rem" onClose={resetForm}>
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
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				/>
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
					{formTargetsError ? 'border-error' : 'border-border'}"
					onblur={validateTargets}
				/>
				{#if formTargetsError}
					<p class="text-error text-xs mt-1">{formTargetsError}</p>
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
					{formCronError ? 'border-error' : 'border-border'}"
					onblur={validateCron}
				/>
				{#if formCronError}
					<p class="text-error text-xs mt-1">{formCronError}</p>
				{/if}
			</div>

			<!-- Timeout -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Timeout Seconds']()}</label>
				<input
					type="number"
					bind:value={formTimeout}
					min="1"
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				/>
			</div>

			<!-- Community -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['scanner.Community']()}</label>
				<input
					bind:value={formCommunity}
					placeholder="public"
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				/>
			</div>

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
					hover:bg-primary-hover transition-colors disabled:opacity-50 text-sm">
				{formLoading ? '...' : m['common.Save']()}
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
