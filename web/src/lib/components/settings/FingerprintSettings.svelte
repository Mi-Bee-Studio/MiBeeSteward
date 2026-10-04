<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. You can use, modify, and redistribute it under
  those terms; see LICENSE for the full text. A commercial license is available
  for use cases the AGPL does not accommodate; see the main repository's
  LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import {
		RefreshCw,
		Upload,
		Undo2,
		CloudDownload,
		FileCode2,
		CheckCircle2,
		AlertCircle
	} from '@lucide/svelte';

	interface CorpusFile {
		name: string;
		size: number;
	}
	interface CorpusStatus {
		source: 'embedded' | 'managed' | 'dir';
		rev: string;
		rule_count?: number;
		engine_rev?: string;
		bytes: number;
		files: CorpusFile[];
		uploads_enabled: boolean;
		upstream_configured: boolean;
		prev_available: boolean;
		prev_rev?: string;
	}
	interface UpstreamCheck {
		upstream_version: string;
		upstream_rev: string;
		rule_count: number;
		current_rev: string;
		up_to_date: boolean;
		changed_files: string[];
		added_rules: string[];
		removed_rules: string[];
	}
	interface AdoptionRow {
		agent_id: string;
		version: string;
		fingerprint_rev: string;
		up_to_date: boolean;
		last_report_at: string;
	}

	let status = $state<CorpusStatus | null>(null);
	let upstream = $state<UpstreamCheck | null>(null);
	let adoption = $state<AdoptionRow[]>([]);
	let loading = $state(true);
	let error = $state('');
	let busy = $state('');

	let fileInput = $state<HTMLInputElement | null>(null);
	let rollbackDialog = $state(false);
	let applyDialog = $state(false);
	let previewFile = $state<{ name: string; content: string } | null>(null);

	const sourceLabel: Record<string, string> = {
		embedded: m['fingerprintAdmin.sourceEmbedded'](),
		managed: m['fingerprintAdmin.sourceManaged'](),
		dir: m['fingerprintAdmin.sourceDir']()
	};

	onMount(load);

	async function load() {
		loading = true;
		error = '';
		try {
			const [st, ag] = await Promise.all([
				api.get<CorpusStatus>('/fingerprints'),
				api.get<{ agents: AdoptionRow[] }>('/fingerprints/agents')
			]);
			status = st;
			adoption = ag.agents ?? [];
			upstream = null;
		} catch (e) {
			error = getErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	async function upload(file: File) {
		busy = 'upload';
		try {
			const fd = new FormData();
			fd.append('file', file);
			const res = await api.upload<{ rev: string; rule_count: number }>('/fingerprints', fd);
			addToast(
				m['fingerprintAdmin.uploadOk']({ rules: String(res.rule_count), rev: res.rev.slice(0, 8) }),
				'success'
			);
			await load();
		} catch (e) {
			addToast(m['fingerprintAdmin.uploadFailed']({ error: getErrorMessage(e) }), 'error');
		} finally {
			busy = '';
		}
	}

	function onFileChosen(ev: Event) {
		const input = ev.target as HTMLInputElement;
		if (input.files?.length) upload(input.files[0]);
		input.value = '';
	}

	async function doRollback() {
		rollbackDialog = false;
		busy = 'rollback';
		try {
			const res = await api.post<{ rev: string; rule_count: number }>('/fingerprints/rollback', {});
			addToast(
				m['fingerprintAdmin.rollbackOk']({ rules: String(res.rule_count), rev: res.rev.slice(0, 8) }),
				'success'
			);
			await load();
		} catch (e) {
			addToast(m['fingerprintAdmin.actionFailed']({ error: getErrorMessage(e) }), 'error');
		} finally {
			busy = '';
		}
	}

	async function checkUpstream() {
		busy = 'check';
		try {
			const res = await api.get<UpstreamCheck>('/fingerprints/upstream');
			// The Go handler serializes empty slices as JSON null; a null
			// here crashes the panel's render effect (`null.length`), which
			// Svelte 5 turns into a silently dead subtree — the button then
			// looks like it "did nothing". Normalize before assigning.
			upstream = {
				...res,
				changed_files: res.changed_files ?? [],
				added_rules: res.added_rules ?? [],
				removed_rules: res.removed_rules ?? []
			};
		} catch (e) {
			addToast(m['fingerprintAdmin.actionFailed']({ error: getErrorMessage(e) }), 'error');
		} finally {
			busy = '';
		}
	}

	async function doApply() {
		applyDialog = false;
		busy = 'apply';
		try {
			const res = await api.post<{ rev: string; rule_count: number }>(
				'/fingerprints/upstream/apply',
				{}
			);
			addToast(
				m['fingerprintAdmin.uploadOk']({ rules: String(res.rule_count), rev: res.rev.slice(0, 8) }),
				'success'
			);
			await load();
		} catch (e) {
			addToast(m['fingerprintAdmin.actionFailed']({ error: getErrorMessage(e) }), 'error');
		} finally {
			busy = '';
		}
	}

	async function openPreview(name: string) {
		try {
			const res = await api.get<{ name: string; content: string }>(
				`/fingerprints/files/${encodeURIComponent(name)}`
			);
			previewFile = res;
		} catch (e) {
			addToast(m['fingerprintAdmin.actionFailed']({ error: getErrorMessage(e) }), 'error');
		}
	}

	const fmtBytes = (n: number) =>
		n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1024).toFixed(0) + ' KB';
</script>

{#if loading}
	<PageSkeleton />
{:else if error}
	<EmptyState title={m['fingerprintAdmin.title']()} description={error} actionLabel={m['fingerprintAdmin.retry']()} onAction={load} />
{:else if status}
	<div class="space-y-6">

		<!-- status card -->
		<div class="bg-surface border border-border rounded-xl p-6">
			<div class="flex flex-wrap items-center justify-between gap-4">
				<div>
					<div class="text-lg font-semibold text-text">
						{m['fingerprintAdmin.currentSource']()}:
						<span class="text-primary ml-2">{sourceLabel[status.source] ?? status.source}</span>
					</div>
					<div class="text-sm text-muted mt-1 font-mono break-all">
						rev {status.rev.slice(0, 16)}…
						{#if status.rule_count !== undefined}
							· {status.rule_count} {m['fingerprintAdmin.rules']()}
						{/if}
						· {status.files.length} {m['fingerprintAdmin.files']()} ({fmtBytes(status.bytes)})
					</div>
					{#if status.prev_available}
						<div class="text-xs text-muted mt-1">
							{m['fingerprintAdmin.prevAvailable']()}:
							<span class="font-mono">{(status.prev_rev ?? '').slice(0, 12)}…</span>
						</div>
					{/if}
				</div>
				<div class="flex flex-wrap gap-2">
					<LoadingButton loading={busy === 'upload'} disabled={!status.uploads_enabled}
						onclick={() => fileInput?.click()}>
						<Upload class="w-4 h-4" />
						{m['fingerprintAdmin.upload']()}
					</LoadingButton>
					<LoadingButton loading={busy === 'rollback'} variant="secondary"
						disabled={!status.uploads_enabled || !status.prev_available}
						onclick={() => (rollbackDialog = true)}>
						<Undo2 class="w-4 h-4" />
						{m['fingerprintAdmin.rollback']()}
					</LoadingButton>
					<LoadingButton loading={busy === 'check'} variant="secondary" onclick={checkUpstream}>
						<CloudDownload class="w-4 h-4" />
						{m['fingerprintAdmin.checkUpstream']()}
					</LoadingButton>
					<LoadingButton loading={busy === '' && loading} variant="ghost" onclick={load}>
						<RefreshCw class="w-4 h-4" />
					</LoadingButton>
				</div>
			</div>
			<input type="file" class="hidden" accept=".yaml,.tar.gz,.tgz,.zip"
				bind:this={fileInput} onchange={onFileChosen} />
			{#if !status.uploads_enabled}
				<div class="mt-3 text-sm text-yellow-500 flex items-center gap-2">
					<AlertCircle class="w-4 h-4" />
					{m['fingerprintAdmin.uploadsDisabledHint']()}
				</div>
			{/if}
		</div>

		<!-- upstream panel -->
		{#if upstream}
			<div class="bg-surface border border-border rounded-xl p-6">
				<div class="flex flex-wrap items-center justify-between gap-3 mb-3">
					<h2 class="font-semibold text-text">{m['fingerprintAdmin.upstreamTitle']()}</h2>
					{#if upstream.up_to_date}
						<span class="flex items-center gap-1 text-sm text-green-500">
							<CheckCircle2 class="w-4 h-4" /> {m['fingerprintAdmin.upToDate']()}
						</span>
					{:else}
						<LoadingButton loading={busy === 'apply'} disabled={!status.uploads_enabled}
							onclick={() => (applyDialog = true)}>
							<CloudDownload class="w-4 h-4" />
							{m['fingerprintAdmin.applyUpdate']()} (v{upstream.upstream_version})
						</LoadingButton>
					{/if}
				</div>
				<div class="text-sm text-muted mb-2 font-mono">
					{m['fingerprintAdmin.upstreamRev']()}: {upstream.upstream_rev.slice(0, 16)}…
					· {upstream.rule_count} {m['fingerprintAdmin.rules']()}
				</div>
				{#if upstream.changed_files.length}
					<div class="text-sm mb-1 font-medium text-text">{m['fingerprintAdmin.changedFiles']()}</div>
					<div class="flex flex-wrap gap-1 mb-3">
						{#each upstream.changed_files as f}
							<span class="text-xs bg-background border border-border rounded px-2 py-0.5 font-mono">{f}</span>
						{/each}
					</div>
				{/if}
				{#if upstream.added_rules.length}
					<div class="text-sm mb-1 font-medium text-green-500">+ {m['fingerprintAdmin.addedRules']()}</div>
					<div class="flex flex-wrap gap-1 mb-2">
						{#each upstream.added_rules as id}
							<span class="text-xs bg-green-500/10 border border-green-500/30 rounded px-2 py-0.5 font-mono">{id}</span>
						{/each}
					</div>
				{/if}
				{#if upstream.removed_rules.length}
					<div class="text-sm mb-1 font-medium text-red-500">− {m['fingerprintAdmin.removedRules']()}</div>
					<div class="flex flex-wrap gap-1">
						{#each upstream.removed_rules as id}
							<span class="text-xs bg-red-500/10 border border-red-500/30 rounded px-2 py-0.5 font-mono">{id}</span>
						{/each}
					</div>
				{/if}
			</div>
		{/if}

		<!-- fleet adoption -->
		<div class="bg-surface border border-border rounded-xl p-6">
			<h2 class="font-semibold text-text mb-3">{m['fingerprintAdmin.adoptionTitle']()}</h2>
			{#if adoption.length === 0}
				<p class="text-sm text-muted">{m['fingerprintAdmin.noAgents']()}</p>
			{:else}
				<div class="space-y-2">
					{#each adoption as a}
						<div class="flex flex-wrap items-center justify-between gap-2 border border-border rounded-lg px-4 py-2">
							<div>
								<span class="font-medium text-text font-mono">{a.agent_id}</span>
								<span class="text-xs text-muted ml-2">{a.version}</span>
							</div>
							<div class="flex items-center gap-2">
								{#if a.fingerprint_rev}
									<span class="text-xs font-mono text-muted">{a.fingerprint_rev.slice(0, 10)}…</span>
									{#if a.up_to_date}
										<span class="flex items-center gap-1 text-xs text-green-500">
											<CheckCircle2 class="w-3.5 h-3.5" /> {m['fingerprintAdmin.upToDate']()}
										</span>
									{:else}
										<span class="flex items-center gap-1 text-xs text-yellow-500">
											<AlertCircle class="w-3.5 h-3.5" /> {m['fingerprintAdmin.stale']()}
										</span>
									{/if}
								{:else}
									<span class="text-xs text-muted">{m['fingerprintAdmin.revUnknown']()}</span>
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</div>

		<!-- corpus files -->
		<div class="bg-surface border border-border rounded-xl p-6">
			<h2 class="font-semibold text-text mb-3">
				{m['fingerprintAdmin.filesTitle']()} ({status.files.length})
			</h2>
			<div class="grid gap-2">
				{#each status.files as f}
					<button
						class="flex items-center justify-between border border-border rounded-lg px-4 py-2 hover:border-primary transition-colors text-left"
						onclick={() => openPreview(f.name)}
					>
						<span class="flex items-center gap-2 font-mono text-sm text-text">
							<FileCode2 class="w-4 h-4 text-primary" />{f.name}
						</span>
						<span class="text-xs text-muted">{fmtBytes(f.size)}</span>
					</button>
				{/each}
			</div>
		</div>
	</div>
{/if}

<ConfirmDialog
	open={rollbackDialog}
	title={m['fingerprintAdmin.rollbackConfirmTitle']()}
	message={m['fingerprintAdmin.rollbackConfirmMsg']()}
	confirmLabel={m['fingerprintAdmin.rollback']()}
	onConfirm={doRollback}
	onCancel={() => (rollbackDialog = false)}
/>

<ConfirmDialog
	open={applyDialog}
	title={m['fingerprintAdmin.applyConfirmTitle']()}
	message={m['fingerprintAdmin.applyConfirmMsg']({ version: upstream?.upstream_version ?? '' })}
	confirmLabel={m['fingerprintAdmin.applyUpdate']()}
	onConfirm={doApply}
	onCancel={() => (applyDialog = false)}
/>

{#if previewFile}
	<Modal open title={previewFile.name} onClose={() => (previewFile = null)} maxWidth="48rem">
		<pre class="text-xs bg-background border border-border rounded-lg p-4 overflow-auto max-h-[60vh]">{previewFile.content}</pre>
	</Modal>
{/if}
