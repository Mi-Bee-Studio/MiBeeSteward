<script lang="ts">
	/**
	 * Asset archive library (#663/#667): archived devices with lifecycle
	 * badges (periodic / force pins), restore + pin actions, and a link into
	 * each device's dossier timeline.
	 */
	import { onMount } from 'svelte';
	import { m } from '$lib/i18n-paraglide';
	import { addToast } from '$lib/stores/toast';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import {
		listArchive,
		restoreDevice,
		putArchiveSettings,
		type ArchiveItem
	} from '$lib/api/archiveTags';

	let items = $state<ArchiveItem[]>([]);
	let total = $state(0);
	let offset = $state(0);
	const limit = 20;
	let loading = $state(true);
	let error = $state('');

	let restoreOpen = $state(false);
	let restoreTarget = $state<ArchiveItem | null>(null);
	let actionBusy = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			const resp = await listArchive(limit, offset);
			items = resp.devices ?? [];
			total = resp.total ?? 0;
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	function fmt(ts?: string | null): string {
		if (!ts) return '-';
		const d = new Date(ts);
		return Number.isNaN(d.getTime()) ? '-' : d.toLocaleString();
	}

	async function doRestore() {
		if (!restoreTarget) return;
		actionBusy = true;
		try {
			await restoreDevice(restoreTarget.id, restoreTarget.archive_pin === 'force_archive');
			addToast('success', m['archive.Restored']({ name: restoreTarget.name }));
			restoreOpen = false;
			restoreTarget = null;
			await load();
		} catch (e) {
			addToast('error', e instanceof Error ? e.message : String(e));
		} finally {
			actionBusy = false;
		}
	}

	async function togglePin(item: ArchiveItem) {
		const next = item.archive_pin === 'force_archive' ? '' : 'force_archive';
		actionBusy = true;
		try {
			await putArchiveSettings(item.id, { pin: next });
			addToast(
				'success',
				next
					? m['archive.Pin Set']({ name: item.name })
					: m['archive.Pin Cleared']({ name: item.name })
			);
			await load();
		} catch (e) {
			addToast('error', e instanceof Error ? e.message : String(e));
		} finally {
			actionBusy = false;
		}
	}

	function pinBadge(pin: string): string {
		if (pin === 'force_archive') return m['archive.Force Archived']();
		if (pin === 'force_active') return m['archive.Force Active']();
		return '';
	}

	// IP is NOT device identity (#737): an archived record whose name is
	// literally its address and that never collected a MAC is an unidentified
	// gadget — present it as such, with the address as the LAST RECORDED IP
	// (IPs get reassigned; the record is history, not a live claim).
	function isIpOnly(item: ArchiveItem): boolean {
		return !item.mac_address && (!item.name || item.name === item.ip_address);
	}

	onMount(load);
</script>

<div class="p-4 sm:p-6">
	<div class="mb-6 flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
		<div>
			<h1 class="text-xl font-semibold">{m['archive.Title']()}</h1>
			<p class="text-sm text-muted">{m['archive.Subtitle']()}</p>
		</div>
		<a href="/devices" class="text-sm text-primary hover:underline">{m['archive.Back To Devices']()}</a>
	</div>

	{#if error}
		<div class="mb-4 rounded-lg border border-error/40 bg-error/10 px-4 py-3 text-sm text-error">{error}</div>
	{/if}

	{#if loading && items.length === 0}
		<div class="space-y-2">
			{#each Array(5) as _}
				<div class="h-12 animate-pulse rounded-lg bg-muted/40"></div>
			{/each}
		</div>
	{:else if items.length === 0}
		<EmptyState title={m['archive.Empty']()} description={m['archive.Empty Desc']()} />
	{:else}
		<div class="overflow-x-auto rounded-lg border border-border bg-card">
			<table class="w-full text-sm">
				<thead class="bg-muted/50 text-xs uppercase tracking-wide text-muted">
						<tr>
							<th class="px-3 py-2 text-left">{m['devices.Device Name']()}</th>
							<th class="px-3 py-2 text-left">{m['archive.Last Recorded']()}</th>
							<th class="px-3 py-2 text-left">{m['devices.Type']()}</th>
							<th class="px-3 py-2 text-left">{m['devices.Status']()}</th>
							<th class="px-3 py-2 text-left">{m['archive.Archived At']()}</th>
							<th class="px-3 py-2 text-left">{m['archive.Badges']()}</th>
							<th class="px-3 py-2 text-right">{m['archive.Actions']()}</th>
						</tr>
				</thead>
				<tbody class="divide-y divide-border">
					{#each items as item (item.id)}
						<tr class="hover:bg-muted/20">
							<td class="px-3 py-2">
								{#if isIpOnly(item)}
									<a href="/archive/{item.id}" class="font-medium text-primary hover:underline"
										>{m['archive.Unidentified']()}</a
									>
									<span class="ml-1 rounded-full border border-border bg-surface-2 px-2 py-0.5 text-xs text-text-muted">
										{m['archive.Ip Only']()}
									</span>
								{:else}
									<a href="/archive/{item.id}" class="font-medium text-primary hover:underline"
										>{item.name}</a
									>
								{/if}
								{#if item.network_name}<span class="ml-1 text-xs text-muted">({item.network_name})</span
									>{/if}
							</td>
							<td class="px-3 py-2 font-mono text-xs">
								{item.ip_address || '-'}<br />{item.mac_address || '-'}
							</td>
							<td class="px-3 py-2">{item.type}</td>
							<td class="px-3 py-2">
								<span class="inline-flex items-center gap-1.5">
									<span
										class="h-2 w-2 rounded-full {item.status === 'online'
											? 'bg-success'
											: item.status === 'offline'
												? 'bg-error'
												: 'bg-muted'}"
									></span>
									{item.status}
								</span>
								{#if item.status === 'online' && item.online_since}
									<div class="text-xs text-muted">
										{m['archive.Online Since']()}: {fmt(item.online_since)}
									</div>
								{/if}
							</td>
							<td class="px-3 py-2 text-xs">{fmt(item.archived_at)}</td>
							<td class="px-3 py-2">
								<div class="flex flex-wrap gap-1">
									{#if item.periodic}
										<span class="rounded-full bg-primary/15 px-2 py-0.5 text-xs text-primary">
											{m['archive.Periodic']()} · {Math.round(item.periodic_cycle_days || 0)}d
										</span>
									{/if}
									{#if pinBadge(item.archive_pin)}
										<span class="rounded-full bg-warning/20 px-2 py-0.5 text-xs text-warning">
											{pinBadge(item.archive_pin)}
										</span>
									{/if}
								</div>
							</td>
							<td class="whitespace-nowrap px-3 py-2 text-right">
								<button
									class="rounded px-2 py-1 text-xs text-primary hover:bg-primary/10"
									disabled={actionBusy}
									onclick={() => {
										restoreTarget = item;
										restoreOpen = true;
									}}
								>
									{m['archive.Restore Action']()}
								</button>
								<button
									class="rounded px-2 py-1 text-xs text-muted hover:bg-muted/20"
									disabled={actionBusy}
									onclick={() => togglePin(item)}
								>
									{item.archive_pin === 'force_archive'
										? m['archive.Unpin']()
										: m['archive.Pin Force']()}
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		{#if items.some(isIpOnly)}
			<p class="mt-2 text-xs text-muted">{m['archive.Ip Only Note']()}</p>
		{/if}

		<div class="mt-4">
			<Pagination
			{total}
			{limit}
			{offset}
			onPageChange={(o) => {
				offset = o;
				load();
			}}
		/>
		</div>
	{/if}
</div>

<ConfirmDialog
	open={restoreOpen}
	title={m['archive.Restore Title']()}
	message={restoreTarget
		? restoreTarget.archive_pin === 'force_archive'
			? m['archive.Restore Force Msg']({ name: restoreTarget.name })
			: m['archive.Restore Msg']({ name: restoreTarget.name })
		: ''}
	confirmLabel={m['archive.Restore Action']()}
	loading={actionBusy}
	onConfirm={doRestore}
	onCancel={() => {
		restoreOpen = false;
		restoreTarget = null;
	}}
/>
