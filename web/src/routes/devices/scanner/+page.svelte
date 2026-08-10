<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api, RequestCancelledError } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { validateScanTarget } from '$lib/utils/validation';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import { LoaderCircle, Radar, CircleStop } from '@lucide/svelte';
	import { onMount } from 'svelte';

	// All 9 device types matching internal/domain/device.go
	const DEVICE_TYPES = ['pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas'] as const;

	interface ScanHost {
		ip: string;
		alive: boolean;
		rtt_ms: number;
		snmp_name: string;
		snmp_descr: string;
		snmp_success: boolean;
		// Enriched fields (inferred from scan data)
		inferred_brand?: string;
		inferred_type?: string;
		inferred_description?: string;
		inferred_location?: string;
	}

	interface ScanResponse {
		hosts: ScanHost[];
		total: number;
		alive: number;
		duration_ms: number;
	}

	interface AddDevicesResponse {
		added: number;
		errors: string[];
	}

	// Form state
	let targets = $state('');
	let community = $state('public');
	let timeout = $state(2);
	let targetsError = $state('');
	// SNMP credential selection (issue #135). When set, overrides community and
	// routes the scan through v3 USM (or the credential's own community).
	let credentials = $state<Array<{ id: number; name: string; security_level: string }>>([]);
	let selectedCredentialId = $state<number | null>(null);

	// Best-effort credential list load (issue #135). Failures are silent — the
	// community field still works as the fallback. Admin-only endpoint; non-admin
	// users just see no selector and use community as before.
	onMount(async () => {
		try {
			const res = await api.get<{ credentials: Array<{ id: number; name: string; security_level: string }> }>('/snmp-credentials');
			credentials = res.credentials ?? [];
		} catch {
			// Non-admin or disabled — leave credentials empty; selector hidden.
		}
	});

	// Results state
	let scanning = $state(false);
	// AbortController for the in-flight scan request — lets the user cancel a
	// long scan. The backend honors request-context cancellation (ScanTargets
	// listens on ctx.Done), so aborting here actually stops the server scan.
	let scanController: AbortController | null = null;
	let result = $state<ScanResponse | null>(null);
	// Inline error for a failed whole-scan run. Previously a scan failure only
	// surfaced as a corner toast and the result pane stayed silently empty —
	// easy to miss and indistinguishable from "no alive hosts".
	let scanError = $state('');
	let selectedIps = $state<Set<string>>(new Set());
	let adding = $state(false);
	// Expand/collapse unreachable hosts
	let showAllUnreachable = $state(false);
	// Client-side pagination of the alive-hosts table. The alive table renders
	// a heavy row (4 bound inputs + a 9-option select + 4 conditional badges),
	// so an unbounded /22+ (1k+ hosts) thrashes the DOM. Form state is kept in
	// Record<ip, value> maps keyed by IP, so slicing the rendered rows loses no
	// edits when paging — the maps survive independent of which slice is shown.
	let aliveOffset = $state(0);
	let aliveLimit = $state(50);
	// Confirm dialog for bulk add
	let confirmAddOpen = $state(false);

	// Per-host form state
	let deviceTypes: Record<string, string> = $state({});
	let deviceNames: Record<string, string> = $state({});
	let deviceDescriptions: Record<string, string> = $state({});
	let deviceBrands: Record<string, string> = $state({});
	let deviceLocations: Record<string, string> = $state({});

	// Track which fields were auto-detected (for badge display)
	let autoDetectedFields: Record<string, Set<string>> = $state({});

	function getDeviceTypeLabel(type: string): string {
		const key = `devices.${type.charAt(0).toUpperCase() + type.slice(1)}`;
		try {
			return m[key as keyof typeof m]();
		} catch {
			return type;
		}
	}

	function getAliveHosts(): ScanHost[] {
		if (!result) return [];
		return result.hosts.filter(h => h.alive);
	}

	function getUnreachableHosts(): ScanHost[] {
		if (!result) return [];
		return result.hosts.filter(h => !h.alive);
	}

	function validateTargets(): string | null {
		const err = validateScanTarget(targets);
		targetsError = err || '';
		return err;
	}

	async function startScan() {
		const err = validateTargets();
		if (err) {
			addToast('error', m['scanner.Invalid Range']());
			return;
		}

		scanning = true;
		scanController = new AbortController();
		result = null;
		scanError = '';
		selectedIps = new Set();
		deviceTypes = {};
		deviceNames = {};
		deviceDescriptions = {};
		deviceBrands = {};
		deviceLocations = {};
		autoDetectedFields = {};
		showAllUnreachable = false;
		aliveOffset = 0;

		try {
			const res = await api.post<ScanResponse>('/scanner/scan', {
				targets: targets.trim(),
				community: community || 'public',
				timeout: timeout || 2,
				credential_id: selectedCredentialId ?? undefined
			}, scanController?.signal);
			result = res;

			// Initialize form fields for alive hosts, pre-fill from enriched data
			for (const host of res.hosts.filter(h => h.alive)) {
				const detected = new Set<string>();

				// Device type
				if (host.inferred_type && (DEVICE_TYPES as readonly string[]).includes(host.inferred_type)) {
					deviceTypes[host.ip] = host.inferred_type;
					detected.add('type');
				} else {
					deviceTypes[host.ip] = 'other';
				}

				// Device name
				if (host.inferred_brand || host.snmp_name) {
					deviceNames[host.ip] = host.snmp_name || host.inferred_brand || host.ip;
					if (host.snmp_name) detected.add('name');
				} else {
					deviceNames[host.ip] = host.ip;
				}

				// Description
				if (host.inferred_description) {
					deviceDescriptions[host.ip] = host.inferred_description;
					detected.add('description');
				}

				// Brand
				if (host.inferred_brand) {
					deviceBrands[host.ip] = host.inferred_brand;
					detected.add('brand');
				}

				// Location
				if (host.inferred_location) {
					deviceLocations[host.ip] = host.inferred_location;
					detected.add('location');
				}

				if (detected.size > 0) {
					autoDetectedFields[host.ip] = detected;
				}
			}

			addToast('success', m['scanner.Scan Complete']());
		} catch (err) {
			// User-triggered cancel: the toast was already shown by cancelScan;
			// don't also surface a generic error banner.
			if (err instanceof RequestCancelledError) return;
			// Inline banner so the user sees the failure in context (not just a
			// corner toast) — the result pane stays empty otherwise.
			scanError = getErrorMessage(err);
			addToast('error', scanError);
		} finally {
			scanning = false;
			scanController = null;
		}
	}

	// Abort the in-flight scan. The backend honors request-context cancellation,
	// so the server actually stops probing (#153).
	function cancelScan() {
		if (!scanController) return;
		scanController.abort();
		scanController = null;
		addToast('info', m['scanner.Scan Cancelled']());
	}

	function toggleSelect(ip: string) {
		const next = new Set(selectedIps);
		if (next.has(ip)) {
			next.delete(ip);
		} else {
			next.add(ip);
		}
		selectedIps = next;
	}

	function selectAll() {
		selectedIps = new Set(getAliveHosts().map(h => h.ip));
	}

	function deselectAll() {
		selectedIps = new Set();
	}

	// addSelected is the entry point from the "Add Selected" button. For
	// selections >10 it opens the confirm dialog and stops; the actual add is
	// done by performAdd when the user confirms. Previously both paths went
	// through one function guarded by `!confirmAddOpen`, which any future
	// caller of addSelected() could trip to bypass the confirm gate. Splitting
	// the two intents makes the confirm unavoidable.
	function addSelected() {
		if (selectedIps.size === 0) return;
		if (selectedIps.size > 10) {
			confirmAddOpen = true;
			return;
		}
		performAdd();
	}

	async function performAdd() {
		adding = true;
		try {
			const devices = getAliveHosts()
				.filter(h => selectedIps.has(h.ip))
				.map(h => {
					const device: Record<string, string> = {
						ip: h.ip,
						name: deviceNames[h.ip] || h.ip,
						type: deviceTypes[h.ip] || 'other'
					};
					if (deviceDescriptions[h.ip]) device.description = deviceDescriptions[h.ip];
					if (deviceBrands[h.ip]) device.brand = deviceBrands[h.ip];
					if (deviceLocations[h.ip]) device.location = deviceLocations[h.ip];
					return device;
				});

			const res = await api.post<AddDevicesResponse>('/scanner/add-devices', { devices });

			if (res.errors && res.errors.length > 0) {
				// Single summary warning (count + first reason) instead of one
				// toast per failure — floods the toast stack when many devices
				// fail (e.g. duplicates). Matches the CSV-import path. #152 part 3.
				addToast('warning', m['scanner.Add N Failed']().replace('{count}', String(res.errors.length)).replace('{reason}', res.errors[0]));
			}

			if (res.added > 0) {
				addToast('success', m['scanner.Added N Devices']().replace('{count}', String(res.added)));
				deselectAll();
			}
		} catch (err) {
			addToast('error', getErrorMessage(err));
		} finally {
			adding = false;
		}
	}
</script>

<div class="p-6 space-y-6">
	<!-- Header -->
	<div>
		<h2 class="text-2xl font-bold text-primary">{m['scanner.Scanner']()}</h2>
		<p class="text-sm text-muted mt-1">
			{m['scanner.Select Devices']()}
		</p>
	</div>

	<!-- Scan Form -->
	<div class="bg-surface border border-border rounded-lg p-5 space-y-4">
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<div class="md:col-span-1">
				<label class="label text-sm">{m['scanner.Targets']()}</label>
				<input
					type="text"
					bind:value={targets}
					placeholder={m['scanner.Targets Placeholder']()}
					class="input {targetsError ? 'input-error' : ''}"
					disabled={scanning}
					onblur={validateTargets}
				/>
				{#if targetsError}
					<p class="form-error">{targetsError}</p>
				{/if}
			</div>
			<div>
				<label class="label text-sm">{m['scanner.Community']()}</label>
				<input
					type="text"
					bind:value={community}
					placeholder="public"
					class="input"
					disabled={scanning || selectedCredentialId !== null}
				/>
				{#if selectedCredentialId !== null}
					<p class="text-xs text-text-muted mt-1">Overridden by selected credential</p>
				{/if}
			</div>
			{#if credentials.length > 0}
				<div>
					<label class="label text-sm">{m['snmpCredentials.Title']()}</label>
					<select
						bind:value={selectedCredentialId}
						class="input"
						disabled={scanning}
					>
						<option value={null}>{m['snmpCredentials.Community']()} ({community || 'public'})</option>
						{#each credentials as c (c.id)}
							<option value={c.id}>{c.name} ({c.security_level})</option>
						{/each}
					</select>
				</div>
			{/if}
			<div>
				<label class="label text-sm">{m['scanner.Timeout']()}</label>
				<input
					type="number"
					bind:value={timeout}
					min="1"
					max="10"
					class="input"
					disabled={scanning}
				/>
			</div>
		</div>
		<div>
			<button
				onclick={startScan}
				disabled={scanning}
				class="btn btn-primary"
			>
				{#if scanning}
					<LoaderCircle class="w-4 h-4 animate-spin" />
					{m['scanner.Scanning']()}
				{:else}
					{m['scanner.Start Scan']()}
				{/if}
			</button>
			{#if scanning}
				<button
					onclick={cancelScan}
					class="btn btn-danger"
					title={m['common.Cancel']()}
				>
					<CircleStop class="w-4 h-4" />
					{m['common.Cancel']()}
				</button>
			{/if}
		</div>
	</div>

	<!-- Results -->
	{#if scanError}
		<div class="px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error mb-4" aria-live="polite">
			{scanError}
		</div>
	{:else if result}
		<!-- Summary -->
		<div class="grid grid-cols-3 gap-4">
			<div class="stat-card text-center">
				<div class="stat-value text-primary">{result.total}</div>
				<div class="stat-label">{m['scanner.Total Hosts']()}</div>
			</div>
			<div class="stat-card text-center">
				<div class="stat-value text-success">{result.alive}</div>
				<div class="stat-label">{m['scanner.Alive Hosts']()}</div>
			</div>
			<div class="stat-card text-center">
				<div class="stat-value text-text">{result.duration_ms} {m['scanner.ms']()}</div>
				<div class="stat-label">{m['scanner.Duration']()}</div>
			</div>
		</div>

		<!-- Action bar (only if alive hosts) -->
		{#if getAliveHosts().length > 0}
			<div class="flex items-center gap-3">
				<button
					onclick={selectAll}
					class="btn btn-secondary text-xs py-1.5"
				>
					{m['scanner.Select All']()}
				</button>
				<button
					onclick={deselectAll}
					class="btn btn-secondary text-xs py-1.5"
				>
					{m['scanner.Deselect All']()}
				</button>
				<span class="text-sm text-muted">
					{selectedIps.size} / {getAliveHosts().length}
				</span>
				<div class="flex-1"></div>
				<button
					onclick={addSelected}
					disabled={selectedIps.size === 0 || adding}
					class="btn btn-primary"
				>
					{#if adding}
						{m['common.Loading']()}...
					{:else}
						{m['scanner.Add Selected']()} ({selectedIps.size})
					{/if}
				</button>
			</div>

			<!-- Results Table -->
			<div class="bg-surface border border-border rounded-lg overflow-x-auto">
				<table class="w-full text-sm">
					<thead>
						<tr class="border-b border-border bg-bg">
							<th class="px-3 py-2 text-left w-10"></th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['scanner.IP Address']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['scanner.Status']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['scanner.RTT']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['scanner.SNMP Info']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['scanner.Device Name']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['scanner.Device Type']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['devices.Brand']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['devices.Description']()}</th>
							<th class="px-3 py-2 text-left text-xs font-medium text-muted uppercase">{m['devices.Location']()}</th>
						</tr>
					</thead>
					<tbody>
						{#each getAliveHosts().slice(aliveOffset, aliveOffset + aliveLimit) as host (host.ip)}
							{@const autoFields = autoDetectedFields[host.ip] || new Set<string>()}
							<tr class="border-b border-border hover:bg-bg/50 transition-colors">
								<td class="px-3 py-2">
									<input
										type="checkbox"
										checked={selectedIps.has(host.ip)}
										onchange={() => toggleSelect(host.ip)}
										class="rounded border-border text-primary focus:ring-primary"
									/>
								</td>
								<td class="px-3 py-2 font-mono text-text">{host.ip}</td>
								<td class="px-3 py-2">
									<span class="inline-flex items-center gap-1 text-success">
										<span class="w-2 h-2 bg-success rounded-full"></span>
										{m['scanner.Alive']()}
									</span>
								</td>
								<td class="px-3 py-2 text-muted">{host.rtt_ms} {m['scanner.ms']()}</td>
								<td class="px-3 py-2">
									{#if host.snmp_success}
										<div class="text-text text-xs">{host.snmp_name || '-'}</div>
										<div class="text-muted text-xs truncate max-w-[200px]">{host.snmp_descr || '-'}</div>
									{:else}
										<span class="text-muted">-</span>
									{/if}
								</td>
								<!-- Device Name -->
								<td class="px-3 py-2">
									<div class="relative">
										<input
											type="text"
											bind:value={deviceNames[host.ip]}
											class="w-full px-2 py-1 text-xs bg-bg border border-border rounded text-text focus:outline-none focus:border-primary"
										/>
										{#if autoFields.has('name')}
											<span class="auto-badge">{m['scanner.Auto Detected']()}</span>
										{/if}
									</div>
								</td>
								<!-- Device Type -->
								<td class="px-3 py-2">
									<div class="relative">
										<select
											bind:value={deviceTypes[host.ip]}
											class="px-2 py-1 text-xs bg-bg border border-border rounded text-text focus:outline-none focus:border-primary"
										>
											{#each DEVICE_TYPES as type}
												<option value={type}>{getDeviceTypeLabel(type)}</option>
											{/each}
										</select>
										{#if autoFields.has('type')}
											<span class="auto-badge">{m['scanner.Auto Detected']()}</span>
										{/if}
									</div>
								</td>
								<!-- Brand -->
								<td class="px-3 py-2">
									<div class="relative">
										<input
											type="text"
											bind:value={deviceBrands[host.ip]}
											placeholder="-"
											class="w-full px-2 py-1 text-xs bg-bg border border-border rounded text-text focus:outline-none focus:border-primary"
										/>
										{#if autoFields.has('brand')}
											<span class="auto-badge">{m['scanner.Auto Detected']()}</span>
										{/if}
									</div>
								</td>
								<!-- Description -->
								<td class="px-3 py-2">
									<div class="relative">
										<input
											type="text"
											bind:value={deviceDescriptions[host.ip]}
											placeholder="-"
											class="w-full px-2 py-1 text-xs bg-bg border border-border rounded text-text focus:outline-none focus:border-primary"
										/>
										{#if autoFields.has('description')}
											<span class="auto-badge">{m['scanner.Auto Detected']()}</span>
										{/if}
									</div>
								</td>
								<!-- Location -->
								<td class="px-3 py-2">
									<div class="relative">
										<input
											type="text"
											bind:value={deviceLocations[host.ip]}
											placeholder="-"
											class="w-full px-2 py-1 text-xs bg-bg border border-border rounded text-text focus:outline-none focus:border-primary"
										/>
										{#if autoFields.has('location')}
											<span class="auto-badge">{m['scanner.Auto Detected']()}</span>
										{/if}
									</div>
								</td>
							</tr>
						{/each}

						<!-- Unreachable hosts section -->
							{#if getUnreachableHosts().length > 0}
								<tr class="border-t border-border">
									<td colspan="10" class="px-3 py-2">
										<div class="flex items-center gap-2 text-xs text-muted">
											<span class="w-2 h-2 bg-error rounded-full"></span>
											{m['scanner.Unreachable Hosts']().replace('{count}', String(getUnreachableHosts().length))}
										</div>
									</td>
								</tr>
							{/if}
							{#each (showAllUnreachable ? getUnreachableHosts() : getUnreachableHosts().slice(0, 5)) as host (host.ip)}
								<tr class="border-b border-border opacity-50">
									<td class="px-3 py-2"></td>
									<td class="px-3 py-2 font-mono text-muted">{host.ip}</td>
									<td class="px-3 py-2">
										<span class="inline-flex items-center gap-1 text-error">
											<span class="w-2 h-2 bg-error rounded-full"></span>
											{m['scanner.Unreachable']()}
										</span>
									</td>
									<td class="px-3 py-2 text-muted" colspan="6">-</td>
								</tr>
							{/each}
							{#if getUnreachableHosts().length > 5}
								<tr class="border-b border-border">
									<td colspan="10" class="px-3 py-2 text-center">
										<button
											onclick={() => { showAllUnreachable = !showAllUnreachable; }}
											class="text-xs text-primary hover:underline cursor-pointer"
										>
											{showAllUnreachable
												? m['scanner.Show Less Unreachable']()
												: m['scanner.Show All Unreachable']().replace('{count}', String(getUnreachableHosts().length))}
										</button>
									</td>
								</tr>
							{/if}
					</tbody>
					</table>
				</div>

				{#if getAliveHosts().length > aliveLimit}
					<p class="text-xs text-muted italic mt-1 mb-1">{m['scanner.Large Range Hint']()}</p>
					<Pagination
						total={getAliveHosts().length}
						limit={aliveLimit}
						offset={aliveOffset}
						onPageChange={(o) => (aliveOffset = o)}
						onPageSizeChange={(n) => { aliveLimit = n; aliveOffset = 0; }}
					/>
				{/if}
		{:else}
			<div class="bg-surface border border-border rounded-lg">
				<EmptyState
					icon={Radar}
					title={m['scanner.No Alive Hosts']()}
					description={m['scanner.No Alive Hosts Desc']()}
				/>
			</div>
		{/if}
	{/if}
</div>

<!-- Confirm bulk add dialog -->
	<ConfirmDialog
		bind:open={confirmAddOpen}
		title={m['scanner.Confirm Add Title']()}
		message={m['scanner.Confirm Add Message']().replace('{count}', String(selectedIps.size))}
		confirmLabel={m['scanner.Add Selected']()}
		onConfirm={performAdd}
		onCancel={() => { confirmAddOpen = false; }}
	/>

<style>
	.auto-badge {
		display: inline-block;
		margin-top: 2px;
		padding: 0 4px;
		font-size: 9px;
		line-height: 14px;
		font-weight: 600;
		letter-spacing: 0.02em;
		color: var(--color-primary);
		background: color-mix(in srgb, var(--color-primary) 12%, transparent);
		border-radius: var(--radius-sm);
		white-space: nowrap;
		pointer-events: none;
		user-select: none;
	}
</style>
