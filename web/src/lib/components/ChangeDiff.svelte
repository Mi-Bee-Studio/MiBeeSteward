<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	/**
	 * ChangeDiff — renders the full before/after data of a ChangeLogEntry.
	 *
	 * Three shapes:
	 *  - device_added: `after_data` = full DeviceSnapshot → render as a property table.
	 *  - device_lost:  `before_data` = full DeviceSnapshot → render as a property table.
	 *  - device_changed: `before_data` / `after_data` = full DeviceSnapshots →
	 *    diffed client-side into changed fields → render a side-by-side old→new
	 *    comparison table (red old / green new). Legacy entries whose `after_data`
	 *    is already a {field: [old, new]} diff map are still supported.
	 *
	 * Long string values (JSON columns like open_ports / scan_attributes) are
	 * pretty-printed for readability.
	 */

	import { m } from '$lib/i18n-paraglide';
	import { buildDiff, tryParse, type Snapshot } from '$lib/changesDiff';

	interface Props {
		changeType: string;
		beforeData?: string;
		afterData?: string;
	}

	let { changeType, beforeData, afterData }: Props = $props();

	const diff = $derived(changeType === 'device_changed' ? buildDiff(beforeData, afterData) : null);
	const snapshot = $derived(
		changeType === 'device_changed'
			? null
			: (tryParse(changeType === 'device_added' ? afterData : beforeData) as Snapshot | null)
	);

	// Pretty-format a single value: JSON-parse strings that look like JSON,
	// stringify objects, truncate very long single-line values.
	function fmt(v: unknown): string {
		if (v === null || v === undefined) return '-';
		if (typeof v === 'string') {
			if ((v.startsWith('{') && v.endsWith('}')) || (v.startsWith('[') && v.endsWith(']'))) {
				try {
					return JSON.stringify(JSON.parse(v), null, 2);
				} catch {
					/* fall through */
				}
			}
			return v || '-';
		}
		if (typeof v === 'object') {
			try {
				return JSON.stringify(v, null, 2);
			} catch {
				return String(v);
			}
		}
		return String(v);
	}

	// Is a value "large" (worth rendering in a <pre> block)?
	function isLarge(v: unknown): boolean {
		return fmt(v).length > 40 || fmt(v).includes('\n');
	}

	// Friendly labels for the diff field keys (the DeviceSnapshot field names),
	// backed by the changefields.* i18n section so they localize. Unknown keys
	// fall back to the raw field name rather than disappearing. The map is
	// rebuilt on each call so a locale switch reflects immediately.
	function labelFor(key: string): string {
		const labels: Record<string, string> = {
			name: m['changefields.name'](),
			type: m['changefields.type'](),
			brand: m['changefields.brand'](),
			model: m['changefields.model'](),
			mac_address: m['changefields.mac_address'](),
			ip_address: m['changefields.ip_address'](),
			status: m['changefields.status'](),
			open_ports: m['changefields.open_ports'](),
			detected_services: m['changefields.detected_services'](),
			prometheus_url: m['changefields.prometheus_url'](),
			node_exporter_url: m['changefields.node_exporter_url'](),
			scan_attributes: m['changefields.scan_attributes']()
		};
		return labels[key] ?? key;
	}
</script>

<div class="text-sm">
	{#if diff}
		<!-- device_changed: field-by-field old → new comparison -->
		{#if Object.keys(diff).length === 0}
			<p class="text-text-muted italic text-xs">{m['changes.Diff No Field Changes']()}</p>
		{:else}
			<table class="w-full text-left border-collapse">
				<thead>
					<tr class="border-b border-border">
						<th class="py-1.5 pr-3 text-xs font-medium text-text-muted uppercase tracking-wide w-1/4">{m['changes.Diff Field']()}</th>
						<th class="py-1.5 pr-3 text-xs font-medium text-text-muted uppercase tracking-wide">{m['changes.Diff Before']()}</th>
						<th class="py-1.5 text-xs font-medium text-text-muted uppercase tracking-wide">{m['changes.Diff After']()}</th>
					</tr>
				</thead>
				<tbody>
					{#each Object.entries(diff) as [field, values]}
						{@const [oldV, newV] = values as [unknown, unknown]}
						{@const oldS = fmt(oldV)}
						{@const newS = fmt(newV)}
						{@const changed = oldS !== newS}
						<tr class="border-b border-border/50 align-top">
							<td class="py-2 pr-3 font-mono text-xs text-text">{labelFor(field)}</td>
							<td class="py-2 pr-3">
								{#if isLarge(oldV)}
									<pre class="text-xs text-error/80 bg-error/5 border border-error/20 rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{oldS}</pre>
								{:else}
									<span class="font-mono text-xs {changed ? 'text-error line-through opacity-70' : 'text-text-muted'}">{oldS}</span>
								{/if}
							</td>
							<td class="py-2">
								{#if isLarge(newV)}
									<pre class="text-xs text-success bg-success/5 border border-success/20 rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{newS}</pre>
								{:else}
									<span class="font-mono text-xs {changed ? 'text-success font-medium' : 'text-text-muted'}">{newS}</span>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	{:else if snapshot}
		<!-- device_added / device_lost: full snapshot property table -->
		{#if Object.keys(snapshot).length === 0}
			<p class="text-text-muted italic text-xs">{m['changes.Diff No Snapshot']()}</p>
		{:else}
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
				{#each Object.entries(snapshot) as [field, value]}
					<div class="flex flex-col gap-0.5 border-b border-border/30 pb-1.5">
						<span class="text-[10px] text-text-muted uppercase tracking-wide">{labelFor(field)}</span>
						{#if isLarge(value)}
							<pre class="text-xs text-text bg-bg/50 border border-border rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-32">{fmt(value)}</pre>
						{:else}
							<span class="text-xs text-text font-mono break-all">{fmt(value)}</span>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	{:else}
		<p class="text-text-muted italic text-xs">{m['changes.Diff No Data']()}</p>
	{/if}
</div>
