<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Search, X, ChevronUp, ChevronDown, Inbox } from '@lucide/svelte';
	import { m } from '$lib/i18n-paraglide';

	interface Column {
		key: string;
		label: string;
		sortable?: boolean;
		/** Marks a column whose cells are rendered by the `cell` snippet (real
		 * <button>/<input> with bound handlers) instead of `render`'s {@html}
		 * string — the keyboard-accessible path (#167). */
		interactive?: boolean;
		/**
		 * Custom cell renderer. The returned string is injected via `{@html}`, so
		 * the caller is responsible for escaping EVERY user-controlled value
		 * (device name, username, MAC, URL, …) — otherwise a value containing
		 * `<` is an XSS vector.
		 *
		 * Build the string with the `html` tagged-template helper
		 * (`$lib/utils/index`): it auto-escapes interpolations while leaving
		 * markup intact, so the safe default is also the easy one:
		 *   render: (row) => html`<span class="font-medium">${row.name}</span>`
		 * Raw string concatenation is allowed only if the caller escapes each
		 * user-controlled interpolation with `escapeHtml`/`escapeAttr` (see
		 * `devices/+page.svelte` for the manual pattern).
		 */
		render?: (row: Record<string, unknown>) => string;
	}

	let {
		columns,
		rows,
		searchPlaceholder = m['common.Search']() + '...',
		searchableKeys = [],
		initialSearch = '',
		emptyTitle = m['common.No Data'](),
		emptyDescription = '',
		emptyAction,
		emptyActionLabel,
		id,
		expandedRowId,
		expandedContent,
		// Interactive-cell snippet: when a column has `interactive: true`, its
		// cells render via {@render cell(row, col)} (real Svelte elements with
		// bound handlers) instead of col.render's {@html} string (#167).
		cell,
		// Controlled sorting: when onSortChange is provided, the table runs in
		// "server-side sort" mode — column clicks call back instead of sorting the
		// in-memory rows (which would only reorder the current page and disagree
		// with server-side pagination). externalSortKey/Dir drive the arrow display.
		externalSortKey = null,
		externalSortDirection = 'none',
		onSortChange,
		// Controlled search: when onSearchChange is provided, the search box calls
		// back to the parent (which refetches filtered from the server) instead of
		// filtering the in-memory page slice. Mirrors the onSortChange server-side
		// pattern. Without it, search stays client-side (backward-compatible).
		onSearchChange,
	}: {
		columns: Column[];
		rows: Record<string, unknown>[];
		searchPlaceholder?: string;
		searchableKeys?: string[];
		initialSearch?: string;
		emptyTitle?: string;
		emptyDescription?: string;
		emptyAction?: () => void;
		emptyActionLabel?: string;
		id?: string;
		expandedRowId?: number | null;
		expandedContent?: Snippet<[Record<string, unknown>]>;
		cell?: Snippet<[Record<string, unknown>, Column]>;
		externalSortKey?: string | null;
		externalSortDirection?: 'asc' | 'desc' | 'none';
		onSortChange?: (key: string, direction: 'asc' | 'desc') => void;
		onSearchChange?: (query: string) => void;
	} = $props();

	let sortKey = $state<string | null>(null);
	let sortDirection = $state<'asc' | 'desc' | 'none'>('none');
	// Seed the search box from the initialSearch prop (e.g. a ?search=... URL
	// param) so deep links like the "View Device" button land on a filtered list.
	let searchQuery = $state(initialSearch);
	let debouncedQuery = $state(initialSearch);
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;

	// When sorting is server-controlled, mirror the external state so the arrow
	// indicators follow what the server actually returned (not local clicks).
	const displaySortKey = $derived(onSortChange ? externalSortKey : sortKey);
	const displaySortDir = $derived(onSortChange ? externalSortDirection : sortDirection);

	$effect(() => {
		if (debounceTimer) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => {
			debouncedQuery = searchQuery;
		}, 300);
		return () => {
			if (debounceTimer) clearTimeout(debounceTimer);
		};
	});

	const filteredRows = $derived(() => {
		// Server-driven search/sort: rows already come back filtered/ordered from
		// the backend, so don't re-filter the page slice client-side (it would
		// double-narrow results). Mirrors the onSortChange guard.
		if (onSortChange || onSearchChange) return rows;
		if (!debouncedQuery || searchableKeys.length === 0) return rows;
		const q = debouncedQuery.toLowerCase();
		return rows.filter((row) =>
			searchableKeys.some((key) => {
				const val = row[key];
				return val != null && String(val).toLowerCase().includes(q);
			})
		);
	});

	const sortedRows = $derived(() => {
		const data = filteredRows();
		// Server-side sort: rows already come back ordered; don't reshuffle.
		if (onSortChange) return data;
		if (!sortKey || sortDirection === 'none') return data;

		return [...data].sort((a, b) => {
			const aVal = a[sortKey];
			const bVal = b[sortKey];
			if (aVal == null && bVal == null) return 0;
			if (aVal == null) return 1;
			if (bVal == null) return -1;

			const aStr = String(aVal);
			const bStr = String(bVal);
			const cmp = aStr.localeCompare(bStr, undefined, { numeric: true, sensitivity: 'base' });
			return sortDirection === 'asc' ? cmp : -cmp;
		});
	});

	const displayRows = $derived(sortedRows());
	const isEmpty = $derived(displayRows.length === 0 && rows.length > 0);
	const isTotallyEmpty = $derived(rows.length === 0);

	function handleSort(key: string) {
		if (onSortChange) {
			// Server-side sort: cycle asc → desc (no "none" — a server-backed list
			// always has an order), and hand the decision up.
			const nextDir: 'asc' | 'desc' =
				externalSortKey === key && externalSortDirection === 'asc' ? 'desc' : 'asc';
			onSortChange(key, nextDir);
			return;
		}
		// Local three-state sort (unchanged behaviour for callers not opting in).
		if (sortKey === key) {
			sortDirection = sortDirection === 'asc' ? 'desc' : sortDirection === 'desc' ? 'none' : 'asc';
		} else {
			sortKey = key;
			sortDirection = 'asc';
		}
		if (sortDirection === 'none') {
			sortKey = null;
		}
	}
</script>

<div {id} class="w-full">
	<!-- Search bar -->
	{#if searchableKeys.length > 0}
		<div class="mb-3">
			<div class="relative">
				<Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted pointer-events-none" />
				<input
					type="text"
					bind:value={searchQuery}
					oninput={() => onSearchChange?.(searchQuery)}
					placeholder={searchPlaceholder}
					data-search-shortcut
					aria-label={searchPlaceholder}
					class="input pl-10 pr-10"
				/>
				{#if searchQuery}
					<button
						onclick={() => { searchQuery = ''; onSearchChange?.(''); }}
						class="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text transition-colors"
						aria-label={m['common.Clear Search']()}
					>
						<X class="w-4 h-4" />
					</button>
				{/if}
			</div>
		</div>
	{/if}

	<!-- Table -->
	{#if !isTotallyEmpty}
		<div class="overflow-x-auto rounded-lg border border-border">
			<table role="table" class="w-full">
				<thead>
					<tr class="border-b border-border text-left text-xs text-muted bg-surface">
						{#each columns as col}
							<th
								scope="col"
								class="px-4 py-3 {col.sortable ? 'cursor-pointer select-none hover:text-text' : ''}"
								class:whitespace-nowrap={true}
								aria-sort={col.sortable
									? (displaySortKey === col.key
										? (displaySortDir === 'asc' ? 'ascending' : displaySortDir === 'desc' ? 'descending' : 'none')
										: 'none')
									: undefined}
							>
								{#if col.sortable}
									<button
										class="inline-flex items-center gap-1.5"
										onclick={() => handleSort(col.key)}
									>
										{col.label}
								<span class="inline-flex flex-col ml-0.5 text-[0.6rem] leading-none">
												<ChevronUp class="w-3 h-2.5 {displaySortKey === col.key && displaySortDir === 'asc' ? 'text-primary' : 'opacity-30'}" />
												<ChevronDown class="w-3 h-2.5 -mt-0.5 {displaySortKey === col.key && displaySortDir === 'desc' ? 'text-primary' : 'opacity-30'}" />
										</span>
									</button>
								{:else}
									{col.label}
								{/if}
							</th>
						{/each}
					</tr>
				</thead>
				<tbody>
					{#if isEmpty}
						<tr>
							<td colspan={columns.length} class="px-4 py-8 text-center text-sm text-muted">
								<div class="flex flex-col items-center gap-1">
									<Search class="w-7 h-7 mb-1 opacity-40" />
									<span>{m['common.No Results']()}</span>
								</div>
							</td>
						</tr>
					{:else}
						{#each displayRows as row, i}
							<tr class="border-b border-border last:border-b-0 hover:bg-surface-2 transition-colors">
								{#each columns as col, colIndex}
							<td class="px-4 py-3 text-sm" scope={colIndex === 0 ? 'row' : undefined}>
								{#if col.interactive && cell}
									{@render cell(row, col)}
								{:else if col.render}
									{@html col.render(row)}
								{:else}
									<span class="text-text">{row[col.key] != null ? String(row[col.key]) : '-'}</span>
								{/if}
							</td>
							{/each}
						</tr>
						{#if expandedRowId != null && row.id === expandedRowId && expandedContent}
						<tr>
							<td colspan={columns.length} class="p-0">
								{@render expandedContent(row)}
							</td>
						</tr>
						{/if}
					{/each}
				{/if}
			</tbody>
			</table>
		</div>
	{/if}

	<!-- Empty state — no rows at all -->
	{#if isTotallyEmpty}
		<div class="flex flex-col items-center justify-center py-12 px-4 text-center">
			<Inbox class="w-12 h-12 mb-3 text-muted opacity-40" strokeWidth={1.5} />
			<h3 class="text-sm font-medium text-text mb-1">{emptyTitle}</h3>
			{#if emptyDescription}
				<p class="text-xs text-muted mb-4">{emptyDescription}</p>
			{/if}
			{#if emptyAction && emptyActionLabel}
				<button onclick={emptyAction} class="btn btn-primary">
					{emptyActionLabel}
				</button>
			{/if}
		</div>
	{/if}
</div>
