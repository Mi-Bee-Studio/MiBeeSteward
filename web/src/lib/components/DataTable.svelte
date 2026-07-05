<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Search, X, ChevronUp, ChevronDown, Inbox } from '@lucide/svelte';

	interface Column {
		key: string;
		label: string;
		sortable?: boolean;
		render?: (row: Record<string, unknown>) => string;
	}

	let {
		columns,
		rows,
		searchPlaceholder = 'Search...',
		searchableKeys = [],
		initialSearch = '',
		emptyTitle = 'No data',
		emptyDescription = '',
		emptyAction,
		emptyActionLabel,
		id,
		expandedRowId,
		expandedContent,
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
	} = $props();

	let sortKey = $state<string | null>(null);
	let sortDirection = $state<'asc' | 'desc' | 'none'>('none');
	// Seed the search box from the initialSearch prop (e.g. a ?search=... URL
	// param) so deep links like the "View Device" button land on a filtered list.
	let searchQuery = $state(initialSearch);
	let debouncedQuery = $state(initialSearch);
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;

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
					placeholder={searchPlaceholder}
					class="input pl-10 pr-10"
				/>
				{#if searchQuery}
					<button
						onclick={() => (searchQuery = '')}
						class="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text transition-colors"
						aria-label="Clear search"
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
							<th scope="col" class="px-4 py-3 {col.sortable ? 'cursor-pointer select-none hover:text-text' : ''}" class:whitespace-nowrap={true}>
								{#if col.sortable}
									<button
										class="inline-flex items-center gap-1.5"
										onclick={() => handleSort(col.key)}
									>
										{col.label}
										<span class="inline-flex flex-col ml-0.5 text-[0.6rem] leading-none">
											<ChevronUp class="w-3 h-2.5 {sortKey === col.key && sortDirection === 'asc' ? 'text-primary' : 'opacity-30'}" />
											<ChevronDown class="w-3 h-2.5 -mt-0.5 {sortKey === col.key && sortDirection === 'desc' ? 'text-primary' : 'opacity-30'}" />
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
									<span>No results found</span>
								</div>
							</td>
						</tr>
					{:else}
						{#each displayRows as row, i}
							<tr class="border-b border-border last:border-b-0 hover:bg-surface-2 transition-colors">
								{#each columns as col, colIndex}
							<td class="px-4 py-3 text-sm" scope={colIndex === 0 ? 'row' : undefined}>
								{#if col.render}
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
