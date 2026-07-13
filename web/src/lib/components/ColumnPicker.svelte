<script lang="ts">
	/**
	 * ColumnPicker — a dropdown of checkboxes that lets the user choose which
	 * optional columns a table shows. Selections persist to localStorage so the
	 * choice survives reloads and shared links.
	 *
	 * The parent owns the actual column rendering; this component is purely the
	 * selection UI + persistence. Bind `selected` for two-way binding.
	 */

	interface OptionalColumn {
		/** Stable key persisted to localStorage. Never rename (breaks storage). */
		key: string;
		/** Label shown in the picker dropdown. */
		label: string;
	}

	interface Props {
		columns: OptionalColumn[];
		/** Keys currently selected. Use bind:selected for two-way. */
		selected: Set<string>;
		storageKey: string;
		/** Defaults applied on first visit (no localStorage entry yet). */
		defaults: string[];
		label?: string;
	}

	let {
		columns,
		selected = $bindable(new Set<string>()),
		storageKey,
		defaults,
		label = 'Columns'
	}: Props = $props();

	let open = $state(false);
	let container: HTMLElement | null = $state(null);

	// Load persisted selection on mount (client-only). If nothing is stored,
	// seed from `defaults` and persist so the choice is stable from then on.
	$effect(() => {
		if (typeof localStorage === 'undefined') return;
		const stored = localStorage.getItem(storageKey);
		if (stored === null) {
			selected = new Set(defaults);
			localStorage.setItem(storageKey, JSON.stringify(defaults));
		} else {
			try {
				const arr = JSON.parse(stored) as string[];
				selected = new Set(arr);
			} catch {
				selected = new Set(defaults);
			}
		}
	});

	function persist() {
		if (typeof localStorage === 'undefined') return;
		localStorage.setItem(storageKey, JSON.stringify([...selected]));
	}

	function toggle(key: string) {
		const next = new Set(selected);
		if (next.has(key)) next.delete(key);
		else next.add(key);
		// Refuse to remove the very last column — an empty table is a bad UX.
		if (next.size === 0) return;
		selected = next;
		persist();
	}

	function reset() {
		selected = new Set(defaults);
		persist();
	}

	function handleOutsideClick(e: MouseEvent) {
		if (container && !container.contains(e.target as Node)) open = false;
	}
</script>

<svelte:window on:click={handleOutsideClick} />

<div class="relative" bind:this={container}>
	<button
		type="button"
		class="inline-flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-md border border-border bg-surface hover:bg-primary/10 transition-colors text-text"
		onclick={(e) => {
			e.stopPropagation();
			open = !open;
		}}
		aria-expanded={open}
		aria-haspopup="true"
	>
		<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h10M4 18h7" />
		</svg>
		<span>{label}</span>
		<svg class="w-3.5 h-3.5 transition-transform {open ? 'rotate-180' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
		</svg>
	</button>

	{#if open}
		<div
			class="absolute right-0 z-30 mt-1 w-56 rounded-lg border border-border bg-surface shadow-lg"
			onclick={(e) => e.stopPropagation()}
			role="menu"
		>
			<div class="flex items-center justify-between px-3 py-2 border-b border-border">
				<span class="text-xs font-medium text-muted">{label}</span>
				<button
					type="button"
					class="text-xs text-accent hover:underline"
					onclick={reset}
				>Reset</button>
			</div>
			<ul class="max-h-64 overflow-y-auto py-1">
				{#each columns as col (col.key)}
					{@const checked = selected.has(col.key)}
					<li>
						<label
							class="flex items-center gap-2.5 px-3 py-1.5 cursor-pointer hover:bg-primary/5 transition-colors"
						>
							<input
								type="checkbox"
								checked={checked}
								onchange={() => toggle(col.key)}
								class="w-4 h-4 rounded border-border text-primary focus:ring-primary"
							/>
							<span class="text-sm text-text">{col.label}</span>
						</label>
					</li>
				{/each}
			</ul>
		</div>
	{/if}
</div>
