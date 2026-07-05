<script lang="ts">
	import { ChevronLeft, ChevronRight } from '@lucide/svelte';

	let { total, limit, offset, onPageChange }: {
		total: number;
		limit: number;
		offset: number;
		onPageChange: (offset: number) => void;
	} = $props();

	let jumpInput = $state('');

	const totalPages = $derived(Math.ceil(total / limit));
	const currentPage = $derived(Math.floor(offset / limit) + 1);
	const start = $derived(offset + 1);
	const end = $derived(Math.min(offset + limit, total));
	const showJumpInput = $derived(totalPages > 5);

	function goPrev() {
		if (offset > 0) onPageChange(Math.max(0, offset - limit));
	}

	function goNext() {
		if (offset + limit < total) onPageChange(offset + limit);
	}

	function handleJumpKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') {
			const page = parseInt(jumpInput, 10);
			if (page >= 1 && page <= totalPages) {
				onPageChange((page - 1) * limit);
			}
			jumpInput = '';
		}
	}
</script>

{#if total > limit}
	<div class="flex items-center justify-between gap-4 px-1 py-2">
		<!-- Range display -->
		<span class="text-xs text-muted whitespace-nowrap">
			Showing {start}–{end} of {total}
		</span>

		<!-- Controls -->
		<div class="flex items-center gap-2">
			<!-- Previous button -->
			<button
				onclick={goPrev}
				disabled={offset === 0}
				class="flex items-center gap-1 px-3 py-1.5 text-sm bg-surface border border-border rounded-md
					text-muted hover:border-primary hover:text-primary
					disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:border-border disabled:hover:text-muted
					transition-colors"
			>
				<ChevronLeft class="w-3.5 h-3.5" />
				Previous
			</button>

			<!-- Page indicator -->
			<span class="text-xs text-muted px-2 tabular-nums select-none">
				{currentPage} / {totalPages}
			</span>

			<!-- Next button -->
			<button
				onclick={goNext}
				disabled={offset + limit >= total}
				class="flex items-center gap-1 px-3 py-1.5 text-sm bg-surface border border-border rounded-md
					text-muted hover:border-primary hover:text-primary
					disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:border-border disabled:hover:text-muted
					transition-colors"
			>
				Next
				<ChevronRight class="w-3.5 h-3.5" />
			</button>

			<!-- Jump to page (shown for large datasets) -->
			{#if showJumpInput}
				<div class="flex items-center gap-1.5 ml-2 pl-2 border-l border-border">
					<span class="text-xs text-muted">Jump to</span>
					<input
						type="number"
						bind:value={jumpInput}
						onkeydown={handleJumpKeydown}
						min="1"
						max={totalPages}
						placeholder="#"
						class="w-14 px-2 py-1 text-xs bg-surface border border-border rounded-md
							text-text placeholder:text-muted/40
							focus:outline-none focus:border-primary transition-colors
							[appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
					/>
				</div>
			{/if}
		</div>
	</div>
{/if}
