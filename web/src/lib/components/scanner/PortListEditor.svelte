<!--
  Port whitelist editor (#275): chip-style add/remove of ports and port ranges
  over the same spec syntax pipeline_config.port_scan.ports uses. Replaces the
  bare text input, which gave no validation and never told the user the list is
  a WHITELIST (out-of-list open ports are invisible by design).
-->
<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import { X, Plus } from '@lucide/svelte';

	let {
		value,
		onchange,
		id
	}: {
		value: string;
		onchange?: () => void;
		id?: string;
	} = $props();

	let draft = $state('');
	let error = $state('');

	interface Chip {
		raw: string; // display form: "80" or "5000-5010"
	}

	const chips = $derived<Chip[]>(
		value
			.split(',')
			.map((s) => s.trim())
			.filter((s) => s !== '')
			.map((raw) => ({ raw }))
	);

	function isValidEntry(entry: string): boolean {
		const rangeMatch = entry.match(/^(\d+)-(\d+)$/);
		if (rangeMatch) {
			const lo = Number(rangeMatch[1]);
			const hi = Number(rangeMatch[2]);
			return lo >= 1 && hi <= 65535 && lo <= hi;
		}
		const p = Number(entry);
		return /^\d+$/.test(entry) && p >= 1 && p <= 65535;
	}

	function commitSpec(next: string[]) {
		value = next.join(',');
		onchange?.();
	}

	function addDraft() {
		const entry = draft.trim();
		error = '';
		if (entry === '') return;
		if (!isValidEntry(entry)) {
			error = m['scanner.ports.invalid_entry']();
			return;
		}
		const existing = value.split(',').map((s) => s.trim()).filter((s) => s !== '');
		if (!existing.includes(entry)) existing.push(entry);
		commitSpec(existing);
		draft = '';
	}

	function removeChip(raw: string) {
		commitSpec(
			value
				.split(',')
				.map((s) => s.trim())
				.filter((s) => s !== '' && s !== raw)
		);
	}

	function applyTemplate(ports: string) {
		value = ports;
		error = '';
		onchange?.();
	}
</script>

<div class="space-y-2" {id}>
	<div class="flex flex-wrap items-center gap-1.5">
		{#each chips as chip (chip.raw)}
			<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-mono">
				{chip.raw}
				<button
					type="button"
					onclick={() => removeChip(chip.raw)}
					aria-label={m['scanner.ports.remove']({ port: chip.raw })}
					class="hover:text-error transition-colors"
				>
					<X class="w-3 h-3" />
				</button>
			</span>
		{:else}
			<span class="text-xs text-muted">{m['scanner.ports.empty']()}</span>
		{/each}
	</div>

	<div class="flex items-center gap-2">
		<input
			type="text"
			bind:value={draft}
			onkeydown={(e) => {
				if (e.key === 'Enter') {
					e.preventDefault();
					addDraft();
				}
			}}
			placeholder={m['scanner.ports.add_placeholder']()}
			class="flex-1 px-2.5 py-1.5 bg-bg border border-border rounded-lg text-sm text-text font-mono
				focus:border-primary focus:outline-none {error ? '!border-error' : ''}"
		/>
		<button
			type="button"
			onclick={addDraft}
			class="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-sm bg-primary/10 text-primary
				hover:bg-primary/20 transition-colors"
		>
			<Plus class="w-3.5 h-3.5" />
			{m['common.Add']()}
		</button>
	</div>
	{#if error}
		<p class="text-xs text-error">{error}</p>
	{/if}
	<p class="text-xs text-muted">
		{m['scanner.ports.whitelist_note']({ count: chips.length })}
	</p>

	<slot name="templates" {applyTemplate} />
</div>
