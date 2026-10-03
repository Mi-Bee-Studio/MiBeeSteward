<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { ChevronDown } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	interface Props {
		/** Stable section id; also the URL hash deep-link target. */
		id: string;
		title: string;
		open: boolean;
		onToggle: () => void;
		children: Snippet;
	}

	let { id, title, open, onToggle, children }: Props = $props();

	// Keep-alive: mount the (possibly data-fetching) content on first open,
	// then preserve it across collapses so in-progress form input survives an
	// accidental fold. Hidden via CSS instead of unmounting.
	let mounted = $state(false);
	$effect(() => {
		if (open) mounted = true;
	});
</script>

<section id="settings-{id}" class="bg-surface border border-border rounded-xl mb-4 overflow-hidden">
	<button
		type="button"
		onclick={onToggle}
		aria-expanded={open}
		aria-controls="settings-panel-{id}"
		class="w-full flex items-center justify-between gap-3 px-6 py-4 text-left hover:bg-surface/80 transition-colors"
	>
		<h3 class="text-lg font-semibold text-text">{title}</h3>
		<ChevronDown
			class="w-5 h-5 text-muted shrink-0 transition-transform duration-200 {open ? 'rotate-180' : ''}"
		/>
	</button>
	{#if mounted}
		<div
			id="settings-panel-{id}"
			class="px-6 pb-6 pt-5 border-t border-border {open ? '' : 'hidden'}"
		>
			{@render children()}
		</div>
	{/if}
</section>
