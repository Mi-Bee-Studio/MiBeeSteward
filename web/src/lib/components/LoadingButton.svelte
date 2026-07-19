<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  LoadingButton — a button that shows a spinner next to its label while in a
  loading state, instead of swapping the label for the literal "..." that 31+
  call-sites used before. The label stays visible so the user still knows what
  the button will do; the spinner communicates the in-flight state.

  Variants and sizing mirror the `.btn` classes from themes.css so it slots
  into existing layouts without restyling.
-->

<script lang="ts">
	import { LoaderCircle } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	let {
		loading = false,
		disabled = false,
		variant = 'primary',
		size = 'md',
		type = 'button',
		class: className = '',
		label,
		children,
		onclick,
		...rest
	}: {
		loading?: boolean;
		disabled?: boolean;
		/** Matches the `.btn-*` classes from themes.css. */
		variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
		/** `sm` shrinks the spinner + tightens padding for inline/table use. */
		size?: 'sm' | 'md';
		type?: 'button' | 'submit' | 'reset';
		class?: string;
		/** Plain-text label. Prefer `children` when you need an icon at rest. */
		label?: string;
		children?: Snippet;
		onclick?: (e: MouseEvent) => void;
		[key: string]: unknown;
	} = $props();

	const variantClass = $derived({
		primary: 'btn-primary',
		secondary: 'btn-secondary',
		danger: 'btn-danger',
		ghost: 'btn-ghost'
	}[variant]);

	const sizeClass = $derived(size === 'sm' ? 'text-xs py-1.5' : '');
	const isDisabled = $derived(disabled || loading);
	const iconSize = $derived(size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4');
</script>

<button
	{type}
	class="btn {variantClass} {sizeClass} {className}"
	disabled={isDisabled}
	onclick={onclick}
	aria-busy={loading ? 'true' : undefined}
	{...rest}
>
	{#if loading}
		<LoaderCircle class="{iconSize} animate-spin" aria-hidden="true" />
	{:else if children}
		{@render children()}
	{/if}
	<span>{label}</span>
</button>
