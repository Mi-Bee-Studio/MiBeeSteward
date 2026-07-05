<script lang="ts">
	import { Sun, Moon } from '@lucide/svelte';

	function getInitialDark(): boolean {
		const stored = localStorage.getItem('theme');
		if (stored === 'light') return false;
		if (stored === 'dark') return true;
		// No stored preference — detect from system
		return !window.matchMedia('(prefers-color-scheme: light)').matches;
	}

	let dark = $state(getInitialDark());

	function toggle() {
		dark = !dark;
		const theme = dark ? 'dark' : 'light';
		localStorage.setItem('theme', theme);
		document.documentElement.setAttribute('data-theme', theme);
	}
</script>

<button
	onclick={toggle}
	class="btn-icon"
	title={dark ? 'Switch to light theme' : 'Switch to dark theme'}
	aria-label="Toggle theme"
>
	{#if dark}
		<Sun class="w-[18px] h-[18px]" />
	{:else}
		<Moon class="w-[18px] h-[18px]" />
	{/if}
</button>
