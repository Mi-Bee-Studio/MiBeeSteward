<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import { page } from '$app/stores';
	import { auth } from '$lib/stores/auth';

	let { children } = $props<{ children: () => void }>();

	const isAdmin = $derived($auth.user?.role === 'admin');

	const tabs = $derived([
		{ path: '/devices', label: m['devices.Tab Device List'](), exact: true },
		...(isAdmin
			? [
				{ path: '/devices/scanner', label: m['devices.Tab Scanner'](), exact: false },
				{ path: '/devices/scan-tasks', label: m['devices.Tab Scan Tasks'](), exact: false },
				{ path: '/devices/scan-results', label: m['devices.Tab Scan Results'](), exact: false }
			]
			: [])
	]);

	function isActive(tab: { path: string; exact: boolean }): boolean {
		const pathname = $page.url.pathname;
		if (tab.exact) {
			return pathname === tab.path || pathname === tab.path + '/';
		}
		return pathname.startsWith(tab.path);
	}
</script>

<div class="flex flex-col h-full">
	<!-- Tab bar -->
	<nav class="flex border-b border-border bg-surface overflow-x-auto shrink-0">
		{#each tabs as tab (tab.path)}
			<a
				href={tab.path}
				class="tab {isActive(tab) ? 'tab-active' : ''}"
				aria-current={isActive(tab) ? 'page' : undefined}
			>
				{tab.label}
			</a>
		{/each}
	</nav>

	<!-- Tab content -->
	<div class="flex-1 overflow-auto">
		{@render children()}
	</div>
</div>
