<script lang="ts">
	import '../lib/styles/themes.css';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import LanguageSwitcher from '$lib/components/LanguageSwitcher.svelte';
	import NotificationBell from '$lib/components/NotificationBell.svelte';
	import logo from '$lib/assets/logo.svg';
	import Toast from '$lib/components/Toast.svelte';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import {
		LayoutDashboard,
		Server,
		FileText,
		Users,
		ScrollText,
		Settings,
		LogOut,
		Menu,
		X,
		History,
		Bot,
		Radar,
		Network,
		Share2
	} from '@lucide/svelte';
	import type { Component } from 'svelte';

	let { children } = $props<{ children: () => void }>();

	let sidebarOpen = $state(false);

	onMount(() => {
		// Redirect to login if not authenticated and not already on login page
		const path = window.location.pathname;
		if (!$auth.token && path !== '/login') {
			goto('/login');
		}
	});


	function handleLogout() {
		auth.logout();
		goto('/login');
	}

	const allNavItems: { path: string; label: string; icon: Component; adminOnly?: boolean }[] = [
		{ path: '/dashboard', label: m['navigation.Dashboard'](), icon: LayoutDashboard },
		{ path: '/devices', label: m['navigation.Devices'](), icon: Server },
		{ path: '/changes', label: m['navigation.Changes']?.() ?? 'Changes', icon: History },
		{ path: '/topology', label: m['navigation.Topology']?.() ?? 'Topology', icon: Share2 },
		{ path: '/discovery', label: m['navigation.Discovery']?.() ?? 'Discovery', icon: Radar },
		{ path: '/networks', label: m['navigation.Networks']?.() ?? 'Networks', icon: Network, adminOnly: true },
		{ path: '/agents', label: m['navigation.Agents']?.() ?? 'Agents', icon: Bot, adminOnly: true },
		{ path: '/documents', label: m['navigation.Documents'](), icon: FileText },
		{ path: '/users', label: m['navigation.Users'](), icon: Users, adminOnly: true },
		{ path: '/audit', label: m['navigation.AuditLogs'](), icon: ScrollText, adminOnly: true },
		{ path: '/settings', label: m['navigation.Settings'](), icon: Settings }
	];

	const navItems = $derived(allNavItems.filter(item => !item.adminOnly || $auth.user?.role === 'admin'));

	// Global keyboard shortcuts
	$effect(() => {
		function handleKeydown(e: KeyboardEvent) {
			const target = e.target as HTMLElement;
			// Don't intercept when typing in inputs
			if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) return;

			if (e.key === 'Escape') {
				// Close any open modal
				const backdrop = document.querySelector('.modal-backdrop');
				if (backdrop) {
					const closeBtn = backdrop.querySelector('.modal-close') as HTMLButtonElement | null;
					closeBtn?.click();
				}
				return;
			}

			if (e.key === '/') {
				e.preventDefault();
				// Focus search input on table pages
				const searchInput = document.querySelector<HTMLInputElement>(
					'input[placeholder*="earch"], input[placeholder*="搜索"]'
				);
				searchInput?.focus();
			}
		}

		window.addEventListener('keydown', handleKeydown);
		return () => window.removeEventListener('keydown', handleKeydown);
	});
</script>

<!-- Skip to content — accessibility -->
<a
	href="#main-content"
	class="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-1/2 focus:-translate-x-1/2 focus:z-[100]
		focus:px-4 focus:py-2 focus:bg-primary focus:text-text-inverse focus:rounded-lg
		focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-primary"
>
	Skip to content
</a>

<div class="flex h-screen overflow-hidden relative">
{#if $auth.token}
	<!-- Mobile hamburger button -->
	<button
		onclick={() => sidebarOpen = !sidebarOpen}
		class="btn-icon fixed top-4 left-4 z-50 md:hidden bg-surface border border-border"
		aria-label="Toggle sidebar"
	>
		{#if sidebarOpen}
			<X class="w-5 h-5" />
		{:else}
			<Menu class="w-5 h-5" />
		{/if}
	</button>

	<!-- Mobile backdrop -->
	{#if sidebarOpen}
		<div
			class="fixed inset-0 z-30 md:hidden"
			style="background: var(--overlay-scrim); backdrop-filter: blur(2px);"
			onclick={() => sidebarOpen = false}
			role="presentation"
		></div>
	{/if}

	<!-- Sidebar -->
	<aside
		class="w-64 bg-surface border-r border-border flex flex-col shrink-0
			fixed inset-y-0 left-0 z-40
			md:static md:z-auto
			transition-transform duration-200 ease-in-out
			{sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
			md:translate-x-0"
	>
		<div class="p-4 border-b border-border">
			<div class="flex items-center gap-3">
				<img src={logo} alt="MiBee" class="w-9 h-9 shrink-0" />
				<div>
					<h1 class="text-xl font-bold text-primary tracking-tight leading-tight">MiBee Steward</h1>
					<p class="text-xs text-muted">Device Management</p>
				</div>
			</div>
		</div>
		<nav class="flex-1 p-2">
			{#each navItems as item (item.path)}
				{@const active = $page.url.pathname === item.path || (item.path !== '/' && $page.url.pathname.startsWith(item.path))}
				<a
					href={item.path}
					class="flex items-center gap-3 px-3 py-2.5 rounded-md mb-0.5 text-sm transition-colors
						{active
							? 'bg-primary/10 text-primary font-medium border-l-2 border-primary'
							: 'text-muted hover:bg-surface-2 hover:text-text border-l-2 border-transparent'}"
					aria-current={active ? 'page' : undefined}
				>
					<item.icon class="w-[18px] h-[18px] shrink-0" />
					<span>{item.label}</span>
				</a>
			{/each}
		</nav>
		<div class="p-3 border-t border-border space-y-2">
			<div class="flex items-center justify-between gap-1">
				<div class="flex items-center gap-1">
					<LanguageSwitcher />
					<ThemeToggle />
				</div>
				<NotificationBell />
			</div>
			{#if $auth.token}
				<div class="flex items-center justify-between pt-2">
					<span class="text-xs text-muted truncate flex items-center gap-1.5">
						<Users class="w-3.5 h-3.5" />
						{$auth.user?.username || '...'}
					</span>
					<button
						onclick={handleLogout}
						class="flex items-center gap-1 text-xs text-muted hover:text-error transition-colors"
					>
						<LogOut class="w-3.5 h-3.5" />
						{m['navigation.Logout']()}
					</button>
				</div>
			{:else}
				<a href="/login" class="flex items-center gap-2 text-sm text-muted hover:text-primary transition-colors">
					<Users class="w-4 h-4" />
					<span>{m['navigation.Login']()}</span>
				</a>
			{/if}
		</div>
	</aside>
{/if}

	<!-- Main content -->
	<main id="main-content" class="flex-1 overflow-auto" class:pt-14={$auth.token} class:md:pt-0={$auth.token}>
		{@render children()}
	</main>
</div>

<Toast />
