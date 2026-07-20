<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

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
		Network
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

	// Nav is grouped (Core / Library / Administration) instead of a flat 11-item
	// list. The admin group is hidden entirely for non-admins — previously the
	// 4 admin-only items rendered as inert grey rows mixed in with the daily-use
	// items, which read as "a bunch of things I can't click". /topology and
	// /discovery were removed as top-level entries: topology is now a view toggle
	// inside /devices, discovery is a tab under the scan center (/devices/scan-*).
	interface NavItem { path: string; label: string; icon: Component }
	interface NavGroup { labelKey: string; items: NavItem[] }

	const navGroups: NavGroup[] = [
		{
			labelKey: 'navigation.Group Core',
			items: [
				{ path: '/dashboard', label: m['navigation.Dashboard'](), icon: LayoutDashboard },
				{ path: '/devices', label: m['navigation.Devices'](), icon: Server },
				{ path: '/changes', label: m['navigation.Changes'](), icon: History }
			]
		},
		{
			labelKey: 'navigation.Group Library',
			items: [
				{ path: '/documents', label: m['navigation.Documents'](), icon: FileText }
			]
		},
		{
			labelKey: 'navigation.Group Admin',
			items: [
				{ path: '/networks', label: m['navigation.Networks'](), icon: Network },
				{ path: '/agents', label: m['navigation.Agents'](), icon: Bot },
				{ path: '/users', label: m['navigation.Users'](), icon: Users },
				{ path: '/audit', label: m['navigation.AuditLogs'](), icon: ScrollText }
			]
		}
	];

	// Non-admins don't see the Administration group at all. The Settings entry
	// stays in the footer (it's self-service profile/security, not admin infra).
	const visibleGroups = $derived(
		navGroups.filter(g => g.labelKey !== 'navigation.Group Admin' || $auth.user?.role === 'admin')
	);

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
		<nav class="flex-1 p-2 overflow-y-auto">
			{#each visibleGroups as group, gi (group.labelKey)}
				{#if gi > 0}
					<div class="my-2 mx-3 border-t border-border"></div>
				{/if}
				<p class="nav-group-label">{m[group.labelKey]()}</p>
				{#each group.items as item (item.path)}
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

<style>
	/* Section label for grouped nav (Core / Library / Administration).
	 * Visually subdued so the items remain the focus, but present so the
	 * grouping is legible — especially the admin/normal split. */
	.nav-group-label {
		padding: 0.625rem 0.75rem 0.25rem;
		font-size: 0.6875rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--color-text-muted);
		opacity: 0.7;
	}
	/* First group has no top label padding (the header above already has padding). */
	.nav-group-label:first-child {
		padding-top: 0.25rem;
	}
</style>
