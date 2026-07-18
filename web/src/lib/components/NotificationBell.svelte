<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { auth } from '$lib/stores/auth';
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { Bell } from '@lucide/svelte';

	interface NotificationLog {
		id: number;
		rule_name: string;
		channel_name: string;
		channel_type: string;
		status: string;
		payload: string;
		error_message: string;
		sent_at: string;
	}

	interface NotificationLogsResponse {
		logs: NotificationLog[];
		total: number;
	}

	let notifications = $state<NotificationLog[]>([]);
	let unreadCount = $state(0);
	let showDropdown = $state(false);
	let loading = $state(false);
	let containerRef: HTMLDivElement | undefined = $state();

	async function fetchNotifications() {
		try {
			loading = true;
			const res = await api.get<NotificationLogsResponse>(
				'/notification/logs?status=sent&limit=10'
			);
			notifications = res.logs ?? [];
			unreadCount = Math.min(res.total ?? 0, 99);
		} catch {
			// Silently fail — non-critical UI
		} finally {
			loading = false;
		}
	}

	function toggleDropdown() {
		showDropdown = !showDropdown;
	}

	function handleClickOutside(e: MouseEvent) {
		if (containerRef && !containerRef.contains(e.target as Node)) {
			showDropdown = false;
		}
	}

	function formatTime(iso: string): string {
		return new Date(iso).toLocaleString();
	}

	onMount(() => {
		if ($auth.token) {
			fetchNotifications();
		}

		const interval = setInterval(() => {
			if ($auth.token) {
				fetchNotifications();
			}
		}, 60_000);

		document.addEventListener('click', handleClickOutside);
		return () => {
			clearInterval(interval);
			document.removeEventListener('click', handleClickOutside);
		};
	});
</script>

{#if $auth.token}
	<div class="relative" bind:this={containerRef}>
		<!-- Bell button -->
		<button
			onclick={toggleDropdown}
			class="btn-icon relative"
			aria-label={m["notifications.Notification"]()}
		>
			<Bell class="w-5 h-5" />

			<!-- Unread badge -->
			{#if unreadCount > 0}
				<span
					class="absolute -top-1 -right-1 min-w-[18px] h-[18px] flex items-center justify-center
						rounded-full bg-error text-text-inverse text-[10px] font-bold
						leading-none px-1"
				>
					{unreadCount > 99 ? '99+' : unreadCount}
				</span>
			{/if}
		</button>

		<!-- Dropdown -->
		{#if showDropdown}
			<div
				class="absolute right-0 bottom-full mb-2 w-80
					bg-surface border border-border rounded-xl
					overflow-hidden z-50"
				style="box-shadow: var(--shadow-lg);"
			>
				<!-- Header -->
				<div class="px-4 py-3 border-b border-border flex items-center justify-between">
					<span class="text-sm font-semibold text-text">
						{m["notifications.Recent Notifications"]()}
					</span>
					{#if loading}
						<span class="text-xs text-muted">{m["common.Loading"]()}</span>
					{/if}
				</div>

				<!-- Notification list -->
				<div class="max-h-72 overflow-y-auto">
					{#if notifications.length === 0}
						<div class="px-4 py-8 text-center">
							<p class="text-sm text-muted">
								{m["notifications.No Recent Notifications"]()}
							</p>
						</div>
					{:else}
						{#each notifications as notif}
							<div
								class="px-4 py-3 border-b border-border last:border-b-0
									hover:bg-surface-2 transition-colors cursor-default"
							>
								<div class="flex items-start justify-between gap-2">
									<p class="text-sm text-text font-medium truncate">
										{notif.rule_name}
									</p>
									<span
										class="shrink-0 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium
											{notif.status === 'sent'
											? 'bg-success/15 text-success'
											: notif.status === 'failed'
												? 'bg-error/15 text-error'
												: 'bg-surface-2 text-muted'}"
									>
										{notif.status === 'sent'
											? m["notifications.Sent"]()
											: notif.status === 'failed'
												? m["notifications.Failed"]()
												: notif.status}
									</span>
								</div>
								<div class="flex items-center gap-2 mt-1">
									<span class="text-xs text-muted truncate">
										{notif.channel_name}
									</span>
									<span class="text-border-strong">·</span>
									<span class="text-xs text-muted">
										{formatTime(notif.sent_at)}
									</span>
								</div>
							</div>
						{/each}
					{/if}
				</div>

				<!-- Footer -->
				<a
					href="/audit"
					class="block px-4 py-2.5 text-center text-sm text-primary
						hover:bg-surface-2 transition-colors border-t border-border"
				>
					{m["notifications.View All"]()}
				</a>
			</div>
		{/if}
	</div>
{/if}
