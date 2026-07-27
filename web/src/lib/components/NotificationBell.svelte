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
		status: string;
		payload: string;
		error_message: string;
		sent_at: string;
		is_read: boolean;
	}

	interface NotificationLogsResponse {
		logs: NotificationLog[];
		// "total" is the requesting user's UNREAD count (server semantics), used
		// directly as the bell badge value.
		total: number;
	}

	interface MarkAllReadResponse {
		marked: number;
	}

	let notifications = $state<NotificationLog[]>([]);
	let unreadCount = $state(0);
	let showDropdown = $state(false);
	let loading = $state(false);
	let marking = $state(false);
	let containerRef: HTMLDivElement | undefined = $state();

	async function fetchNotifications() {
		try {
			loading = true;
			const res = await api.get<NotificationLogsResponse>(
				'/notification/logs?limit=10'
			);
			notifications = res.logs ?? [];
			unreadCount = res.total ?? 0;
		} catch {
			// Silently fail — non-critical UI
		} finally {
			loading = false;
		}
	}

	async function markAllRead() {
		if (marking || unreadCount === 0) return;
		marking = true;
		try {
			await api.post<MarkAllReadResponse>('/notification/logs/read', {});
			// Clear the badge + flip each visible item's is_read flag in place
			// (index mutation, not array reassignment — reassigning the $state
			// array while the dropdown's {#each} is mounted tears Svelte 5's
			// effect graph and snaps the panel shut under hydration).
			unreadCount = 0;
			for (let i = 0; i < notifications.length; i++) {
				notifications[i].is_read = true;
			}
		} catch {
			// Silently fail — the badge will re-sync on the next poll.
		} finally {
			marking = false;
		}
	}

	async function toggleDropdown() {
		showDropdown = !showDropdown;
		// Opening the dropdown marks everything read (clears the badge). This
		// matches the common bell pattern (open == acknowledge all).
		if (showDropdown) {
			await markAllRead();
		}
	}

	// Extract a human-readable subject from the notification payload JSON.
	// The dispatcher stores { subject, body, recipient } — fall back to the
	// delivery status if no subject is present.
	function subject(payload: string, status: string): string {
		try {
			const parsed = JSON.parse(payload) as { subject?: string };
			if (parsed.subject) return parsed.subject;
		} catch {
			// payload isn't JSON — fall through
		}
		return status === 'sent' ? m['notifications.Sent']() : m['notifications.Failed']();
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
			aria-label={m["notifications.Notification"]()
				+ (unreadCount > 0 ? ` (${unreadCount} ${m['notifications.Unread']()})` : '')}
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
								class="flex gap-2 px-4 py-3 border-b border-border last:border-b-0
									hover:bg-surface-2 transition-colors cursor-default
									{notif.is_read ? 'opacity-60' : ''}"
							>
								<!-- Unread dot (left rail) — only renders for unread items -->
								<span
									class="shrink-0 mt-1.5 w-2 h-2 rounded-full
										{notif.is_read ? 'bg-transparent' : 'bg-primary'}"
									aria-label={notif.is_read ? undefined : m['notifications.Unread']()}
								></span>
								<div class="min-w-0 flex-1">
									<div class="flex items-start justify-between gap-2">
										<p class="text-sm text-text truncate {notif.is_read ? 'font-normal' : 'font-medium'}">
											{subject(notif.payload, notif.status)}
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
									{#if notif.error_message}
										<p class="text-xs text-error mt-1 truncate">{notif.error_message}</p>
									{/if}
									<div class="flex items-center gap-2 mt-1">
										<span class="text-xs text-muted">
											{formatTime(notif.sent_at)}
										</span>
									</div>
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
