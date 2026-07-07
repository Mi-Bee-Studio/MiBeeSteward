<script lang="ts">
	import { page } from '$app/stores';
	import { m } from '$lib/i18n-paraglide';
	import { FileQuestion, Lock, Ban, ServerCrash, AlertTriangle, ArrowLeft } from '@lucide/svelte';
	import type { Component } from 'svelte';

	let status = $derived($page.status);
	let message = $derived($page.error?.message || '');
	let Icon = $derived(errorCode(status));

	function errorTitle(code: number): string {
		switch (code) {
			case 401: return m["errors.Unauthorized"]();
			case 403: return m["errors.Forbidden"]();
			case 404: return m["errors.Not Found"]();
			case 500: return m["errors.Server Error"]();
			default: return m["errors.Something Went Wrong"]();
		}
	}

	function errorDescription(code: number): string {
		switch (code) {
			case 401: return m["errors.Unauthorized Desc"]();
			case 403: return m["errors.Forbidden Desc"]();
			case 404: return m["errors.Not Found Desc"]();
			case 500: return m["errors.Server Error Desc"]();
			default: return m["errors.Unknown Error Desc"]();
		}
	}

	function errorCode(code: number): Component {
		if (code === 404) return FileQuestion;
		if (code === 401) return Lock;
		if (code === 403) return Ban;
		if (code >= 500) return ServerCrash;
		return AlertTriangle;
	}
</script>

<div class="flex items-center justify-center min-h-[70vh] p-6">
	<div class="text-center max-w-md">
		<!-- Error icon -->
		<Icon class="w-20 h-20 mx-auto mb-6 text-muted opacity-80" strokeWidth={1.25} />

		<!-- Status code -->
		<div class="inline-block px-3 py-1 rounded-full bg-error/10 border border-error/20 mb-4">
			<span class="text-sm font-mono font-bold text-error">{status}</span>
		</div>

		<!-- Title -->
		<h1 class="text-2xl font-bold text-text mb-3">
			{errorTitle(status)}
		</h1>

		<!-- Description -->
		<p class="text-sm text-muted mb-2 leading-relaxed">
			{errorDescription(status)}
		</p>

		<!-- Raw error message if available -->
		{#if message}
			<p class="text-xs text-muted font-mono bg-surface border border-border rounded-lg px-3 py-2 mb-6 break-all">
				{message}
			</p>
		{/if}

		<!-- Back to dashboard -->
		<a href="/dashboard" class="btn btn-primary">
			<ArrowLeft class="w-4 h-4" />
			{m["errors.Back Home"]()}
		</a>
	</div>
</div>
