<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import { api, ApiError, SessionExpiredError } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { ensurePasswordPolicyLoaded, passwordPolicy } from '$lib/stores/passwordPolicy';
	import type { LoginResponse } from '$lib/types';
	import { getErrorMessage } from '$lib/utils/error.js';
	import { loginSchema, forcePasswordSchema, validateForm } from '$lib/utils/validation.js';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { fly } from 'svelte/transition';
	import { addToast } from '$lib/stores/toast';
	import { Lock, Eye, EyeOff, ShieldCheck } from '@lucide/svelte';
	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';

	let username = $state('');
	let password = $state('');
	let showPassword = $state(false);
	let error = $state('');
	let loading = $state(false);
	let errors = $state<Record<string, string>>({});

	// First-run setup state: when the bootstrap admin has NO password yet
	// (installer default: /auth/setup-status reports it), the login page
	// renders a create-admin-password form instead of the login form.
	let setupRequired = $state(false);
	let setupNewPassword = $state('');
	let setupConfirmPassword = $state('');
	let setupError = $state('');
	let setupLoading = $state(false);

	// Live strength-policy hint (shared by the setup form and the force-change
	// modal): from the passwordPolicy store so it follows the EFFECTIVE
	// backend policy, not hardcoded defaults (#332).
	let policyHint = $derived.by(() => {
		const p = $passwordPolicy;
		const parts: string[] = [m['security.hint.length']({ min: p.min_length })];
		if (p.require_uppercase) parts.push(m['security.hint.uppercase']());
		if (p.require_lowercase) parts.push(m['security.hint.lowercase']());
		if (p.require_digit) parts.push(m['security.hint.digit']());
		if (p.require_special) parts.push(m['security.hint.special']());
		return parts.join(m['security.hint.joiner']());
	});

	onMount(() => {
		// Already authenticated (e.g. navigating to /login with a live session):
		// bounce straight to the dashboard instead of rendering the login form
		// next to the logged-in sidebar (#430). One-shot at mount ONLY: the
		// post-login flows on this page call auth.login() themselves and then
		// decide where to go (2FA / force-password stay here), so a reactive
		// token watcher would hijack those redirects.
		if (get(auth)?.token) {
			goto('/dashboard');
			return;
		}
		// Pre-fetch the strength policy so the hint is correct before submit;
		// failures keep the compiled-in defaults.
		void ensurePasswordPolicyLoaded();
		api
			.get<{ required: boolean }>('/auth/setup-status')
			.then((res) => {
				if (res?.required) setupRequired = true;
			})
			.catch(() => {
				/* unreachable backend / old version: stay on the login form */
			});
	});

	// Force password change state
	let showForceDialog = $state(false);
	let forceNewPassword = $state('');
	let forceConfirmPassword = $state('');
	let forceError = $state('');
	let forceLoading = $state(false);
	let loginResponse: LoginResponse | null = $state(null);

	// 2FA state
	let twoFactorRequired = $state(false);
	let twoFactorUserId = $state<number | null>(null);
	let twoFactorCode = $state('');
	let twoFactorLoading = $state(false);
	async function handleLogin(e: Event) {
		e.preventDefault();
		error = '';
		errors = {};

		// validateForm translates the zod message keys (validation.Username
		// Required → localized text); a hand-rolled safeParse loop here would
		// render the raw keys instead (#427).
		const validation = validateForm(loginSchema, { username, password });
		if (!validation.valid) {
			errors = validation.errors;
			return;
		}

		loading = true;
		let loginDone = false;
		try {
			const res = await api.post<LoginResponse>('/auth/login', { username, password });
			loginResponse = res;
			loginDone = true;

			// Check if 2FA is required. LoginResponse models these fields
			// (two_factor_required / user_id) directly: no `as any` needed.
			if (res.two_factor_required) {
				twoFactorRequired = true;
				twoFactorUserId = res.user_id ?? null;
				return; // Don't navigate yet
			}

			auth.login(res.user, res.token);

			if (res.user.must_change_password) {
				showForceDialog = true;
			} else {
				goto('/dashboard');
			}
		} catch (err: unknown) {
			// Classify by error TYPE / HTTP status, never by message text: the
			// message is localized and would break classification if the locale
			// or backend wording changes.
			if (err instanceof ApiError && err.status === 409 && err.message === 'setup_required') {
				// The bootstrap admin has no password yet (another tab finished
				// setup-status after we rendered, or an old bundle cached the
				// login form): flip to the setup form instead of showing an
				// error nobody can act on.
				setupRequired = true;
				error = '';
				return;
			}
			if (err instanceof SessionExpiredError) {
				// 401 from /auth/login = bad credentials (the api client treats
				// every 401 as session-expired; on the login endpoint that maps
				// to "invalid username or password").
				error = m['auth.error.invalid_credentials']();
			} else if (err instanceof ApiError && err.status === 423) {
				error = m['auth.error.account_locked']();
			} else if (err instanceof ApiError && err.status === 429) {
				error = m['auth.error.too_many_attempts']();
			} else if (err instanceof TypeError) {
				// fetch() throws TypeError on network failure / DNS / CORS.
				error = m['auth.error.network_error']();
			} else if (err instanceof ApiError && err.status >= 500) {
				error = m['auth.error.server_error']();
			} else {
				// 4xx other than 401/429 (e.g. 400/403/422): surface the
				// backend's own message, which is already user-facing.
				error = getErrorMessage(err);
			}
		} finally {
			loading = false;
			// A failed attempt leaves the typed password in the (masked) field;
			// clear it so a stale password isn't shoulder-surfed or resubmitted
			// after the user walks away (#251).
			if (!loginDone) password = '';
		}
	}

	// handleSetup submits the first-run create-admin-password form. The
	// response is the same LoginResponse shape as /auth/login (token + user),
	// so on success we enter the app directly: no second login round-trip.
	async function handleSetup(e: Event) {
		e.preventDefault();
		setupError = '';

		const validation = validateForm(forcePasswordSchema, {
			new_password: setupNewPassword,
			confirm: setupConfirmPassword
		});
		if (!validation.valid) {
			setupError = validation.errors.new_password ?? validation.errors.confirm ?? '';
			return;
		}

		setupLoading = true;
		try {
			const res = await api.post<LoginResponse>('/auth/setup', {
				new_password: setupNewPassword
			});
			auth.login(res.user, res.token);
			goto('/dashboard');
		} catch (err: unknown) {
			if (err instanceof ApiError && err.status === 409) {
				// Setup was already completed elsewhere: back to the login form.
				setupRequired = false;
				addToast('success', m['auth.setup_already_done']());
				return;
			}
			setupError = getErrorMessage(err);
		} finally {
			setupLoading = false;
		}
	}

	async function handleForcePasswordChange(e: Event) {
		e.preventDefault();
		forceError = '';

		// Validate via the shared forcePasswordSchema (8-char min + match) so the
		// password policy lives in ONE place (#154 part 3): previously these
		// were hand-rolled length / mismatch checks that would silently drift
		// from the users-page reset-password modal if the policy changed.
		const validation = validateForm(forcePasswordSchema, {
			new_password: forceNewPassword,
			confirm: forceConfirmPassword
		});
		if (!validation.valid) {
			// The schema attaches the error to `confirm` for a mismatch, or to
			// `new_password` for the length rule: surface the first one.
			forceError = validation.errors.new_password ?? validation.errors.confirm ?? '';
			return;
		}

		forceLoading = true;
		try {
			const res = await api.put<{ message: string; token: string }>('/auth/force-password', {
				new_password: forceNewPassword
			});
			showForceDialog = false;
			if (res.token && loginResponse) {
				// The pre-change token carries the must-change gate (mcp claim,
				// enforced server-side) until it expires: the handler mints a
				// fresh ungated one; swap it in before navigating or every API
				// call on the dashboard would 403.
				auth.login({ ...loginResponse.user, must_change_password: false }, res.token);
			}
			goto('/dashboard');
		} catch (err: unknown) {
			forceError = getErrorMessage(err);
		} finally {
			forceLoading = false;
		}
	}

	async function handle2FAVerify(e: Event) {
		e.preventDefault();
		if (!twoFactorCode || twoFactorCode.length !== 6) return;
		twoFactorLoading = true;
		try {
			// The verify endpoint returns the same LoginResponse shape as
			// /auth/login (Token + full User, including must_change_password).
			const res = await api.post<LoginResponse>('/auth/2fa/verify', {
				user_id: twoFactorUserId,
				code: twoFactorCode
			});
			loginResponse = res;
			auth.login(res.user, res.token);

			// Keep the user on the login page and show the same focused
			// force-password-change modal the non-2FA flow uses (#156);
			// previously this dumped them onto the generic /settings page.
			if (res.user.must_change_password) {
				twoFactorRequired = false;
				showForceDialog = true;
			} else {
				goto('/dashboard');
			}
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			twoFactorLoading = false;
		}
	}

	function backToLogin() {
		twoFactorRequired = false;
		twoFactorUserId = null;
		twoFactorCode = '';
		// Clear a stale error left over from the failed login that pushed us
		// into the 2FA flow; otherwise it resurfaces on the username/password
		// view. Username/password are intentionally kept (convenience).
		error = '';
	}
</script>

<div class="flex items-center justify-center min-h-screen bg-bg">
	<div class="w-full max-w-md">
		<!-- Logo area -->
		<div class="text-center mb-8">
			<h1 class="text-3xl font-bold text-primary tracking-tight">MiBee Steward</h1>
			<p class="text-sm text-muted mt-2">{m["auth.subtitle"]()}</p>
		</div>

		<!-- Login card -->
		<div class="bg-surface border border-border rounded-xl p-8 glow-border">

            {#if setupRequired}
                <!-- First run: create the admin password (no login exists yet) -->
                <div class="text-center mb-6">
                    <ShieldCheck class="w-12 h-12 mx-auto mb-3 text-primary" strokeWidth={1.5} />
                    <h2 class="text-xl font-bold text-text">{m["auth.setup_title"]()}</h2>
                    <p class="text-sm text-muted mt-1">{m["auth.setup_desc"]()}</p>
                </div>

                {#if setupError}
                    <div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite" transition:fly={{ y: -10, duration: 200 }}>
                        {setupError}
                    </div>
                {/if}

                <form onsubmit={handleSetup}>
                    <div class="mb-4">
                        <label class="block text-sm text-muted mb-2" for="setup-new-password">{m["auth.new_password"]()}</label>
                        <input
                            type={showPassword ? 'text' : 'password'}
                            id="setup-new-password"
                            bind:value={setupNewPassword}
                            class="input py-2.5 focus:ring-1 focus:ring-primary"
                            placeholder="••••••••"
                            required
                            autocomplete="new-password"
                            autofocus
                        />
                    </div>
                    <div class="mb-4">
                        <label class="block text-sm text-muted mb-2" for="setup-confirm-password">{m["auth.confirm_password"]()}</label>
                        <input
                            type={showPassword ? 'text' : 'password'}
                            id="setup-confirm-password"
                            bind:value={setupConfirmPassword}
                            class="input py-2.5 focus:ring-1 focus:ring-primary"
                            placeholder="••••••••"
                            required
                            autocomplete="new-password"
                        />
                    </div>
                    <p class="text-xs text-muted bg-bg rounded-lg px-3 py-2 mb-6">{policyHint}</p>
                    <LoadingButton type="submit" loading={setupLoading} variant="primary"
                        label={m["auth.setup_submit"]()} class="w-full py-2.5" />
                </form>
            {:else if twoFactorRequired}
                <!-- 2FA Verification -->
                <div class="text-center mb-6">
                    <Lock class="w-12 h-12 mx-auto mb-3 text-primary" strokeWidth={1.5} />
                    <h2 class="text-xl font-bold text-text">{m["auth.2fa_login_title"]()}</h2>
                    <p class="text-sm text-muted mt-1">{m["auth.2fa_login_desc"]()}</p>
                </div>
                <form onsubmit={handle2FAVerify}>
                    <div class="mb-4">
                        <input type="text" inputmode="numeric" maxlength="6" bind:value={twoFactorCode} autofocus
                            class="input py-3 text-center text-2xl font-mono tracking-[0.5em]"
                            placeholder="000000" />
                        {#if twoFactorCode.length > 0 && !/^\d{6}$/.test(twoFactorCode)}
                            <p class="mt-2 text-xs text-error text-center">{m["validation.Two Factor Code Length"]()}</p>
                        {/if}
                    </div>
                    <LoadingButton type="submit" loading={twoFactorLoading} disabled={!/^\d{6}$/.test(twoFactorCode)}
                        variant="primary" label={m["auth.2fa_submit"]()} class="w-full py-2.5" />
                </form>
                <button onclick={backToLogin} class="w-full mt-3 text-sm text-muted hover:text-text transition-colors">
                    &larr; {m["auth.2fa_back_to_login"]()}
                </button>
            {:else}
			<h2 class="text-xl font-semibold text-text mb-6">{m["auth.Login"]()}</h2>

			{#if error}
				<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite" transition:fly={{ y: -10, duration: 200 }}>
					{error}
				</div>
			{/if}

			<!-- novalidate (#427): empty-field feedback comes from the zod path in
			     handleLogin (in-DOM, localized, works under automation) instead of
			     the native required bubble, which is silent in some contexts. -->
			<form onsubmit={handleLogin} novalidate>
				<div class="mb-4">
					<label class="block text-sm text-muted mb-2" for="username">{m["auth.Username"]()}</label>
					<input
						type="text"
						id="username"
						bind:value={username}
						class="input py-2.5 focus:ring-1 focus:ring-primary"
						placeholder={m['auth.Username Placeholder']()}
						required
						autocomplete="username"
					/>
					{#if errors.username}
						<p class="text-error text-xs mt-1">{errors.username}</p>
					{/if}
				</div>
					<div class="mb-6">
						<label class="block text-sm text-muted mb-2" for="password">{m["auth.Password"]()}</label>
						<div class="relative">
							<input
								type={showPassword ? 'text' : 'password'}
								id="password"
								bind:value={password}
								class="input py-2.5 pr-10 focus:ring-1 focus:ring-primary"
								placeholder="••••••••"
								required
								autocomplete="current-password"
							/>
							<button
								type="button"
								onclick={() => showPassword = !showPassword}
								class="absolute right-1 top-1/2 -translate-y-1/2 min-w-[44px] min-h-[44px] flex items-center justify-center text-muted hover:text-text transition-colors"
								aria-label={showPassword ? m['auth.hide_password']() : m['auth.show_password']()}
								title={showPassword ? m['auth.hide_password']() : m['auth.show_password']()}
							>
								{#if showPassword}
									<EyeOff class="w-5 h-5" />
								{:else}
									<Eye class="w-5 h-5" />
								{/if}
							</button>
						</div>
					{#if errors.password}
						<p class="text-error text-xs mt-1">{errors.password}</p>
					{/if}
				</div>
				<LoadingButton
					type="submit"
					loading={loading}
					variant="primary"
					label={m["auth.Login"]()}
					class="w-full py-2.5"
				/>
			</form>

			<p class="text-xs text-muted mt-4 text-center">
				{m["auth.registration_note"]()}
			</p>
            {/if}
		</div>
	</div>
</div>

<!-- Force password change dialog (uses Modal for focus trap / Escape / focus restore) -->
<Modal bind:open={showForceDialog} title={m["auth.Change Password"]()} maxWidth="28rem">
	<p class="text-sm text-warning mb-2">{m["auth.force_change_password"]()}</p>
	<p class="text-xs text-muted mb-6">{policyHint}</p>

	{#if forceError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite" transition:fly={{ y: -10, duration: 200 }}>
			{forceError}
		</div>
	{/if}

	<form onsubmit={handleForcePasswordChange}>
		<div class="mb-4">
			<label class="block text-sm text-muted mb-2" for="force-new-password">{m["auth.new_password"]()}</label>
			<input
				type="password"
				id="force-new-password"
				bind:value={forceNewPassword}
				class="input py-2.5 focus:ring-1 focus:ring-primary"
				placeholder="••••••••"
				required
				autocomplete="new-password"
			/>
		</div>
		<div class="mb-6">
			<label class="block text-sm text-muted mb-2" for="force-confirm-password">{m["auth.confirm_password"]()}</label>
			<input
				type="password"
				id="force-confirm-password"
				bind:value={forceConfirmPassword}
				class="input py-2.5 focus:ring-1 focus:ring-primary"
				placeholder="••••••••"
				required
				autocomplete="new-password"
			/>
		</div>
		<LoadingButton type="submit" loading={forceLoading} label={m["auth.Change Password"]()} class="w-full py-2.5" />
	</form>
</Modal>
