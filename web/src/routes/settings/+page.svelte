<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils';
	import { settingsSchema, validateField } from '$lib/utils/validation';
	import { m, getLocale, setLocale } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { Sun, Moon, Copy, Check } from '@lucide/svelte';
	import QRCode from 'qrcode';
	import Modal from '$lib/components/Modal.svelte';

	interface Profile {
		id: number;
		username: string;
		email: string;
		role: string;
	}

	let profile = $state<Profile | null>(null);
	let loading = $state(true);
	let error = $state('');

	// Profile form
	let email = $state('');
	let profileLoading = $state(false);

	// Password form
	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let passwordLoading = $state(false);

	// Inline validation errors (blur-triggered)
	let fieldErrors = $state<Record<string, string>>({});
	// Track which fields have been blurred
	let touched = $state<Record<string, boolean>>({});

	// Language
	let lang = $state(getLocale());

	// Theme
	let theme = $state<'dark' | 'light'>('dark');

	// Auth state
	let authState = $state<{ user: { username: string; role: string } | null; token: string | null }>({
		user: null,
		token: null
	});

	// 2FA state
	let twoFAEnabled = $state(false);
	let twoFALoading = $state(false);
	let twoFASetupData = $state<{ secret: string; qr_url: string; backup_codes: string[] } | null>(null);
	let twoFAQRDataUrl = $state('');
	let twoFAVerifyCode = $state('');
	let twoFAVerifyLoading = $state(false);
	let twoFADisablePassword = $state('');
	let twoFADisableLoading = $state(false);
	let show2FADisableModal = $state(false);
	function detectTheme(): 'dark' | 'light' {
		const stored = localStorage.getItem('theme');
		if (stored === 'light' || stored === 'dark') return stored;
		return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
	}

	function applyTheme(t: 'dark' | 'light') {
		document.documentElement.setAttribute('data-theme', t);
		localStorage.setItem('theme', t);
		theme = t;
	}

onMount(() => {
    const unsub = auth.subscribe((v) => { authState = v; });
    theme = detectTheme();
    applyTheme(theme);

    api.get<Profile>('/auth/profile')
        .then((res) => {
            profile = res;
            email = res.email || '';
            auth.setUser(res as any);
        })
        .catch((err: unknown) => {
            error = getErrorMessage(err);
        })
        .finally(() => {
            loading = false;
        });

    api.get<{ enabled: boolean }>('/auth/2fa/status')
        .then((res) => { twoFAEnabled = res.enabled; })
        .catch(() => {});

    return unsub;
});

	function handleFieldBlur(field: 'currentPassword' | 'newPassword' | 'confirmPassword') {
		touched[field] = true;
		let value: string;
		if (field === 'currentPassword') value = currentPassword;
		else if (field === 'newPassword') value = newPassword;
		else value = confirmPassword;

		// For confirmPassword, also check match against newPassword
		if (field === 'confirmPassword' && newPassword !== confirmPassword) {
			fieldErrors[field] = 'Passwords do not match';
			return;
		}

		const result = validateField(settingsSchema, field, value);
		if (result.valid) {
			delete fieldErrors[field];
		} else {
			fieldErrors[field] = result.error ?? '';
		}
	}

	function validatePasswordForm(): boolean {
		const result = settingsSchema.safeParse({
			currentPassword,
			newPassword,
			confirmPassword
		});
		if (result.success) {
			fieldErrors = {};
			return true;
		}
		const errors: Record<string, string> = {};
		for (const issue of result.error.issues) {
			const key = issue.path.join('.');
			if (!errors[key]) errors[key] = issue.message;
		}
		fieldErrors = errors;
		// Mark all touched
		touched = { currentPassword: true, newPassword: true, confirmPassword: true };
		return false;
	}

	async function handleProfileSubmit(e: Event) {
		e.preventDefault();
		profileLoading = true;
		error = '';
		try {
			const res = await api.put<Profile>('/auth/profile', { email });
			profile = res;
			auth.setUser(res as any);
			addToast('success', m["common.Success"]());
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			error = msg;
			addToast('error', msg);
		} finally {
			profileLoading = false;
		}
	}

	async function handlePasswordSubmit(e: Event) {
		e.preventDefault();
		if (!validatePasswordForm()) return;

		passwordLoading = true;
		try {
			await api.put('/auth/password', {
				old_password: currentPassword,
				new_password: newPassword
			});
			currentPassword = '';
			newPassword = '';
			confirmPassword = '';
			fieldErrors = {};
			touched = {};
			addToast('success', m["auth.Change Password"]() + ' ' + m["common.Success"]());
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			addToast('error', msg);
		} finally {
			passwordLoading = false;
		}
	}

	function handleLangChange() {
		setLocale(lang);
		window.dispatchEvent(new CustomEvent('lang-change', { detail: lang }));
	}

	function handleThemeToggle() {
		const next = theme === 'dark' ? 'light' : 'dark';
		applyTheme(next);
	}

async function handle2FASetup() {
    twoFALoading = true;
    try {
        const res = await api.post<{ secret: string; qr_url: string; backup_codes: string[] }>('/auth/2fa/setup', {});
        twoFASetupData = res;
        twoFAQRDataUrl = await QRCode.toDataURL(res.qr_url, { width: 256, margin: 2, color: { dark: '#000000', light: '#ffffff' } });
    } catch (err: unknown) { addToast('error', getErrorMessage(err)); }
    finally { twoFALoading = false; }
}

async function handle2FAEnable(e: Event) {
    e.preventDefault();
    if (!twoFAVerifyCode || twoFAVerifyCode.length !== 6) { addToast('error', m["auth.2fa_invalid_code"]()); return; }
    twoFAVerifyLoading = true;
    try {
        await api.post('/auth/2fa/enable', { code: twoFAVerifyCode });
        twoFAEnabled = true; twoFASetupData = null; twoFAVerifyCode = '';
        addToast('success', m["auth.2fa_enabled_success"]());
    } catch (err: unknown) { addToast('error', getErrorMessage(err)); }
    finally { twoFAVerifyLoading = false; }
}

async function handle2FADisable(e: Event) {
    e.preventDefault();
    if (!twoFADisablePassword) return;
    twoFADisableLoading = true;
    try {
        await api.post('/auth/2fa/disable', { password: twoFADisablePassword });
        twoFAEnabled = false; show2FADisableModal = false;
        addToast('success', m["auth.2fa_disabled_success"]());
    } catch (err: unknown) { addToast('error', getErrorMessage(err)); }
    finally { twoFADisableLoading = false; }
}

function handleCopyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    addToast('success', m["auth.2fa_copied"]());
}

function handleCancel2FASetup() {
    twoFASetupData = null; twoFAQRDataUrl = ''; twoFAVerifyCode = '';
}
</script>

<div class="p-6 max-w-2xl">
	<h2 class="text-2xl font-bold text-primary mb-6">{m["navigation.Settings"]()}</h2>

	{#if loading}
		<div class="text-muted">{m["common.Loading"]()}...</div>
	{:else if error && !profile}
		<div class="px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{:else}
		{#if error}
			<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
				{error}
			</div>
		{/if}

		<!-- Profile section -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<h3 class="text-lg font-semibold text-text mb-4">{m["navigation.Profile"]()}</h3>
			<form onsubmit={handleProfileSubmit} class="space-y-4">
				<div>
				<label class="block text-xs text-muted mb-1">{m["auth.Username"]()}</label>
					<input value={profile?.username || ''} disabled
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-muted
							cursor-not-allowed opacity-60" />
				</div>
				<div>
				<label class="block text-xs text-muted mb-1">{m["auth.Email"]()}</label>
					<input bind:value={email} type="email"
						class="input" />
				</div>
				<div>
				<label class="block text-xs text-muted mb-1">{m["users.Role"]()}</label>
					<input value={profile?.role || ''} disabled
						class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-muted
							cursor-not-allowed opacity-60" />
				</div>
				<button type="submit" disabled={profileLoading}
					class="btn btn-primary">
					{profileLoading ? '...' : m["common.Save"]()}
				</button>
			</form>
		</div>

		<!-- Password section -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<h3 class="text-lg font-semibold text-text mb-4">{m["auth.Change Password"]()}</h3>
			<form onsubmit={handlePasswordSubmit} class="space-y-4">
				<div>
				<label class="block text-xs text-muted mb-1">{m["auth.Old Password"]()}</label>
					<input bind:value={currentPassword} type="password" required autocomplete="current-password"
						onblur={() => handleFieldBlur('currentPassword')}
						class="input" />
					{#if touched.currentPassword && fieldErrors.currentPassword}
						<p class="mt-1 text-xs text-error">{fieldErrors.currentPassword}</p>
					{/if}
				</div>
				<div>
				<label class="block text-xs text-muted mb-1">{m["auth.New Password"]()}</label>
					<input bind:value={newPassword} type="password" required autocomplete="new-password"
						onblur={() => handleFieldBlur('newPassword')}
						class="input" />
					{#if touched.newPassword && fieldErrors.newPassword}
						<p class="mt-1 text-xs text-error">{fieldErrors.newPassword}</p>
					{/if}
				</div>
				<div>
				<label class="block text-xs text-muted mb-1">{m["auth.Confirm Password"]()}</label>
					<input bind:value={confirmPassword} type="password" required autocomplete="new-password"
						onblur={() => handleFieldBlur('confirmPassword')}
						class="input" />
					{#if touched.confirmPassword && fieldErrors.confirmPassword}
						<p class="mt-1 text-xs text-error">{fieldErrors.confirmPassword}</p>
					{/if}
				</div>
				<button type="submit" disabled={passwordLoading}
					class="btn btn-primary">
					{passwordLoading ? '...' : m["auth.Change Password"]()}
				</button>
			</form>
		</div>

		<!-- Theme section -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<h3 class="text-lg font-semibold text-text mb-4">
				{m["settings.Appearance"]()}
			</h3>
			<div class="flex items-center gap-4">
				<button onclick={handleThemeToggle} class="btn btn-secondary">
					{#if theme === 'dark'}
						<Moon class="w-4 h-4" />
						Dark
					{:else}
						<Sun class="w-4 h-4" />
						Light
					{/if}
				</button>
				<span class="text-sm text-muted">
					{#if theme === 'dark'}
						{m["settings.Dark Mode"]()}
					{:else}
						{m["settings.Light Mode"]()}
					{/if}
				</span>
			</div>
		</div>

        <!-- 2FA section -->
        <div class="bg-surface border border-border rounded-xl p-6 mb-6">
            <h3 class="text-lg font-semibold text-text mb-4">{m["auth.2fa_title"]()}</h3>

            {#if twoFASetupData}
                <!-- Setup flow -->
                <div class="space-y-5">
                    <p class="text-sm text-muted">{m["auth.2fa_scan_qr"]()}</p>
                    <div class="flex justify-center">
                        {#if twoFAQRDataUrl}
                            <img src={twoFAQRDataUrl} alt="TOTP QR Code" class="w-64 h-64 rounded-lg border border-border" />
                        {/if}
                    </div>
                    <div>
                        <label class="block text-xs text-muted mb-1">{m["auth.2fa_secret"]()}</label>
                        <div class="flex items-center gap-2">
                            <code class="flex-1 px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text font-mono break-all select-all">{twoFASetupData.secret}</code>
                            <button type="button" onclick={() => handleCopyToClipboard(twoFASetupData!.secret)}
                                class="btn btn-secondary text-xs py-2 shrink-0">
                                <Copy class="w-3.5 h-3.5" />
                                {m["auth.2fa_copy_secret"]()}
                            </button>
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs text-muted mb-1">{m["auth.2fa_backup_codes"]()}</label>
                        <div class="p-3 bg-bg border border-border rounded-lg mb-2">
                            <div class="grid grid-cols-2 gap-1">
                                {#each twoFASetupData.backup_codes as code}
                                    <code class="text-sm text-text font-mono px-2 py-1 bg-surface rounded">{code}</code>
                                {/each}
                            </div>
                        </div>
                        <p class="text-xs text-warning mb-2">⚠ {m["auth.2fa_backup_codes_warning"]()}</p>
                        <button type="button" onclick={() => handleCopyToClipboard(twoFASetupData!.backup_codes.join('\n'))}
                            class="px-3 py-1.5 bg-bg border border-border rounded-lg text-xs text-muted hover:border-primary hover:text-text transition-colors">
                            {m["auth.2fa_copy_codes"]()}
                        </button>
                    </div>
                    <form onsubmit={handle2FAEnable} class="flex items-end gap-3">
                        <div class="flex-1">
                            <label class="block text-xs text-muted mb-1">{m["auth.2fa_verify_code"]()}</label>
                            <input type="text" maxlength="6" bind:value={twoFAVerifyCode} placeholder="000000"
                                class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text font-mono tracking-widest focus:border-primary focus:outline-none" />
                        </div>
                        <button type="button" onclick={handleCancel2FASetup}
                            class="btn btn-secondary">
                            {m["common.Cancel"]()}
                        </button>
                        <button type="submit" disabled={twoFAVerifyLoading}
                            class="btn btn-primary">
                            {twoFAVerifyLoading ? '...' : m["auth.2fa_confirm_enable"]()}
                        </button>
                    </form>
                </div>
            {:else if twoFAEnabled}
                <!-- Enabled state -->
                <div class="flex items-center justify-between">
                    <span class="inline-flex items-center gap-2 px-3 py-1.5 bg-success/15 text-success rounded-lg text-sm font-medium">
                        ✓ {m["auth.2fa_enabled"]()}
                    </span>
                    <button onclick={() => { twoFADisablePassword = ''; show2FADisableModal = true; }}
                        class="px-4 py-2 bg-error/10 text-error border border-error/20 rounded-lg text-sm font-medium hover:bg-error/20 transition-colors">
                        {m["auth.2fa_disable"]()}
                    </button>
                </div>
            {:else}
                <!-- Disabled state -->
                <div class="flex items-center justify-between">
                    <p class="text-sm text-muted">{m["auth.2fa_disabled"]()}</p>
                    <button onclick={handle2FASetup} disabled={twoFALoading}
                        class="btn btn-primary">
                        {twoFALoading ? '...' : m["auth.2fa_enable"]()}
                    </button>
                </div>
            {/if}
        </div>

		<!-- Language section -->
		<div class="bg-surface border border-border rounded-xl p-6">
			<h3 class="text-lg font-semibold text-text mb-4">Language / 语言</h3>
			<div class="flex items-center gap-4">
				<select bind:value={lang} onchange={handleLangChange}
					class="px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none">
					<option value="zh">中文</option>
					<option value="en">English</option>
				</select>
				<span class="text-sm text-muted">Current: {lang === 'zh' ? '中文' : 'English'}</span>
			</div>
		</div>

        <!-- 2FA disable modal -->
        <Modal bind:open={show2FADisableModal} title={m["auth.2fa_disable"]()} maxWidth="24rem" onclose={() => { twoFADisablePassword = ''; }}>
            <p class="text-sm text-muted mb-4">{m["auth.2fa_disable_confirm"]()}</p>
            <form onsubmit={handle2FADisable}>
                <input type="password" bind:value={twoFADisablePassword} placeholder="Current password"
                    class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text mb-3 focus:border-primary focus:outline-none" required />
                <div class="flex gap-2 justify-end">
                    <button type="button" onclick={() => show2FADisableModal = false}
                        class="px-3 py-1.5 border border-border text-muted rounded-lg text-sm">{m["common.Cancel"]()}</button>
                    <button type="submit" disabled={twoFADisableLoading}
                        class="px-3 py-1.5 bg-error text-text-inverse rounded-lg text-sm font-medium disabled:opacity-50">{twoFADisableLoading ? '...' : m["common.Delete"]()}</button>
                </div>
            </form>
        </Modal>
	{/if}
</div>
