<script lang="ts">
	import Modal from './Modal.svelte';
	import { m } from '$lib/i18n-paraglide';
	import type { TLSPortCerts, CertificateInfo } from '$lib/types';
	import { ShieldCheck, ShieldAlert, ShieldX, Copy, Check, ChevronDown } from '@lucide/svelte';

	let {
		open = $bindable(false),
		portCerts = null as TLSPortCerts | null,
		onClose
	}: {
		open?: boolean;
		portCerts?: TLSPortCerts | null;
		onClose?: () => void;
	} = $props();

	// Per-chain-entry expanded state — default to leaf expanded so the user
	// sees the most relevant cert first. Keyed by cert_index.
	let expandedChain = $state<Record<number, boolean>>({ 0: true });

	// Per-cert "copied" feedback state. Cleared on a timeout.
	let copiedIndex = $state<number | null>(null);

	// Reset expanded/copy state whenever a new port is opened.
	$effect(() => {
		if (open && portCerts) {
			expandedChain = { 0: true };
			copiedIndex = null;
		}
	});

	function toggleChainEntry(idx: number) {
		expandedChain[idx] = !expandedChain[idx];
	}

	async function copyPEM(idx: number, pem: string) {
		try {
			await navigator.clipboard.writeText(pem);
			copiedIndex = idx;
			setTimeout(() => {
				if (copiedIndex === idx) copiedIndex = null;
			}, 1500);
		} catch {
			// Clipboard API may be unavailable (insecure context); fall back to
			// selecting the <pre> text. We don't auto-select to avoid jarring UX.
		}
	}

	// Expiry classification for the status badge.
	type Status = 'expired' | 'expiring' | 'valid' | 'error';
	function statusOf(port: TLSPortCerts | null): Status {
		if (!port) return 'error';
		if (port.error) return 'error';
		if (!port.leaf) return 'error';
		const now = Date.now();
		const after = Date.parse(port.leaf.not_after);
		if (Number.isNaN(after)) return 'error';
		if (after < now) return 'expired';
		// 15-day warning window — short enough to be actionable, long enough to
		// catch monthly rotations.
		if (after - now < 15 * 24 * 3600 * 1000) return 'expiring';
		return 'valid';
	}

	// Signed day delta (positive = expires in N days; negative = expired N days ago).
	function dayDelta(iso: string): number {
		const t = Date.parse(iso);
		if (Number.isNaN(t)) return 0;
		return Math.ceil((t - Date.now()) / (24 * 3600 * 1000));
	}

	// Format an ISO 8601 string as a locale-friendly YYYY-MM-DD for display.
	function fmtDate(iso: string): string {
		if (!iso) return '—';
		const t = Date.parse(iso);
		if (Number.isNaN(t)) return iso;
		return new Date(t).toISOString().slice(0, 10);
	}

	function statusLabel(s: Status, port: TLSPortCerts | null): string {
		if (!port || !port.leaf) return m['certificates.CollectionError']();
		const d = Math.abs(dayDelta(port.leaf.not_after));
		switch (s) {
			case 'expired':
				return m['certificates.Expired']({ days: d });
			case 'expiring':
				return m['certificates.ExpiringSoon']({ days: d });
			case 'valid':
				return m['certificates.ValidFor']({ days: d });
			case 'error':
				return port.error || m['certificates.CollectionError']();
		}
	}

	function chainRole(idx: number, total: number): string {
		if (idx === 0) return m['certificates.Leaf']();
		if (idx === total - 1) return m['certificates.Root']();
		return m['certificates.Intermediate']();
	}

	// Display: the leaf's SANs as a single comma-joined string for compactness.
	function sanDisplay(cert: CertificateInfo): string {
		const parts: string[] = [];
		if (cert.san_dns) parts.push(cert.san_dns);
		if (cert.san_ip) parts.push(cert.san_ip);
		if (cert.san_email) parts.push(cert.san_email);
		return parts.join(', ') || '—';
	}

	// Group the fingerprint into colon-separated bytes for readability, matching
	// the openssl-format convention operators expect. Input is uppercase hex
	// without separators (e.g. "AB12CD...") — we want "AB:12:CD:...".
	function fmtFingerprint(fp: string): string {
		if (!fp) return '—';
		return fp.replace(/(.{2})/g, '$1:').replace(/:$/, '');
	}

	let status = $derived(statusOf(portCerts));
</script>

<Modal bind:open maxWidth="42rem" title={m['certificates.Title']()} {onClose}>
	{#if portCerts}
		<!-- Status header: shield icon + colored badge. Tells the whole story at a glance. -->
		<div
			class="cert-status"
			data-status={status}
		>
			<div class="cert-status-icon">
				{#if status === 'valid'}
					<ShieldCheck class="w-5 h-5" />
				{:else if status === 'expiring'}
					<ShieldAlert class="w-5 h-5" />
				{:else}
					<ShieldX class="w-5 h-5" />
				{/if}
			</div>
			<div class="cert-status-text">
				<div class="cert-status-port">
					{m['certificates.Port']()} :{portCerts.port}
					{#if portCerts.tls_version}
						<span class="cert-status-tls">{portCerts.tls_version}</span>
					{/if}
				</div>
				<div class="cert-status-label">{statusLabel(status, portCerts)}</div>
			</div>
			{#if portCerts.trusted}
				<span class="cert-badge cert-badge-trusted">{m['certificates.Trusted']()}</span>
			{/if}
			{#if portCerts.leaf?.self_signed}
				<span class="cert-badge cert-badge-self">{m['certificates.SelfSigned']()}</span>
			{/if}
		</div>

		{#if portCerts.error}
			<div class="cert-error-box">
				<p>{m['certificates.CollectionError']()}</p>
				<code>{portCerts.error}</code>
			</div>
		{:else if portCerts.leaf}
			<!-- Leaf summary grid — the most-asked fields surfaced for at-a-glance. -->
			<div class="cert-grid">
				<div class="cert-field">
					<div class="cert-field-label">{m['certificates.Subject']()}</div>
					<div class="cert-field-value">{portCerts.leaf.subject_cn || portCerts.leaf.subject}</div>
				</div>
				<div class="cert-field">
					<div class="cert-field-label">{m['certificates.Issuer']()}</div>
					<div class="cert-field-value">{portCerts.leaf.issuer_cn || portCerts.leaf.issuer}</div>
				</div>
				<div class="cert-field">
					<div class="cert-field-label">{m['certificates.IssuedOn']()}</div>
					<div class="cert-field-value">{fmtDate(portCerts.leaf.not_before)}</div>
				</div>
				<div class="cert-field">
					<div class="cert-field-label">{m['certificates.ExpiresOn']()}</div>
					<div class="cert-field-value">{fmtDate(portCerts.leaf.not_after)}</div>
				</div>
				<div class="cert-field cert-field-wide">
					<div class="cert-field-label">{m['certificates.SAN']()}</div>
					<div class="cert-field-value cert-mono">{sanDisplay(portCerts.leaf)}</div>
				</div>
				<div class="cert-field">
					<div class="cert-field-label">{m['certificates.SignatureAlgorithm']()}</div>
					<div class="cert-field-value">{portCerts.leaf.sig_algorithm || '—'}</div>
				</div>
				<div class="cert-field">
					<div class="cert-field-label">{m['certificates.KeyAlgorithm']()}</div>
					<div class="cert-field-value">
						{portCerts.leaf.key_algorithm || '—'}{#if portCerts.leaf.key_bits} ({portCerts.leaf.key_bits} bits){/if}
					</div>
				</div>
				<div class="cert-field cert-field-wide">
					<div class="cert-field-label">{m['certificates.Fingerprint']()}</div>
					<div class="cert-field-value cert-mono cert-fp">{fmtFingerprint(portCerts.leaf.fingerprint_sha256)}</div>
				</div>
			</div>

			{#if portCerts.cipher_suite}
				<div class="cert-handshake">
					<span class="cert-handshake-label">{m['certificates.CipherSuite']()}:</span>
					<code class="cert-mono">{portCerts.cipher_suite}</code>
				</div>
			{/if}

			<!-- Certificate chain: one collapsible entry per cert (leaf, intermediates, root). -->
			{#if portCerts.chain.length > 0}
				<div class="cert-chain">
					<div class="cert-chain-title">{m['certificates.Chain']()} ({portCerts.chain.length})</div>
					{#each portCerts.chain as cert, i (cert.cert_index)}
						<div class="cert-chain-entry">
							<button
								class="cert-chain-header"
								onclick={() => toggleChainEntry(cert.cert_index)}
								aria-expanded={expandedChain[cert.cert_index] ?? false}
							>
								<ChevronDown class={`w-4 h-4 cert-chevron ${expandedChain[cert.cert_index] ? 'rotated' : ''}`} />
								<span class="cert-chain-role">{chainRole(i, portCerts.chain.length)}</span>
								<span class="cert-chain-cn">{cert.subject_cn || cert.subject || '—'}</span>
								{#if cert.is_ca}
									<span class="cert-chain-ca">CA</span>
								{/if}
							</button>
							{#if expandedChain[cert.cert_index]}
								<div class="cert-chain-body">
									<div class="cert-grid cert-grid-compact">
										<div class="cert-field">
											<div class="cert-field-label">{m['certificates.Subject']()}</div>
											<div class="cert-field-value cert-mono">{cert.subject || '—'}</div>
										</div>
										<div class="cert-field">
											<div class="cert-field-label">{m['certificates.Issuer']()}</div>
											<div class="cert-field-value cert-mono">{cert.issuer || '—'}</div>
										</div>
										<div class="cert-field">
											<div class="cert-field-label">{m['certificates.Serial']()}</div>
											<div class="cert-field-value cert-mono">{cert.serial || '—'}</div>
										</div>
										<div class="cert-field">
											<div class="cert-field-label">{m['certificates.ExpiresOn']()}</div>
											<div class="cert-field-value">{fmtDate(cert.not_after)}</div>
										</div>
									</div>
									{#if cert.pem}
										<div class="cert-pem-row">
											<div class="cert-pem-header">
												<span class="cert-field-label">{m['certificates.PEM']()}</span>
												<button
													class="cert-copy-btn"
													onclick={() => copyPEM(cert.cert_index, cert.pem)}
												>
													{#if copiedIndex === cert.cert_index}
														<Check class="w-3.5 h-3.5" />{m['certificates.Copied']()}
													{:else}
														<Copy class="w-3.5 h-3.5" />{m['certificates.CopyPEM']()}
													{/if}
												</button>
											</div>
											<pre class="cert-pem">{cert.pem}</pre>
										</div>
									{/if}
								</div>
							{/if}
						</div>
					{/each}
				</div>
			{/if}
		{/if}
	{/if}
</Modal>

<style>
	/* Status header */
	.cert-status {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
		border-radius: var(--radius-md);
		margin-bottom: 1rem;
		border: 1px solid var(--color-border);
	}
	.cert-status[data-status='valid'] {
		background: color-mix(in srgb, var(--color-success) 12%, transparent);
		border-color: color-mix(in srgb, var(--color-success) 35%, transparent);
	}
	.cert-status[data-status='expiring'] {
		background: color-mix(in srgb, var(--color-warning) 12%, transparent);
		border-color: color-mix(in srgb, var(--color-warning) 35%, transparent);
	}
	.cert-status[data-status='expired'],
	.cert-status[data-status='error'] {
		background: color-mix(in srgb, var(--color-error) 12%, transparent);
		border-color: color-mix(in srgb, var(--color-error) 35%, transparent);
	}
	.cert-status[data-status='valid'] .cert-status-icon { color: var(--color-success); }
	.cert-status[data-status='expiring'] .cert-status-icon { color: var(--color-warning); }
	.cert-status[data-status='expired'] .cert-status-icon,
	.cert-status[data-status='error'] .cert-status-icon { color: var(--color-error); }

	.cert-status-icon {
		flex-shrink: 0;
		display: flex;
	}
	.cert-status-text {
		flex: 1;
		min-width: 0;
	}
	.cert-status-port {
		font-weight: 600;
		color: var(--color-text);
		font-size: 0.9375rem;
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.cert-status-tls {
		font-size: 0.75rem;
		font-family: var(--font-mono, monospace);
		padding: 0.0625rem 0.375rem;
		border-radius: var(--radius-sm);
		background: var(--color-surface-2);
		color: var(--color-text-muted);
	}
	.cert-status-label {
		font-size: 0.8125rem;
		color: var(--color-text-muted);
		margin-top: 0.125rem;
	}

	/* Badges */
	.cert-badge {
		font-size: 0.6875rem;
		font-weight: 600;
		padding: 0.1875rem 0.5rem;
		border-radius: 9999px;
		text-transform: uppercase;
		letter-spacing: 0.02em;
		flex-shrink: 0;
	}
	.cert-badge-trusted {
		background: color-mix(in srgb, var(--color-success) 18%, transparent);
		color: var(--color-success);
	}
	.cert-badge-self {
		background: color-mix(in srgb, var(--color-warning) 18%, transparent);
		color: var(--color-warning);
	}

	/* Error box */
	.cert-error-box {
		padding: 0.75rem 1rem;
		background: color-mix(in srgb, var(--color-error) 8%, transparent);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-error);
	}
	.cert-error-box code {
		display: block;
		margin-top: 0.375rem;
		font-family: var(--font-mono, monospace);
		font-size: 0.75rem;
		word-break: break-all;
	}

	/* Field grid */
	.cert-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem 1.25rem;
		margin-bottom: 1rem;
	}
	.cert-grid-compact {
		gap: 0.5rem 1rem;
		margin-bottom: 0.75rem;
	}
	.cert-field {
		min-width: 0;
	}
	.cert-field-wide {
		grid-column: 1 / -1;
	}
	.cert-field-label {
		font-size: 0.6875rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--color-text-muted);
		margin-bottom: 0.1875rem;
	}
	.cert-field-value {
		font-size: 0.8125rem;
		color: var(--color-text);
		word-break: break-word;
	}
	.cert-mono {
		font-family: var(--font-mono, monospace);
		font-size: 0.75rem;
	}
	.cert-fp {
		word-break: break-all;
		line-height: 1.5;
	}

	/* Handshake summary */
	.cert-handshake {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.8125rem;
		color: var(--color-text-muted);
		padding: 0.5rem 0.75rem;
		background: var(--color-surface-2);
		border-radius: var(--radius-sm);
		margin-bottom: 1rem;
	}

	/* Chain */
	.cert-chain {
		border-top: 1px solid var(--color-border);
		padding-top: 0.875rem;
	}
	.cert-chain-title {
		font-size: 0.8125rem;
		font-weight: 600;
		color: var(--color-text);
		margin-bottom: 0.5rem;
	}
	.cert-chain-entry {
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		margin-bottom: 0.375rem;
		overflow: hidden;
	}
	.cert-chain-header {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.5rem 0.625rem;
		background: var(--color-surface-2);
		border: none;
		cursor: pointer;
		text-align: left;
		color: var(--color-text);
		font-size: 0.8125rem;
	}
	.cert-chain-header:hover {
		background: color-mix(in srgb, var(--color-surface-2) 80%, var(--color-primary) 10%);
	}
	.cert-chevron {
		transition: transform 0.15s ease;
		flex-shrink: 0;
		color: var(--color-text-muted);
	}
	.cert-chevron.rotated {
		transform: rotate(-90deg);
	}
	.cert-chain-role {
		font-size: 0.6875rem;
		font-weight: 600;
		text-transform: uppercase;
		color: var(--color-primary);
		flex-shrink: 0;
		min-width: 4.5rem;
	}
	.cert-chain-cn {
		flex: 1;
		min-width: 0;
		font-family: var(--font-mono, monospace);
		font-size: 0.75rem;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.cert-chain-ca {
		font-size: 0.625rem;
		font-weight: 700;
		padding: 0.0625rem 0.3125rem;
		border-radius: var(--radius-sm);
		background: color-mix(in srgb, var(--color-info) 18%, transparent);
		color: var(--color-info);
		flex-shrink: 0;
	}
	.cert-chain-body {
		padding: 0.75rem;
		border-top: 1px solid var(--color-border);
	}

	/* PEM block */
	.cert-pem-row {
		margin-top: 0.625rem;
	}
	.cert-pem-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 0.3125rem;
	}
	.cert-copy-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		font-size: 0.6875rem;
		padding: 0.1875rem 0.5rem;
		border-radius: var(--radius-sm);
		border: 1px solid var(--color-border);
		background: var(--color-surface);
		color: var(--color-text-muted);
		cursor: pointer;
	}
	.cert-copy-btn:hover {
		color: var(--color-primary);
		border-color: var(--color-primary);
	}
	.cert-pem {
		font-family: var(--font-mono, monospace);
		font-size: 0.6875rem;
		line-height: 1.5;
		color: var(--color-text);
		background: var(--color-surface-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		padding: 0.5rem 0.625rem;
		overflow-x: auto;
		margin: 0;
		white-space: pre;
		max-height: 12rem;
	}

	@media (max-width: 480px) {
		.cert-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
