/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { m } from '$lib/i18n-paraglide';

/**
 * Shared status→badge maps. Each returns a localized `{ label, cls }` pair so
 * backend enum values never reach the user as raw English. The `cls` follows
 * the tailwind badge convention used across the app
 * (`bg-<tone>/10 text-<tone>`). Unknown values fall back to a neutral badge
 * and the raw string so new backend states remain visible rather than blank.
 *
 * Pattern cribbed from src/routes/agents/+page.svelte (commandStatusBadge).
 */

export interface Badge {
	label: string;
	cls: string;
}

/**
 * Scan run lifecycle (5 states, per internal/service/scannerv2/runner + taskservice):
 * running / completed / failed / cancelled / triggered.
 */
export function scanRunStatusBadge(status: string): Badge {
	switch (status) {
		case 'running':
			return { label: m['scanner.Running'](), cls: 'bg-warning/10 text-warning' };
		case 'completed':
			return { label: m['scanner.Completed'](), cls: 'bg-success/10 text-success' };
		case 'failed':
			return { label: m['scanner.Failed'](), cls: 'bg-error/10 text-error' };
		case 'cancelled':
			return { label: m['scanner.Cancelled'](), cls: 'bg-surface text-text-muted border border-border' };
		case 'triggered':
			return { label: m['scanner.Status Triggered'](), cls: 'bg-accent/10 text-accent' };
		default:
			return { label: status, cls: 'bg-surface text-text-muted border border-border' };
	}
}

/**
 * Discovery event outcome (4 states, per internal/service/scannerv2/discovery):
 * recorded / skipped_known / skipped_recent / identify_failed.
 */
export function discoveryOutcomeBadge(outcome: string): Badge {
	switch (outcome) {
		case 'recorded':
			return { label: m['discovery.Recorded'](), cls: 'bg-success/10 text-success' };
		case 'skipped_known':
			return { label: m['discovery.Skipped Known'](), cls: 'bg-surface text-text-muted border border-border' };
		case 'skipped_recent':
			return { label: m['discovery.Skipped Recent'](), cls: 'bg-warning/10 text-warning' };
		case 'identify_failed':
			return { label: m['discovery.Identify Failed'](), cls: 'bg-error/10 text-error' };
		default:
			return { label: outcome, cls: 'bg-surface text-text-muted border border-border' };
	}
}

/**
 * Notification channel type (2 states, per internal/domain/notification):
 * webhook / email.
 */
export function channelTypeBadge(type: string): Badge {
	switch (type) {
		case 'webhook':
			return { label: m['notifications.Webhook'](), cls: 'bg-accent/10 text-accent' };
		case 'email':
			return { label: m['notifications.Email'](), cls: 'bg-primary/10 text-primary' };
		case 'feishu':
			return { label: m['notifications.Feishu'](), cls: 'bg-success/10 text-success' };
		case 'wecom':
			return { label: m['notifications.WeCom'](), cls: 'bg-primary/10 text-primary' };
		case 'telegram':
			return { label: m['notifications.Telegram'](), cls: 'bg-accent/10 text-accent' };
		case 'discord':
			return { label: m['notifications.Discord'](), cls: 'bg-accent-purple/10 text-accent-purple' };
		default:
			return { label: type, cls: 'bg-surface text-text-muted border border-border' };
	}
}

/**
 * Localized on/off for boolean flags rendered as a status word.
 * Treats undefined/null as "off" (flags default off in the backend config).
 */
export function onOffBadge(value: boolean | undefined | null): Badge {
	return value
		? { label: m['common.On'](), cls: 'bg-success/10 text-success' }
		: { label: m['common.Off'](), cls: 'bg-surface text-text-muted border border-border' };
}
