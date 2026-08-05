/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 MiBee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { z } from 'zod';
import { m } from '$lib/i18n-paraglide';

// --- Custom validators ---

const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;

// --- i18n boundary ---
//
// Zod schema messages are stable CODES (the i18n key itself, e.g.
// 'validation.Name Required'). They are evaluated at schema-definition time
// and must NOT call into paraglide directly — otherwise the message would be
// frozen to whatever locale was active at module import and would not respond
// to a runtime locale switch. Instead, `translate()` resolves a code to the
// current locale's string at the moment validateField / validateForm return.
//
// Non-validation messages (backend-supplied strings, passthrough) are returned
// unchanged.

type MessageParams = Record<string, string>;

function translate(message: string | undefined, params?: MessageParams): string | undefined {
	if (!message) return message;
	if (message.startsWith('validation.')) {
		// paraglide compiles each key to a function on `m`; look it up dynamically.
		const fn = (m as unknown as Record<string, (p?: MessageParams) => string>)[message];
		if (typeof fn === 'function') {
			return params ? fn(params) : fn();
		}
	}
	return message;
}

// --- Schemas ---

export const deviceSchema = z.object({
	name: z.string().min(1, 'validation.Name Required'),
	type: z.string().min(1, 'validation.Type Required'),
	brand: z.string().optional(),
	model: z.string().optional(),
	location: z.string().optional(),
	purpose: z.string().optional(),
	ip_address: z.string()
		.regex(ipv4Regex, 'validation.Invalid IP Format')
		.refine(
			(val) => val.split('.').every((n) => parseInt(n) >= 0 && parseInt(n) <= 255),
			'validation.IP Octet Range'
		)
		.optional()
		.or(z.literal('')),
	mac_address: z.string()
		.regex(macRegex, 'validation.Invalid MAC Format')
		.optional()
		.or(z.literal('')),
	serial_number: z.string().optional(),
	purchase_date: z.string().optional(),
	warranty_expiry: z.string().optional(),
	description: z.string().optional(),
	tags: z.string().optional(),
});

export const userSchema = z.object({
	username: z.string().min(3, 'validation.Username Min Length'),
	email: z.string().email('validation.Invalid Email').optional().or(z.literal('')),
	password: z.string().min(8, 'validation.Password Min Length'),
	role: z.enum(['admin', 'user']),
});

export const heartbeatConfigSchema = z.object({
	device_id: z.number().int().positive('validation.Device Required'),
	method: z.enum(['ICMP', 'TCP', 'HTTP', 'SNMP']),
	target: z.string().min(1, 'validation.Target Required'),
	interval: z.number().int().min(1, 'validation.Interval Range').max(300, 'validation.Interval Range'),
	timeout: z.number().int().min(1, 'validation.Timeout Range').max(30, 'validation.Timeout Range'),
	enabled: z.boolean(),
	snmp_community: z.string().optional(),
	snmp_oid: z.string().optional(),
	expected_status: z.number().int().min(100).max(599).optional(),
});

export const documentUrlSchema = z.object({
	title: z.string().min(1, 'validation.Title Required'),
	url: z.string().url('validation.Invalid URL'),
	description: z.string().optional(),
});

export const loginSchema = z.object({
	username: z.string().min(1, 'validation.Username Required'),
	password: z.string().min(1, 'validation.Password Required'),
});

export const settingsSchema = z
	.object({
		currentPassword: z.string().min(1, 'validation.Current Password Required'),
		newPassword: z.string().min(8, 'validation.Password Min Length'),
		confirmPassword: z.string().min(1, 'validation.Confirm Password Required'),
	})
	.refine((data) => data.newPassword === data.confirmPassword, {
		message: 'validation.Passwords Do Not Match',
		path: ['confirmPassword'],
	});

// --- Profile form (settings page) ---
// Only `email` is editable (username/role are read-only), so the schema is a
// single optional-email field. Reuses the Invalid Email code.
export const profileSchema = z.object({
	email: z.string().email('validation.Invalid Email').optional().or(z.literal('')),
});

// --- Reset-password form (users page) ---
// Like settingsSchema but without currentPassword — the admin resets another
// user's password by token. The match refine attaches the error to `confirm`.
export const resetPasswordSchema = z
	.object({
		new_password: z.string().min(8, 'validation.Password Min Length'),
		confirm: z.string().min(1, 'validation.Confirm Password Required'),
	})
	.refine((data) => data.new_password === data.confirm, {
		message: 'validation.Passwords Do Not Match',
		path: ['confirm'],
	});

// --- 2FA verify code (login page) ---
// Exactly 6 digits. Used for the verify hint; the disabled-button gate stays
// in the markup.
export const twoFactorCodeSchema = z.object({
	code: z.string().regex(/^\d{6}$/, 'validation.Two Factor Code Length'),
});

// --- Network create/edit form (networks page) ---
// cidr is advisory (display-only per networks.Cidr Help), but when supplied it
// must be a well-formed x.x.x.x/n with valid octets and a 0-32 prefix.
const cidrRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
export const networkSchema = z.object({
	name: z.string().min(1, 'validation.Name Required'),
	cidr: z
		.string()
		.regex(cidrRegex, 'validation.Invalid CIDR Format')
		.refine(
			(val) => {
				const [ip, prefix] = val.split('/');
				return isValidOctets(ip) && Number(prefix) >= 0 && Number(prefix) <= 32;
			},
			{ message: 'validation.Invalid CIDR Octets' }
		)
		.optional()
		.or(z.literal('')),
	site: z.string().optional(),
});

// --- Agent token create form (agents page) ---
// network_id is a number (the <select> value is coerced via Number()).
export const agentTokenSchema = z.object({
	agent_id: z.string().min(1, 'validation.Agent ID Required'),
	network_id: z.number().int().positive('validation.Network Required'),
	name: z.string().optional(),
});

// --- Notification channel form (settings/notifications page) ---
// A flat schema (form state is flat: formUrl, formSmtpHost, ...) with a refine
// enforcing type-conditional required fields — simpler than a Zod
// discriminated union and keeps per-field blur validation working.
export const notificationChannelSchema = z
	.object({
		name: z.string().min(1, 'validation.Name Required'),
		type: z.enum(['webhook', 'email']),
		webhook_url: z.string().url('validation.Invalid URL').optional().or(z.literal('')),
		smtp_host: z.string().optional().or(z.literal('')),
		smtp_port: z.number().int().min(1).max(65535, 'validation.Invalid Port').optional(),
		smtp_from: z.string().optional().or(z.literal('')),
		smtp_to: z.string().optional().or(z.literal('')),
	})
	.refine((data) => data.type !== 'webhook' || !!data.webhook_url, {
		message: 'validation.Webhook URL Required',
		path: ['webhook_url'],
	})
	.refine((data) => data.type !== 'email' || !!data.smtp_host, {
		message: 'validation.SMTP Host Required',
		path: ['smtp_host'],
	})
	.refine((data) => data.type !== 'email' || !!data.smtp_from, {
		message: 'validation.SMTP From Required',
		path: ['smtp_from'],
	})
	.refine((data) => data.type !== 'email' || !!data.smtp_to, {
		message: 'validation.SMTP To Required',
		path: ['smtp_to'],
	});

// --- Notification rule form (settings/notifications rules tab, #139) ---
// Validates name, event/scope enums, channel presence, and the scope-conditional
// required field (network needs scope_network_id, device needs scope_device_uuid).
export const notificationRuleSchema = z
	.object({
		name: z.string().min(1, 'validation.Name Required'),
		event_type: z.enum(['device_lost', 'device_recovered', 'device_added', 'device_changed']),
		scope_type: z.enum(['all', 'network', 'device']),
		scope_network_id: z.union([z.number().int().positive(), z.null()]).optional(),
		scope_device_uuid: z.string().optional().or(z.literal('')),
		channel_id: z.number().int().positive('validation.Channel Required'),
		cooldown_minutes: z.number().int().min(1, 'validation.Cooldown Min').max(10080),
	})
	.refine((data) => data.scope_type !== 'network' || (!!data.scope_network_id && data.scope_network_id > 0), {
		message: 'validation.Network Required',
		path: ['scope_network_id'],
	})
	.refine((data) => data.scope_type !== 'device' || !!data.scope_device_uuid, {
		message: 'validation.Device Required',
		path: ['scope_device_uuid'],
	});

// --- Scanner task form (devices/scan-tasks page) ---
// targets + cron are validated by the standalone validateScanTarget /
// validateCronExpr functions (kept as-is — they return localized strings and
// are already wired to onblur). This schema covers name + timeout range only;
// pipeline_config is deliberately not validated (complex nested object, the
// backend accepts any shape).
export const scannerTaskSchema = z.object({
	name: z.string().min(1, 'validation.Task Name Required'),
	timeout: z.number().int().min(1).max(3600, 'validation.Timeout Range Task'),
});

// --- Inferred types ---

export type DeviceFormData = z.infer<typeof deviceSchema>;
export type UserFormData = z.infer<typeof userSchema>;
export type HeartbeatConfigFormData = z.infer<typeof heartbeatConfigSchema>;
export type DocumentUrlFormData = z.infer<typeof documentUrlSchema>;
export type LoginFormData = z.infer<typeof loginSchema>;
export type SettingsFormData = z.infer<typeof settingsSchema>;
export type ProfileFormData = z.infer<typeof profileSchema>;
export type ResetPasswordFormData = z.infer<typeof resetPasswordSchema>;
export type TwoFactorCodeFormData = z.infer<typeof twoFactorCodeSchema>;
export type NetworkFormData = z.infer<typeof networkSchema>;
export type AgentTokenFormData = z.infer<typeof agentTokenSchema>;
export type NotificationChannelFormData = z.infer<typeof notificationChannelSchema>;
export type ScannerTaskFormData = z.infer<typeof scannerTaskSchema>;

// --- Helper functions ---

export function validateField<T>(
	schema: z.ZodType<T>,
	field: keyof T & string,
	value: unknown
): { valid: boolean; error?: string } {
	const fieldSchema = schema.pick({ [field]: true } as { [K in keyof T]: true });
	const result = fieldSchema.safeParse({ [field]: value });
	if (result.success) {
		return { valid: true };
	}
	const firstIssue = result.error.issues[0];
	return { valid: false, error: translate(firstIssue?.message) };
}

export function validateForm<T>(
	schema: z.ZodType<T>,
	data: unknown
): { valid: boolean; errors: Record<string, string> } {
	const result = schema.safeParse(data);
	if (result.success) {
		return { valid: true, errors: {} };
	}
	const errors: Record<string, string> = {};
	for (const issue of result.error.issues) {
		const key = issue.path.join('.');
		if (!errors[key]) {
			errors[key] = translate(issue.message) ?? issue.message;
		}
	}
	return { valid: false, errors };
}

// --- Scan target validation ---

const ipv4OctetPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function isValidOctets(ip: string): boolean {
	const octets = ip.split('.').map(Number);
	return octets.length === 4 && octets.every(o => o >= 0 && o <= 255);
}

/** isValidIP checks a single IPv4 address (no CIDR/range/list). Reused by
 *  validateScanTarget below and exported for callers that validate one IP at
 *  a time — e.g. the CSV import preview flagging malformed rows. */
export function isValidIP(ip: string): boolean {
	return ipv4OctetPattern.test(ip.trim()) && isValidOctets(ip.trim());
}

/**
 * Validates scan target(s) input.
 * Accepts: single IP, CIDR notation, comma-separated list, IP ranges (1.1.1.1-10).
 * Returns a localized error message string or null if valid.
 */
export function validateScanTarget(value: string): string | null {
	if (!value.trim()) return m['validation.Targets Required']();

	const targets = value.split(',').map(t => t.trim()).filter(t => t.length > 0);
	if (targets.length === 0) return m['validation.Targets Required']();

	for (const target of targets) {
		// Single IP
		if (ipv4OctetPattern.test(target)) {
			if (!isValidOctets(target)) {
				return m['validation.Invalid IP']({ target });
			}
			continue;
		}

		// CIDR notation
		const cidrMatch = target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
		if (cidrMatch) {
			if (!isValidOctets(cidrMatch[1])) {
				return m['validation.Invalid CIDR IP']({ target });
			}
			const prefix = parseInt(cidrMatch[2], 10);
			if (prefix < 0 || prefix > 32) {
				return m['validation.Invalid CIDR Prefix']({ target });
			}
			continue;
		}

		// IP range (1.1.1.1-10)
		const rangeMatch = target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$/);
		if (rangeMatch) {
			if (!isValidOctets(rangeMatch[1])) {
				return m['validation.Invalid Range IP']({ target });
			}
			const rangeEnd = parseInt(rangeMatch[2], 10);
			if (rangeEnd < 0 || rangeEnd > 255) {
				return m['validation.Invalid Range End']({ target });
			}
			continue;
		}

		return m['validation.Invalid Target']({ target });
	}

	return null;
}

/**
 * Validates a 5-field cron expression.
 * Returns a localized error message string or null if valid.
 */
export function validateCronExpr(value: string): string | null {
	if (!value.trim()) return m['validation.Cron Required']();

	const parts = value.trim().split(/\s+/);
	if (parts.length !== 5) {
		return m['validation.Cron Field Count']();
	}

	// Each field: *, */N, number, number-number range, or comma-separated list
	const fieldPattern = /^(\*|\*\/\d+|\d+(-\d+)?(,\d+(-\d+)?)*)$/;
	// Cron field names are technical terms; the i18n template embeds them as-is
	// (zh translation keeps the English field name, e.g. "Cron 的 minute 字段无效").
	const fieldNames = ['minute', 'hour', 'day', 'month', 'weekday'];

	let isAllAsterisks = true;
	for (let i = 0; i < 5; i++) {
		if (parts[i] !== '*') isAllAsterisks = false;
		if (!fieldPattern.test(parts[i])) {
			return m['validation.Invalid Cron Field']({ field: fieldNames[i], value: parts[i] });
		}
	}

	if (isAllAsterisks) {
		return m['validation.Cron All Asterisks']();
	}

	return null;
}
