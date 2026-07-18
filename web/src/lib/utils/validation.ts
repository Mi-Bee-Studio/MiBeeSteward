/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { z } from 'zod';

// --- Custom validators ---

const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;

// --- Schemas ---

export const deviceSchema = z.object({
	name: z.string().min(1, 'Name is required'),
	type: z.string().min(1, 'Type is required'),
	brand: z.string().optional(),
	model: z.string().optional(),
	location: z.string().optional(),
	purpose: z.string().optional(),
	ip_address: z.string()
		.regex(ipv4Regex, 'Invalid IP address format')
		.refine(
			(val) => val.split('.').every((n) => parseInt(n) >= 0 && parseInt(n) <= 255),
			'Each IP octet must be 0-255'
		)
		.optional()
		.or(z.literal('')),
	mac_address: z.string()
		.regex(macRegex, 'Invalid MAC address (use AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)')
		.optional()
		.or(z.literal('')),
	serial_number: z.string().optional(),
	purchase_date: z.string().optional(),
	warranty_expiry: z.string().optional(),
	description: z.string().optional(),
	tags: z.string().optional(),
});

export const userSchema = z.object({
	username: z.string().min(3, 'Username must be at least 3 characters'),
	email: z.string().email('Invalid email').optional().or(z.literal('')),
	password: z.string().min(8, 'Password must be at least 8 characters'),
	role: z.enum(['admin', 'user']),
});

export const heartbeatConfigSchema = z.object({
	device_id: z.number().int().positive('Device is required'),
	method: z.enum(['ICMP', 'TCP', 'HTTP', 'SNMP']),
	target: z.string().min(1, 'Target is required'),
	interval: z.number().int().min(1, 'Interval must be at least 1s').max(300, 'Interval must be at most 300s'),
	timeout: z.number().int().min(1, 'Timeout must be at least 1s').max(30, 'Timeout must be at most 30s'),
	enabled: z.boolean(),
	snmp_community: z.string().optional(),
	snmp_oid: z.string().optional(),
	expected_status: z.number().int().min(100).max(599).optional(),
});

export const documentUrlSchema = z.object({
	title: z.string().min(1, 'Title is required'),
	url: z.string().url('Invalid URL'),
	description: z.string().optional(),
});

export const loginSchema = z.object({
	username: z.string().min(1, 'Username is required'),
	password: z.string().min(1, 'Password is required'),
});

export const settingsSchema = z
	.object({
		currentPassword: z.string().min(1, 'Current password is required'),
		newPassword: z.string().min(8, 'New password must be at least 8 characters'),
		confirmPassword: z.string().min(1, 'Please confirm your password'),
	})
	.refine((data) => data.newPassword === data.confirmPassword, {
		message: 'Passwords do not match',
		path: ['confirmPassword'],
	});

// --- Inferred types ---

export type DeviceFormData = z.infer<typeof deviceSchema>;
export type UserFormData = z.infer<typeof userSchema>;
export type HeartbeatConfigFormData = z.infer<typeof heartbeatConfigSchema>;
export type DocumentUrlFormData = z.infer<typeof documentUrlSchema>;
export type LoginFormData = z.infer<typeof loginSchema>;
export type SettingsFormData = z.infer<typeof settingsSchema>;

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
	return { valid: false, error: firstIssue?.message };
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
			errors[key] = issue.message;
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

/**
 * Validates scan target(s) input.
 * Accepts: single IP, CIDR notation, comma-separated list, IP ranges (1.1.1.1-10).
 * Returns error message string or null if valid.
 */
export function validateScanTarget(value: string): string | null {
	if (!value.trim()) return 'Targets are required';

	const targets = value.split(',').map(t => t.trim()).filter(t => t.length > 0);
	if (targets.length === 0) return 'Targets are required';

	for (const target of targets) {
		// Single IP
		if (ipv4OctetPattern.test(target)) {
			if (!isValidOctets(target)) {
				return `Invalid IP: ${target} (octets must be 0-255)`;
			}
			continue;
		}

		// CIDR notation
		const cidrMatch = target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
		if (cidrMatch) {
			if (!isValidOctets(cidrMatch[1])) {
				return `Invalid IP in CIDR: ${target} (octets must be 0-255)`;
			}
			const prefix = parseInt(cidrMatch[2], 10);
			if (prefix < 0 || prefix > 32) {
				return `Invalid CIDR prefix: ${target} (prefix must be 0-32)`;
			}
			continue;
		}

		// IP range (1.1.1.1-10)
		const rangeMatch = target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$/);
		if (rangeMatch) {
			if (!isValidOctets(rangeMatch[1])) {
				return `Invalid IP in range: ${target} (octets must be 0-255)`;
			}
			const rangeEnd = parseInt(rangeMatch[2], 10);
			if (rangeEnd < 0 || rangeEnd > 255) {
				return `Invalid range end: ${target} (range end must be 0-255)`;
			}
			continue;
		}

		return `Invalid target: "${target}" — must be an IP, CIDR, or IP range`;
	}

	return null;
}

/**
 * Validates a 5-field cron expression.
 * Returns error message string or null if valid.
 */
export function validateCronExpr(value: string): string | null {
	if (!value.trim()) return 'Cron expression is required';

	const parts = value.trim().split(/\s+/);
	if (parts.length !== 5) {
		return 'Cron expression must have exactly 5 fields (minute hour day month weekday)';
	}

	// Each field: *, */N, number, number-number range, or comma-separated list
	const fieldPattern = /^(\*|\*\/\d+|\d+(-\d+)?(,\d+(-\d+)?)*)$/;
	const fieldNames = ['minute', 'hour', 'day', 'month', 'weekday'];

	let isAllAsterisks = true;
	for (let i = 0; i < 5; i++) {
		if (parts[i] !== '*') isAllAsterisks = false;
		if (!fieldPattern.test(parts[i])) {
			return `Invalid cron ${fieldNames[i]} field: "${parts[i]}"`;
		}
	}

	if (isAllAsterisks) {
		return 'Cron expression must have at least one specific field (cannot be all *)';
	}

	return null;
}
