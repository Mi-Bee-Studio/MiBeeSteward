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

import { describe, expect, it } from 'vitest';
import {
	deviceSchema,
	userSchema,
	heartbeatConfigSchema,
	documentUrlSchema,
	loginSchema,
	settingsSchema,
	validateField,
	validateForm,
	validateScanTarget,
	validateCronExpr
} from '$lib/utils/validation';

// --- deviceSchema ---

describe('deviceSchema', () => {
	const validDevice = {
		name: 'Switch-01',
		type: 'switch',
		ip_address: '192.168.1.1',
		mac_address: 'AA:BB:CC:DD:EE:FF'
	};

	it('accepts a valid device', () => {
		const result = deviceSchema.safeParse(validDevice);
		expect(result.success).toBe(true);
	});

	it('rejects missing name', () => {
		const { name, ...withoutName } = validDevice;
		const result = deviceSchema.safeParse(withoutName);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'name')).toBe(true);
		}
	});

	it('rejects missing type', () => {
		const { type, ...withoutType } = validDevice;
		const result = deviceSchema.safeParse(withoutType);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'type')).toBe(true);
		}
	});

	it('accepts valid IPv4 address', () => {
		const result = deviceSchema.safeParse({ ...validDevice, ip_address: '10.0.0.1' });
		expect(result.success).toBe(true);
	});

	it('rejects invalid IP format (non-numeric)', () => {
		const result = deviceSchema.safeParse({ ...validDevice, ip_address: 'abc.def.ghi.jkl' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'ip_address')).toBe(true);
		}
	});

	it('rejects IP with octet > 255', () => {
		const result = deviceSchema.safeParse({ ...validDevice, ip_address: '999.1.1.1' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'ip_address')).toBe(true);
		}
	});

	it('accepts empty string IP (optional)', () => {
		const result = deviceSchema.safeParse({ ...validDevice, ip_address: '' });
		expect(result.success).toBe(true);
	});

	it('accepts valid MAC with colons', () => {
		const result = deviceSchema.safeParse({ ...validDevice, mac_address: 'AA:BB:CC:DD:EE:FF' });
		expect(result.success).toBe(true);
	});

	it('accepts valid MAC with dashes', () => {
		const result = deviceSchema.safeParse({ ...validDevice, mac_address: 'AA-BB-CC-DD-EE-FF' });
		expect(result.success).toBe(true);
	});

	it('rejects invalid MAC', () => {
		const result = deviceSchema.safeParse({ ...validDevice, mac_address: 'ZZ:ZZ:ZZ:ZZ:ZZ:ZZ' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'mac_address')).toBe(true);
		}
	});

	it('accepts empty string MAC (optional)', () => {
		const result = deviceSchema.safeParse({ ...validDevice, mac_address: '' });
		expect(result.success).toBe(true);
	});

	it('accepts optional fields omitted', () => {
		const minimal = { name: 'Device', type: 'router' };
		const result = deviceSchema.safeParse(minimal);
		expect(result.success).toBe(true);
	});
});

// --- userSchema ---

describe('userSchema', () => {
	const validUser = {
		username: 'admin',
		email: 'admin@example.com',
		password: 'securepass123',
		role: 'admin' as const
	};

	it('accepts a valid user', () => {
		const result = userSchema.safeParse(validUser);
		expect(result.success).toBe(true);
	});

	it('rejects short username (< 3 chars)', () => {
		const result = userSchema.safeParse({ ...validUser, username: 'ab' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'username')).toBe(true);
		}
	});

	it('rejects short password (< 8 chars)', () => {
		const result = userSchema.safeParse({ ...validUser, password: 'short' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'password')).toBe(true);
		}
	});

	it('rejects invalid role', () => {
		const result = userSchema.safeParse({ ...validUser, role: 'superadmin' });
		expect(result.success).toBe(false);
	});

	it('accepts empty email string', () => {
		const result = userSchema.safeParse({ ...validUser, email: '' });
		expect(result.success).toBe(true);
	});

	it('rejects invalid email format', () => {
		const result = userSchema.safeParse({ ...validUser, email: 'not-an-email' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'email')).toBe(true);
		}
	});

	it('accepts user role', () => {
		const result = userSchema.safeParse({ ...validUser, role: 'user' });
		expect(result.success).toBe(true);
	});
});

// --- loginSchema ---

describe('loginSchema', () => {
	const validLogin = { username: 'admin', password: 'steward' };

	it('accepts valid login', () => {
		const result = loginSchema.safeParse(validLogin);
		expect(result.success).toBe(true);
	});

	it('rejects empty username', () => {
		const result = loginSchema.safeParse({ username: '', password: 'pass' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'username')).toBe(true);
		}
	});

	it('rejects empty password', () => {
		const result = loginSchema.safeParse({ username: 'admin', password: '' });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'password')).toBe(true);
		}
	});

	it('rejects missing fields entirely', () => {
		const result = loginSchema.safeParse({});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.length).toBeGreaterThanOrEqual(2);
		}
	});
});

// --- settingsSchema ---

describe('settingsSchema', () => {
	const validSettings = {
		currentPassword: 'oldpass',
		newPassword: 'newpassword123',
		confirmPassword: 'newpassword123'
	};

	it('accepts valid matching passwords', () => {
		const result = settingsSchema.safeParse(validSettings);
		expect(result.success).toBe(true);
	});

	it('rejects mismatched passwords', () => {
		const result = settingsSchema.safeParse({
			...validSettings,
			confirmPassword: 'different'
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'confirmPassword')).toBe(true);
		}
	});

	it('rejects short new password', () => {
		const result = settingsSchema.safeParse({
			...validSettings,
			newPassword: 'short',
			confirmPassword: 'short'
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'newPassword')).toBe(true);
		}
	});

	it('rejects empty current password', () => {
		const result = settingsSchema.safeParse({
			...validSettings,
			currentPassword: ''
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'currentPassword')).toBe(true);
		}
	});

	it('rejects empty confirm password', () => {
		const result = settingsSchema.safeParse({
			...validSettings,
			confirmPassword: ''
		});
		expect(result.success).toBe(false);
	});
});

// --- heartbeatConfigSchema ---

describe('heartbeatConfigSchema', () => {
	const validConfig = {
		device_id: 1,
		method: 'ICMP' as const,
		target: '192.168.1.1',
		interval: 30,
		timeout: 5,
		enabled: true
	};

	it('accepts valid config', () => {
		const result = heartbeatConfigSchema.safeParse(validConfig);
		expect(result.success).toBe(true);
	});

	it('rejects interval of 0', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, interval: 0 });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'interval')).toBe(true);
		}
	});

	it('rejects interval > 300', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, interval: 301 });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'interval')).toBe(true);
		}
	});

	it('rejects timeout of 0', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, timeout: 0 });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'timeout')).toBe(true);
		}
	});

	it('rejects timeout > 30', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, timeout: 31 });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path[0] === 'timeout')).toBe(true);
		}
	});

	it('accepts boundary interval (1 and 300)', () => {
		expect(heartbeatConfigSchema.safeParse({ ...validConfig, interval: 1 }).success).toBe(true);
		expect(heartbeatConfigSchema.safeParse({ ...validConfig, interval: 300 }).success).toBe(true);
	});

	it('accepts boundary timeout (1 and 30)', () => {
		expect(heartbeatConfigSchema.safeParse({ ...validConfig, timeout: 1 }).success).toBe(true);
		expect(heartbeatConfigSchema.safeParse({ ...validConfig, timeout: 30 }).success).toBe(true);
	});

	it('rejects invalid method', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, method: 'FTP' });
		expect(result.success).toBe(false);
	});

	it('rejects empty target', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, target: '' });
		expect(result.success).toBe(false);
	});

	it('rejects non-positive device_id', () => {
		const result = heartbeatConfigSchema.safeParse({ ...validConfig, device_id: 0 });
		expect(result.success).toBe(false);
	});

	it('accepts all valid methods', () => {
		for (const method of ['ICMP', 'TCP', 'HTTP', 'SNMP'] as const) {
			expect(heartbeatConfigSchema.safeParse({ ...validConfig, method }).success).toBe(true);
		}
	});
});

// --- documentUrlSchema ---

describe('documentUrlSchema', () => {
	it('accepts valid document URL', () => {
		const result = documentUrlSchema.safeParse({
			title: 'Manual',
			url: 'https://example.com/manual.pdf'
		});
		expect(result.success).toBe(true);
	});

	it('rejects missing title', () => {
		const result = documentUrlSchema.safeParse({ url: 'https://example.com' });
		expect(result.success).toBe(false);
	});

	it('rejects invalid URL', () => {
		const result = documentUrlSchema.safeParse({ title: 'Link', url: 'not-a-url' });
		expect(result.success).toBe(false);
	});

	it('accepts optional description', () => {
		const result = documentUrlSchema.safeParse({
			title: 'Manual',
			url: 'https://example.com/manual.pdf',
			description: 'Device manual'
		});
		expect(result.success).toBe(true);
	});
});

// --- validateField ---

describe('validateField', () => {
	it('returns valid=true for correct value', () => {
		const result = validateField(deviceSchema, 'name', 'Switch-01');
		expect(result.valid).toBe(true);
		expect(result.error).toBeUndefined();
	});

	it('returns valid=false + error message for invalid value', () => {
		const result = validateField(deviceSchema, 'name', '');
		expect(result.valid).toBe(false);
		expect(result.error).toBeTruthy();
	});

	it('validates IP field correctly', () => {
		const valid = validateField(deviceSchema, 'ip_address', '192.168.1.1');
		expect(valid.valid).toBe(true);

		const invalid = validateField(deviceSchema, 'ip_address', '999.1.1.1');
		expect(invalid.valid).toBe(false);
		expect(invalid.error).toBeTruthy();
	});

	it('validates user password length', () => {
		const valid = validateField(userSchema, 'password', 'longpassword');
		expect(valid.valid).toBe(true);

		const invalid = validateField(userSchema, 'password', 'short');
		expect(invalid.valid).toBe(false);
		expect(invalid.error).toContain('8');
	});
});

// --- validateForm ---

describe('validateForm', () => {
	it('returns valid=true + empty errors for correct data', () => {
		const result = validateForm(loginSchema, { username: 'admin', password: 'steward' });
		expect(result.valid).toBe(true);
		expect(result.errors).toEqual({});
	});

	it('returns valid=false + populated errors for invalid data', () => {
		const result = validateForm(loginSchema, { username: '', password: '' });
		expect(result.valid).toBe(false);
		expect(Object.keys(result.errors).length).toBeGreaterThanOrEqual(2);
	});

	it('collects errors from multiple fields', () => {
		const result = validateForm(userSchema, {
			username: 'ab',
			password: 'short',
			role: 'invalid'
		});
		expect(result.valid).toBe(false);
		expect(result.errors.username).toBeTruthy();
		expect(result.errors.password).toBeTruthy();
		expect(result.errors.role).toBeTruthy();
	});

	it('returns first error per field (no duplicates)', () => {
		const result = validateForm(userSchema, {
			username: '',
			password: '',
			role: 'bad'
		});
		expect(result.valid).toBe(false);
		// Each field should appear exactly once in errors
		for (const key of Object.keys(result.errors)) {
			expect(typeof result.errors[key]).toBe('string');
		}
	});

	it('validates full device form', () => {
		const result = validateForm(deviceSchema, {
			name: 'Switch',
			type: 'switch',
			ip_address: '10.0.0.1',
			mac_address: 'AA:BB:CC:DD:EE:FF'
		});
		expect(result.valid).toBe(true);
	});
});

// --- validateScanTarget ---

describe('validateScanTarget', () => {
	it('accepts a single IP', () => {
		expect(validateScanTarget('192.168.1.1')).toBeNull();
	});

	it('accepts a CIDR notation', () => {
		expect(validateScanTarget('10.0.0.0/24')).toBeNull();
	});

	it('accepts comma-separated targets', () => {
		expect(validateScanTarget('192.168.1.1,10.0.0.0/24')).toBeNull();
	});

	it('accepts IP range', () => {
		expect(validateScanTarget('192.168.1.1-10')).toBeNull();
	});

	it('rejects empty string', () => {
		expect(validateScanTarget('')).toBe('Targets are required');
	});

	it('rejects invalid IP octets (>255)', () => {
		expect(validateScanTarget('999.1.1.1')).toContain('octets must be 0-255');
	});

	it('rejects invalid CIDR prefix (>32)', () => {
		expect(validateScanTarget('192.168.1.0/33')).toContain('prefix must be 0-32');
	});

	it('rejects invalid range end (>255)', () => {
		expect(validateScanTarget('192.168.1.1-300')).toContain('range end must be 0-255');
	});

	it('rejects non-IP string', () => {
		expect(validateScanTarget('not-an-ip')).toContain('Invalid target');
	});
});

// --- validateCronExpr ---

describe('validateCronExpr', () => {
	it('accepts a valid 5-field cron', () => {
		expect(validateCronExpr('*/5 * * * *')).toBeNull();
	});

	it('accepts specific time cron', () => {
		expect(validateCronExpr('30 4 * * 1-5')).toBeNull();
	});

	it('accepts comma-separated cron values', () => {
		expect(validateCronExpr('0 0,12 * * *')).toBeNull();
	});

	it('rejects empty string', () => {
		expect(validateCronExpr('')).toBe('Cron expression is required');
	});

	it('rejects fewer than 5 fields', () => {
		expect(validateCronExpr('*/5 * * *')).toContain('exactly 5 fields');
	});

	it('rejects more than 5 fields', () => {
		expect(validateCronExpr('*/5 * * * * extra')).toContain('exactly 5 fields');
	});

	it('rejects all asterisks', () => {
		expect(validateCronExpr('* * * * *')).toContain('at least one specific field');
	});

	it('rejects invalid characters in field', () => {
		expect(validateCronExpr('abc * * * *')).toContain('Invalid cron minute field');
	});
});
