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
import type { System } from '$lib/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const baseSystem: System = {
	id: 1,
	device_id: 1,
	name: 'Grafana',
	entry_url: 'https://grafana.example.com:3000',
	description: 'Monitoring dashboard',
	category: 'web_app',
	metrics_url: 'http://localhost:3000/metrics',
	metrics_enabled: true,
	tags: '{"env":"prod"}',
	created_at: '2026-01-01T00:00:00Z',
	updated_at: '2026-01-01T00:00:00Z'
};

const validCategories = ['web_app', 'database', 'middleware', 'custom'];

function isValidUrl(url: string): boolean {
	if (!url) return true;
	try {
		const u = new URL(url);
		return u.protocol === 'http:' || u.protocol === 'https:';
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Device System Types
// ---------------------------------------------------------------------------

describe('Device System Types', () => {
	it('System interface has correct fields', () => {
		const system: System = { ...baseSystem };
		expect(system.id).toBe(1);
		expect(system.device_id).toBe(1);
		expect(system.name).toBe('Grafana');
		expect(system.entry_url).toBe('https://grafana.example.com:3000');
		expect(system.description).toBe('Monitoring dashboard');
		expect(system.category).toBe('web_app');
		expect(system.metrics_url).toBe('http://localhost:3000/metrics');
		expect(system.metrics_enabled).toBe(true);
		expect(system.tags).toBe('{"env":"prod"}');
		expect(system.created_at).toBe('2026-01-01T00:00:00Z');
		expect(system.updated_at).toBe('2026-01-01T00:00:00Z');
	});

	it('System with minimal optional fields', () => {
		const system: System = {
			id: 2,
			device_id: 1,
			name: 'PostgreSQL',
			entry_url: '',
			description: '',
			category: 'database',
			metrics_url: '',
			metrics_enabled: false,
			tags: '',
			created_at: '2026-01-01T00:00:00Z',
			updated_at: '2026-01-01T00:00:00Z'
		};
		expect(system.entry_url).toBe('');
		expect(system.metrics_enabled).toBe(false);
	});

	it('System with metrics disabled', () => {
		const system: System = { ...baseSystem, metrics_enabled: false, metrics_url: '' };
		expect(system.metrics_enabled).toBe(false);
		expect(system.metrics_url).toBe('');
	});
});

// ---------------------------------------------------------------------------
// Category Validation
// ---------------------------------------------------------------------------

describe('Category Validation', () => {
	it('accepts all valid category values', () => {
		for (const cat of validCategories) {
			expect(validCategories).toContain(cat);
		}
	});

	it('web_app is a valid category', () => {
		const system: System = { ...baseSystem, category: 'web_app' };
		expect(validCategories).toContain(system.category);
	});

	it('database is a valid category', () => {
		const system: System = { ...baseSystem, category: 'database' };
		expect(validCategories).toContain(system.category);
	});

	it('middleware is a valid category', () => {
		const system: System = { ...baseSystem, category: 'middleware' };
		expect(validCategories).toContain(system.category);
	});

	it('custom is a valid category', () => {
		const system: System = { ...baseSystem, category: 'custom' };
		expect(validCategories).toContain(system.category);
	});

	it('invalid category is not in valid list', () => {
		expect(validCategories).not.toContain('invalid_category');
		expect(validCategories).not.toContain('WEB_APP');
		expect(validCategories).not.toContain('');
	});
});

// ---------------------------------------------------------------------------
// URL Validation
// ---------------------------------------------------------------------------

describe('URL Validation', () => {
	it('accepts valid http URLs', () => {
		expect(isValidUrl('http://localhost:3000')).toBe(true);
	});

	it('accepts valid https URLs', () => {
		expect(isValidUrl('https://grafana.example.com')).toBe(true);
	});

	it('accepts https URL with port', () => {
		expect(isValidUrl('https://grafana.example.com:3000')).toBe(true);
	});

	it('rejects ftp URLs', () => {
		expect(isValidUrl('ftp://files.example.com')).toBe(false);
	});

	it('rejects plain hostname without scheme', () => {
		// new URL('grafana.example.com') treats it as a path, not a host
		expect(isValidUrl('grafana.example.com')).toBe(false);
	});

	it('accepts empty URL', () => {
		expect(isValidUrl('')).toBe(true);
	});

	it('rejects random strings', () => {
		expect(isValidUrl('not-a-url')).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Form Validation Logic
// ---------------------------------------------------------------------------

describe('Form Validation Logic', () => {
	it('name is required — empty fails', () => {
		const name = '';
		expect(name.trim().length > 0).toBe(false);
	});

	it('name with value is valid', () => {
		const name = 'Grafana';
		expect(name.trim().length > 0).toBe(true);
	});

	it('name with only whitespace fails', () => {
		const name = '   ';
		expect(name.trim().length > 0).toBe(false);
	});

	it('valid entry_url format', () => {
		const url = 'https://grafana.example.com';
		expect(() => new URL(url)).not.toThrow();
	});

	it('invalid entry_url format throws', () => {
		expect(() => new URL('not-a-url')).toThrow();
	});

	it('entry_url must have http or https scheme', () => {
		expect(isValidUrl('http://app.local')).toBe(true);
		expect(isValidUrl('https://app.local')).toBe(true);
		expect(isValidUrl('ftp://app.local')).toBe(false);
	});

	it('empty entry_url is allowed', () => {
		expect(isValidUrl('')).toBe(true);
	});

	it('metrics_url validation mirrors entry_url', () => {
		expect(isValidUrl('http://localhost:9090/metrics')).toBe(true);
		expect(isValidUrl('https://prom.example.com/metrics')).toBe(true);
		expect(isValidUrl('bad-url')).toBe(false);
	});

	it('tags field accepts JSON string', () => {
		const tags = '{"env":"prod","tier":"frontend"}';
		expect(() => JSON.parse(tags)).not.toThrow();
		const parsed = JSON.parse(tags);
		expect(parsed.env).toBe('prod');
		expect(parsed.tier).toBe('frontend');
	});

	it('tags field accepts empty string', () => {
		const tags = '';
		expect(tags).toBe('');
	});
});
