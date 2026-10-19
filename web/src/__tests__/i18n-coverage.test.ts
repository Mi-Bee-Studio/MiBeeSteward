/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. See LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// i18n coverage guard (user report 2026-10-19: five message keys were
// referenced from code but missing from the catalogs — every one on an error
// branch, so no test exercised it and the UI broke only in the field).
//
// Three invariants:
//   1. en.json and zh.json carry the exact same key set (recursive).
//   2. Every statically-referenced m['namespace.key']() call in app source
//      resolves to a key that exists in both catalogs. Bracket access with
//      the literal message id is the only access style this codebase uses;
//      dynamic keys would defeat the check, so they are not allowed.
//   3. No en catalog value leaks CJK text (an untranslated value would show
//      Chinese to English users).

type Catalog = Record<string, string | Catalog>;

function loadCatalog(name: string): Catalog {
	return JSON.parse(readFileSync(join(process.cwd(), 'messages', name), 'utf-8'));
}

function flatten(catalog: Catalog, prefix = ''): Map<string, string> {
	const out = new Map<string, string>();
	for (const [k, v] of Object.entries(catalog)) {
		const id = prefix ? `${prefix}.${k}` : k;
		if (typeof v === 'string') {
			out.set(id, v);
		} else {
			for (const [id2, v2] of flatten(v, id)) out.set(id2, v2);
		}
	}
	return out;
}

function walkSources(dir: string, acc: string[] = []): string[] {
	for (const entry of readdirSync(dir)) {
		if (entry === 'i18n-paraglide' || entry === '__tests__' || entry.endsWith('.test.ts')) {
			continue; // generated output and test fixtures are not app sources
		}
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) {
			walkSources(full, acc);
		} else if (entry.endsWith('.svelte') || entry.endsWith('.ts')) {
			acc.push(full);
		}
	}
	return acc;
}

describe('i18n coverage', () => {
	const en = flatten(loadCatalog('en.json'));
	const zh = flatten(loadCatalog('zh.json'));

	it('en.json and zh.json carry the same key set', () => {
		const onlyEn = [...en.keys()].filter((k) => !zh.has(k));
		const onlyZh = [...zh.keys()].filter((k) => !en.has(k));
		expect(onlyEn, 'keys missing from zh.json').toEqual([]);
		expect(onlyZh, 'keys missing from en.json').toEqual([]);
	});

	it('no en.json value leaks untranslated CJK text', () => {
		const leaks = [...en.entries()].filter(([, v]) => /[\u4e00-\u9fff]/.test(v));
		expect(leaks.map(([k]) => k)).toEqual([]);
	});

	it('every statically referenced message key exists in both catalogs', () => {
		const used = new Map<string, string[]>(); // key → files referencing it
		for (const file of walkSources(join(process.cwd(), 'src'))) {
			const src = readFileSync(file, 'utf-8');
			for (const match of src.matchAll(/\bm\[['"]([^'"]+)['"]\]/g)) {
				const key = match[1];
				if (!used.has(key)) used.set(key, []);
				used.get(key)!.push(file);
			}
		}
		expect(used.size).toBeGreaterThan(0); // the walker must actually find sources
		const missing = [...used.entries()]
			.filter(([k]) => !en.has(k) || !zh.has(k))
			.map(([k, files]) => `${k} (${files.map((f) => f.split('src').pop()).join(', ')})`);
		expect(missing, 'message keys referenced in code but absent from a catalog').toEqual([]);
	});
});
