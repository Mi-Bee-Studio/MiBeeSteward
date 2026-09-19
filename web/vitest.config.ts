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

import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { svelteTesting } from '@testing-library/svelte/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	// svelteTesting() makes @testing-library/svelte's render() compile .svelte
	// components for the CLIENT (not SSR) under jsdom — without it the sveltekit
	// plugin emits the server build and render() fails with
	// "lifecycle_function_unavailable: mount() is not available on the server".
	// It only adds a client-compile condition for component rendering; the
	// existing logic/utility tests don't render components and are unaffected.
	plugins: [tailwindcss(), sveltekit(), svelteTesting()],
	test: {
		environment: 'jsdom',
		include: ['src/**/*.test.ts'],
		setupFiles: ['./src/__tests__/setup.ts'],
		coverage: {
			provider: 'v8',
			// Ratchet gate: `npm run test:coverage` (CI) fails below these.
			// Measured baseline 2026-09-19: statements 18.0 / branches 15.1 /
			// functions 17.8 / lines 19.5 — thresholds sit ~1pt under to absorb
			// v8-coverage jitter. Only move them UP after adding tests.
			// src/paraglide is regenerated per build (pretest hook) and the
			// OpenAPI types are generated (drift-checked in CI) — neither is
			// hand-maintained code, so they stay out of the measurement.
			include: ['src/lib/**/*.{ts,svelte}', 'src/routes/**/*.{ts,svelte}'],
			exclude: ['src/lib/api/schema.d.ts', 'src/**/*.test.ts'],
			thresholds: { statements: 17, branches: 14, functions: 16, lines: 18 }
		}
	}
});
