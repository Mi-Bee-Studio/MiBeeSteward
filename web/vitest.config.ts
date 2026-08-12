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
		setupFiles: ['./src/__tests__/setup.ts']
	}
});
