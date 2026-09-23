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

import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/svelte';
import { afterEach } from 'vitest';

// jsdom has no ResizeObserver; Chart.svelte's $effect constructs one on mount
// and the resulting uncaught ReferenceError fails test runs that render charts
// (the dashboard's default cards mount Chart unconditionally).
if (typeof globalThis.ResizeObserver === 'undefined') {
	globalThis.ResizeObserver = class {
		observe() {}
		unobserve() {}
		disconnect() {}
	};
}

// jsdom has no Web Animations API; svelte/transition delegates to
// Element.animate when present, and any test that opens a Modal (fade/scale)
// would throw "element.animate is not a function". The stub returns a finished
// Animation-like object: transitions complete instantly, assertions on the
// post-transition DOM work unmodified.
if (typeof Element.prototype.animate !== 'function') {
	Element.prototype.animate = function (
		_keyframes: Keyframe[] | PropertyIndexedKeyframes | null,
		_options?: number | KeyframeAnimationOptions
	) {
		return {
			finished: Promise.resolve(),
			cancel() {},
			finish() {},
			pause() {},
			play() {},
			reverse() {}
		};
	};
}

afterEach(() => {
	cleanup();
});
