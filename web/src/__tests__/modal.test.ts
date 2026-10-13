/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, it, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { tick } from 'svelte';
import ModalHost from './modal-host.svelte';

// #567: closing a modal must not depend on an outro transition finishing.
// Svelte transitions delegate to the Web Animations API and wait for
// onfinish; in environments whose document timeline never advances (embedded
// webviews on old tablets/kiosks, and jsdom itself — setup.ts stubs
// Element.animate with a no-op whose onfinish NEVER fires) the outro never
// completed: open flipped false but the backdrop+dialog DOM lingered forever,
// shadowing the page and intercepting pointer events. The regression shape
// these tests pin: after a close click, the modal DOM is gone once state
// settles — no animation callback involved.
describe('Modal close paths (#567)', () => {
	it('removes the modal from the DOM immediately after an X click', async () => {
		render(ModalHost);
		expect(document.querySelector('.modal-backdrop')).toBeTruthy();

		await fireEvent.click(document.querySelector('.modal-close')!);
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeNull();
	});

	it('removes the modal from the DOM after a backdrop click', async () => {
		render(ModalHost);

		const backdrop = document.querySelector('.modal-backdrop')!;
		// The handler only acts when the click target is the backdrop itself,
		// not the dialog bubbling up.
		await fireEvent.click(backdrop);
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeNull();
	});

	it('keeps the modal open on backdrop clicks that land on the dialog', async () => {
		render(ModalHost);

		await fireEvent.click(document.querySelector('.modal-dialog')!);
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeTruthy();
	});

	it('honors closable=false (in-flight async confirm lock)', async () => {
		render(ModalHost, { closable: false });

		await fireEvent.click(document.querySelector('.modal-close')!);
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeTruthy();
	});
});
