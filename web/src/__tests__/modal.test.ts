/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, it, expect, vi } from 'vitest';
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

// #582: Escape must close the modal in EVERY dispatch shape. The old code
// only handled keydowns that bubbled up to the backdrop (Svelte-delegated),
// so (a) non-bubbling synthetic KeyboardEvents — the JS default, common in
// automation and key injection — never reached any handler, and (b) with
// focus outside the modal the event never traversed the backdrop at all
// (the app layout carried a querySelector-click-X workaround for that
// half). The modal now owns Escape via a document-CAPTURE listener while
// open: capture sees the key regardless of target, focus, or bubbles.
describe('Modal Escape ownership (#582)', () => {
	it('closes on a NON-bubbling Escape dispatched inside the modal (the reported case)', async () => {
		render(ModalHost);

		const x = document.querySelector('.modal-close')!;
		// KeyboardEvent defaults: bubbles = false. Only a capture-phase
		// listener can observe this.
		x.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeNull();
	});

	it('closes on a bubbling Escape while focus (and target) is outside the modal', async () => {
		render(ModalHost);

		document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeNull();
	});

	it('fires onClose exactly once per Escape (no double close via the backdrop path)', async () => {
		const onClose = vi.fn();
		render(ModalHost, { onClose });

		const x = document.querySelector('.modal-close')!;
		// Bubbling from inside: both the capture owner and the backdrop's
		// delegated handler COULD see it — the owner must claim the event.
		x.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
		await tick();

		expect(onClose).toHaveBeenCalledTimes(1);
		expect(document.querySelector('.modal-backdrop')).toBeNull();
	});

	it('keeps the modal open on Escape while closable=false (async confirm in flight)', async () => {
		render(ModalHost, { closable: false });

		document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
		await tick();

		expect(document.querySelector('.modal-backdrop')).toBeTruthy();
	});
});
