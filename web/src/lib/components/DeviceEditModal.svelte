<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!-- DeviceEditModal — shared device create/edit form used by both the devices
     list page and the device detail page (#57). Owns its own form state +
     validation + submit; the caller just toggles `open`, passes a `device`
     (null for create, non-null for edit), and supplies an `onSaved` refresh
     callback. Extracted verbatim from the list page's inline form to keep one
     source of truth for the device field set + validation. -->

<script lang="ts">
	import { api } from '$lib/api/client';
	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import { m } from '$lib/i18n-paraglide';
	import { addToast } from '$lib/stores/toast';
	import type { Device } from '$lib/types';
	import { getErrorMessage } from '$lib/utils/error';
	import { deviceSchema, validateField, validateForm } from '$lib/utils/validation';
	import { untrack } from 'svelte';

	let {
		open = $bindable(false),
		device = null,
		onSaved
	}: {
		open?: boolean;
		device?: Device | null;
		onSaved?: () => void;
	} = $props();

	// Form field state (mirrors the former list-page formXxx vars).
	let formName = $state('');
	let formType = $state('pc');
	let formBrand = $state('');
	let formModel = $state('');
	let formLocation = $state('');
	let formPurpose = $state('');
	let formIpAddress = $state('');
	let formMacAddress = $state('');
	let formSerialNumber = $state('');
	let formPurchaseDate = $state('');
	let formWarrantyExpiry = $state('');
	let formTags = $state('');
	let formError = $state('');
	let formLoading = $state(false);
	let fieldErrors = $state<Record<string, string>>({});
	// Tracks whether we're editing an existing device (vs creating). Mirrors the
	// list page's `editingDevice` — kept separate from the `device` prop so the
	// form mode is stable across re-renders even if the caller updates `device`.
	let editing = $state<Device | null>(null);

	// Snapshot of form state captured after the modal hydrates; formDirty
	// ($derived) detects unsaved edits so the Modal warns before discarding
	// (Esc / backdrop / X). #170 — same pattern as the list-page modals (#151).
	let formSnapshot = $state('');
	function snapshotForm(): string {
		return JSON.stringify([formName, formType, formBrand, formModel, formLocation,
			formPurpose, formIpAddress, formMacAddress, formSerialNumber,
			formPurchaseDate, formWarrantyExpiry, formTags]);
	}
	const formDirty = $derived(open && snapshotForm() !== formSnapshot);

	function resetForm() {
		formName = '';
		formType = 'pc';
		formBrand = '';
		formModel = '';
		formLocation = '';
		formPurpose = '';
		formIpAddress = '';
		formMacAddress = '';
		formSerialNumber = '';
		formPurchaseDate = '';
		formWarrantyExpiry = '';
		formTags = '';
		formError = '';
		fieldErrors = {};
		editing = null;
	}

	// Hydrate the form whenever the modal opens. device=non-null ⇒ edit (prefill
	// from the device), device=null ⇒ create (blank). Reads `device` at open
	// time so the caller can set it before toggling `open` true. Using
	// $effect.pre so the form is ready before the modal body renders.
	$effect(() => {
		if (open) {
			if (device) {
				editing = device;
				formName = device.name;
				formType = device.type || 'pc';
				formBrand = device.brand || '';
				formModel = device.model || '';
				formLocation = device.location || '';
				formPurpose = device.purpose || '';
				formIpAddress = device.ip_address || '';
				formMacAddress = device.mac_address || '';
				formSerialNumber = device.serial_number || '';
				formPurchaseDate = device.purchase_date || '';
				formWarrantyExpiry = device.warranty_expiry || '';
				formTags = device.tags || '';
				formError = '';
				fieldErrors = {};
			} else {
				resetForm();
			}
			// Capture the baseline after hydration so formDirty reflects only
			// edits the user makes AFTER the form is populated. untrack prevents
			// the $state reads inside snapshotForm from becoming effect deps
			// (which would re-run the effect on every keystroke, re-snapping the
			// form and clearing formDirty). #170
			formSnapshot = untrack(snapshotForm);
		}
	});

	function handleBlur(field: string, value: string) {
		const result = validateField(deviceSchema, field as keyof typeof deviceSchema._type, value);
		if (result.valid) {
			const { [field]: _, ...rest } = fieldErrors;
			fieldErrors = rest;
		} else {
			fieldErrors = { ...fieldErrors, [field]: result.error! };
		}
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;
		formError = '';

		const body = {
			name: formName,
			type: formType,
			brand: formBrand,
			model: formModel,
			location: formLocation,
			purpose: formPurpose,
			ip_address: formIpAddress,
			mac_address: formMacAddress,
			serial_number: formSerialNumber,
			purchase_date: formPurchaseDate,
			warranty_expiry: formWarrantyExpiry,
			tags: formTags
		};

		const validation = validateForm(deviceSchema, body);
		if (!validation.valid) {
			fieldErrors = validation.errors;
			formLoading = false;
			return;
		}

		try {
			if (editing) {
				await api.put(`/devices/${editing.id}`, body);
				addToast('success', m['devices.Updated']());
			} else {
				await api.post('/devices', body);
				addToast('success', m['devices.Created']());
			}
			open = false;
			resetForm();
			onSaved?.();
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			formError = msg;
			addToast('error', msg);
		} finally {
			formLoading = false;
		}
	}
</script>

<Modal bind:open title={editing ? m['devices.Edit Device']() : m['devices.Create Device']()} maxWidth="42rem" onClose={resetForm} confirmDiscard={() => formDirty}>
	{#if formError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{formError}
		</div>
	{/if}

	<form onsubmit={handleSubmit} class="grid grid-cols-2 gap-4">
		<!-- Name -->
		<div class="col-span-2">
			<label class="block text-xs text-muted mb-1">{m['devices.Device Name']()} *</label>
			<input
				bind:value={formName}
				onblur={() => handleBlur('name', formName)}
				required
				class="input {fieldErrors.name ? '!border-error' : ''}"
			/>
			{#if fieldErrors.name}
				<p class="text-xs text-error mt-1">{fieldErrors.name}</p>
			{/if}
		</div>

		<!-- Type -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Type']()} *</label>
			<select
				bind:value={formType}
				onblur={() => handleBlur('type', formType)}
				class="input"
			>
				<option value="pc">{m['devices.PC']()}</option>
				<option value="embedded">{m['devices.Embedded']()}</option>
				<option value="iot">{m['devices.IoT']()}</option>
				<option value="server">{m['devices.Server']()}</option>
				<option value="switch">{m['devices.Switch']()}</option>
				<option value="router">{m['devices.Router']()}</option>
				<option value="firewall">{m['devices.Firewall']()}</option>
				<option value="nas">{m['devices.NAS']()}</option>
				<option value="camera">{m['devices.Camera']()}</option>
				<option value="phone">{m['devices.Phone']()}</option>
				<option value="printer">{m['devices.Printer']()}</option>
				<option value="other">{m['devices.Other']()}</option>
			</select>
			{#if fieldErrors.type}
				<p class="text-xs text-error mt-1">{fieldErrors.type}</p>
			{/if}
		</div>

		<!-- Brand -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Brand']()}</label>
			<input bind:value={formBrand}
				class="input" />
		</div>

		<!-- Model -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Model']()}</label>
			<input bind:value={formModel}
				class="input" />
		</div>

		<!-- Location -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Location']()}</label>
			<input bind:value={formLocation}
				class="input" />
		</div>

		<!-- Purpose -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Purpose']()}</label>
			<input bind:value={formPurpose}
				class="input" />
		</div>

		<!-- IP Address -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.IP Address']()}</label>
			<input
				bind:value={formIpAddress}
				onblur={() => handleBlur('ip_address', formIpAddress)}
				placeholder="192.168.1.100"
				class="input font-mono {fieldErrors.ip_address ? '!border-error' : ''}"
			/>
			{#if fieldErrors.ip_address}
				<p class="text-xs text-error mt-1">{fieldErrors.ip_address}</p>
			{/if}
		</div>

		<!-- MAC Address -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.MAC Address']()}</label>
			<input
				bind:value={formMacAddress}
				onblur={() => handleBlur('mac_address', formMacAddress)}
				placeholder="AA:BB:CC:DD:EE:FF"
				class="input font-mono {fieldErrors.mac_address ? '!border-error' : ''}"
			/>
			{#if fieldErrors.mac_address}
				<p class="text-xs text-error mt-1">{fieldErrors.mac_address}</p>
			{/if}
		</div>

		<!-- Serial Number -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Serial Number']()}</label>
			<input bind:value={formSerialNumber}
				class="input font-mono" />
		</div>

		<!-- Purchase Date -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Purchase Date']()}</label>
			<input type="date" bind:value={formPurchaseDate}
				class="input" />
		</div>

		<!-- Warranty Expiry -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Warranty Expiry']()}</label>
			<input type="date" bind:value={formWarrantyExpiry}
				class="input" />
		</div>

		<!-- Tags -->
		<div class="col-span-2">
			<label class="block text-xs text-muted mb-1">{m['devices.Tags']()}</label>
			<input bind:value={formTags} placeholder="server,production,rack-a"
				class="input" />
		</div>

		<!-- Submit -->
		<div class="col-span-2 flex gap-3 pt-2">
		<LoadingButton type="submit" loading={formLoading} variant="primary" label={m['common.Save']()} />
			<button type="button" onclick={() => { open = false; resetForm(); }} class="btn btn-secondary">
				{m['common.Cancel']()}
			</button>
		</div>
	</form>
</Modal>
