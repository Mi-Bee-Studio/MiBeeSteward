<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

  Test-only host for the shared Modal: components under test need a snippet
  child, which render() cannot pass directly. Not imported by the app.
-->

<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';

	let { closable = true }: { closable?: boolean } = $props();
	let open = $state(true);
</script>

<Modal bind:open title="Host modal" maxWidth="20rem" {closable}>
	<p class="host-body">host body</p>
</Modal>
