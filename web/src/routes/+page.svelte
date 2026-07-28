<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
    // replaceState so `/` doesn't linger in history — without it the back
    // button lands on a redirector stub instead of leaving the app.
    onMount(() => goto('/dashboard', { replaceState: true }));
</script>
