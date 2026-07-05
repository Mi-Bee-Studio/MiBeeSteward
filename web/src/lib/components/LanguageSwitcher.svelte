<script lang="ts">
	import { getLocale, setLocale } from '$lib/i18n-paraglide';

	let lang = $state(getLocale());

	function handleChange() {
		if (lang === getLocale()) return;
		setLocale(lang);
	}
</script>

<select
	bind:value={lang}
	onchange={handleChange}
	class="bg-transparent border border-border rounded-md px-2 py-1.5 text-xs text-muted
		focus:outline-none focus:border-primary transition-colors cursor-pointer"
	aria-label="Switch language"
>
	<option value="zh" class="bg-surface text-text">中文</option>
	<option value="en" class="bg-surface text-text">EN</option>
</select>
