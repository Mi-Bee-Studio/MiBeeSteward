<script lang="ts">
	/**
	 * ChangeDiff — renders the full before/after data of a ChangeLogEntry.
	 *
	 * Three shapes:
	 *  - device_added: `after_data` = full DeviceSnapshot → render as a property table.
	 *  - device_lost:  `before_data` = full DeviceSnapshot → render as a property table.
	 *  - device_changed: `after_data` = {field: [old, new]} diff map → render a
	 *    side-by-side old→new comparison table (red old / green new).
	 *
	 * Long string values (JSON columns like open_ports / scan_attributes) are
	 * pretty-printed for readability.
	 */

	interface Props {
		changeType: string;
		beforeData?: string;
		afterData?: string;
	}

	let { changeType, beforeData, afterData }: Props = $props();

	function tryParse(raw?: string): unknown {
		if (!raw) return null;
		try {
			return JSON.parse(raw);
		} catch {
			return raw;
		}
	}

	// A device_changed diff map: { fieldName: [oldValue, newValue] }.
	type DiffMap = Record<string, [unknown, unknown]>;
	// A device snapshot: flat { fieldName: value } (values may be JSON strings).
	type Snapshot = Record<string, unknown>;

	const diff = $derived(changeType === 'device_changed' ? (tryParse(afterData) as DiffMap | null) : null);
	const snapshot = $derived(
		changeType === 'device_changed'
			? null
			: (tryParse(changeType === 'device_added' ? afterData : beforeData) as Snapshot | null)
	);

	// Pretty-format a single value: JSON-parse strings that look like JSON,
	// stringify objects, truncate very long single-line values.
	function fmt(v: unknown): string {
		if (v === null || v === undefined) return '-';
		if (typeof v === 'string') {
			if ((v.startsWith('{') && v.endsWith('}')) || (v.startsWith('[') && v.endsWith(']'))) {
				try {
					return JSON.stringify(JSON.parse(v), null, 2);
				} catch {
					/* fall through */
				}
			}
			return v || '-';
		}
		if (typeof v === 'object') {
			try {
				return JSON.stringify(v, null, 2);
			} catch {
				return String(v);
			}
		}
		return String(v);
	}

	// Is a value "large" (worth rendering in a <pre> block)?
	function isLarge(v: unknown): boolean {
		return fmt(v).length > 40 || fmt(v).includes('\n');
	}

	// Friendly labels for the diff field keys (the DeviceSnapshot field names).
	const fieldLabels: Record<string, string> = {
		name: 'Name',
		type: 'Type',
		brand: 'Brand',
		model: 'Model',
		mac_address: 'MAC',
		ip_address: 'IP',
		status: 'Status',
		open_ports: 'Open Ports',
		detected_services: 'Detected Services',
		prometheus_url: 'Prometheus URL',
		node_exporter_url: 'Node Exporter URL',
		scan_attributes: 'Scan Attributes'
	};

	function labelFor(key: string): string {
		return fieldLabels[key] ?? key;
	}
</script>

<div class="text-sm">
	{#if diff}
		<!-- device_changed: field-by-field old → new comparison -->
		{#if Object.keys(diff).length === 0}
			<p class="text-text-muted italic text-xs">No field-level differences recorded.</p>
		{:else}
			<table class="w-full text-left border-collapse">
				<thead>
					<tr class="border-b border-border">
						<th class="py-1.5 pr-3 text-xs font-medium text-text-muted uppercase tracking-wide w-1/4">Field</th>
						<th class="py-1.5 pr-3 text-xs font-medium text-text-muted uppercase tracking-wide">Before</th>
						<th class="py-1.5 text-xs font-medium text-text-muted uppercase tracking-wide">After</th>
					</tr>
				</thead>
				<tbody>
					{#each Object.entries(diff) as [field, values]}
						{@const [oldV, newV] = values as [unknown, unknown]}
						{@const oldS = fmt(oldV)}
						{@const newS = fmt(newV)}
						{@const changed = oldS !== newS}
						<tr class="border-b border-border/50 align-top">
							<td class="py-2 pr-3 font-mono text-xs text-text">{labelFor(field)}</td>
							<td class="py-2 pr-3">
								{#if isLarge(oldV)}
									<pre class="text-xs text-error/80 bg-error/5 border border-error/20 rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{oldS}</pre>
								{:else}
									<span class="font-mono text-xs {changed ? 'text-error line-through opacity-70' : 'text-text-muted'}">{oldS}</span>
								{/if}
							</td>
							<td class="py-2">
								{#if isLarge(newV)}
									<pre class="text-xs text-success bg-success/5 border border-success/20 rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{newS}</pre>
								{:else}
									<span class="font-mono text-xs {changed ? 'text-success font-medium' : 'text-text-muted'}">{newS}</span>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	{:else if snapshot}
		<!-- device_added / device_lost: full snapshot property table -->
		{#if Object.keys(snapshot).length === 0}
			<p class="text-text-muted italic text-xs">No snapshot data.</p>
		{:else}
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
				{#each Object.entries(snapshot) as [field, value]}
					<div class="flex flex-col gap-0.5 border-b border-border/30 pb-1.5">
						<span class="text-[10px] text-text-muted uppercase tracking-wide">{labelFor(field)}</span>
						{#if isLarge(value)}
							<pre class="text-xs text-text bg-bg/50 border border-border rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-32">{fmt(value)}</pre>
						{:else}
							<span class="text-xs text-text font-mono break-all">{fmt(value)}</span>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	{:else}
		<p class="text-text-muted italic text-xs">No data available.</p>
	{/if}
</div>
