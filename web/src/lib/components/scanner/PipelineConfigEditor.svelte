<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import type { PipelineConfig } from '$lib/types';
	import { ChevronDown, Info } from '@lucide/svelte';

	let {
		config = $bindable(defaultPipelineConfig()),
		onchange
	}: {
		config: PipelineConfig;
		onchange?: () => void;
	} = $props();

	function defaultPipelineConfig(): PipelineConfig {
		return {
			icmp: { enabled: true, timeout: 2 },
			snmp: { enabled: true, community: 'public', timeout: 5 },
			port_scan: { enabled: true, ports: '22,80,443,8080,9100', scan_type: 'connect' },
			service_detect: { enabled: true },
			prometheus: { enabled: true, ports: '9090' },
			node_exporter: { enabled: true }
		};
	}

	// --- Expanded state ---
	let expandedStage = $state<string | null>(null);

	// --- Presets ---
	type PresetKey = 'quick' | 'full' | 'prometheus' | 'custom';
	let selectedPreset = $state<PresetKey>('full');

	function applyPreset(key: PresetKey) {
		selectedPreset = key;
		switch (key) {
			case 'quick':
				config.icmp = { enabled: true, timeout: 2 };
				config.snmp = { ...config.snmp, enabled: false };
				config.port_scan = { ...config.port_scan, enabled: false };
				config.service_detect = { enabled: false };
				config.prometheus = { ...config.prometheus, enabled: false };
				config.node_exporter = { enabled: false };
				break;
			case 'full':
				config.icmp = { enabled: true, timeout: 2 };
				config.snmp = { enabled: true, community: config.snmp.community || 'public', timeout: 5 };
				config.port_scan = { enabled: true, ports: config.port_scan.ports || '22,80,443,8080,9100', scan_type: 'connect' };
				config.service_detect = { enabled: true };
				config.prometheus = { enabled: true, ports: config.prometheus.ports || '9090' };
				config.node_exporter = { enabled: true };
				break;
			case 'prometheus':
				config.icmp = { enabled: true, timeout: 2 };
				config.snmp = { ...config.snmp, enabled: false };
				config.port_scan = { ...config.port_scan, enabled: false };
				config.service_detect = { enabled: false };
				config.prometheus = { enabled: true, ports: config.prometheus.ports || '9090' };
				config.node_exporter = { enabled: true };
				break;
			case 'custom':
				break;
		}
		onchange?.();
	}

	// Detect current preset from config
	$effect(() => {
		const c = config;
		if (c.icmp.enabled && !c.snmp.enabled && !c.port_scan.enabled && !c.service_detect.enabled && !c.prometheus.enabled && !c.node_exporter.enabled) {
			selectedPreset = 'quick';
		} else if (c.icmp.enabled && c.snmp.enabled && c.port_scan.enabled && c.service_detect.enabled && c.prometheus.enabled && c.node_exporter.enabled) {
			selectedPreset = 'full';
		} else if (c.icmp.enabled && !c.snmp.enabled && !c.port_scan.enabled && !c.service_detect.enabled && c.prometheus.enabled && c.node_exporter.enabled) {
			selectedPreset = 'prometheus';
		} else {
			selectedPreset = 'custom';
		}
	});

	// --- Stages definition ---
	interface StageDef {
		key: string;
		nameKey: string;
		descKey: string;
		icon: string;
	}

	const stages: StageDef[] = [
		{ key: 'icmp', nameKey: 'scanner.pipeline.stage_icmp', descKey: 'scanner.pipeline.stage_icmp_desc', icon: 'icmp' },
		{ key: 'snmp', nameKey: 'scanner.pipeline.stage_snmp', descKey: 'scanner.pipeline.stage_snmp_desc', icon: 'snmp' },
		{ key: 'port_scan', nameKey: 'scanner.pipeline.stage_port', descKey: 'scanner.pipeline.stage_port_desc', icon: 'port' },
		{ key: 'service_detect', nameKey: 'scanner.pipeline.stage_service', descKey: 'scanner.pipeline.stage_service_desc', icon: 'service' },
		{ key: 'prometheus', nameKey: 'scanner.pipeline.stage_prometheus', descKey: 'scanner.pipeline.stage_prometheus_desc', icon: 'prometheus' },
		{ key: 'node_exporter', nameKey: 'scanner.pipeline.stage_node_exporter', descKey: 'scanner.pipeline.stage_node_exporter_desc', icon: 'node' }
	];

	function isStageEnabled(key: string): boolean {
		return (config as any)[key]?.enabled ?? false;
	}

	function toggleStage(key: string) {
		const stage = (config as any)[key];
		if (stage) {
			stage.enabled = !stage.enabled;
		}
		onchange?.();
	}

	let enabledCount = $derived(
		stages.filter((s) => isStageEnabled(s.key)).length
	);

	// --- SVG icons per stage ---
	function stageIcon(icon: string): string {
		switch (icon) {
			case 'icmp':
				return '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />';
			case 'snmp':
				return '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />';
			case 'port':
				return '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />';
			case 'service':
				return '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />';
			case 'prometheus':
				return '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />';
			case 'node':
				return '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />';
			default:
				return '';
		}
	}
</script>

<div class="pipeline-editor">
	<!-- Preset selector -->
	<div class="flex items-center gap-3 mb-5">
		<span class="text-xs font-semibold text-muted uppercase tracking-wider">
			{m['scanner.pipeline.preset']()}
		</span>
		<div class="flex rounded-lg border border-border overflow-hidden">
			{#each [
				{ key: 'quick' as PresetKey, labelKey: 'scanner.pipeline.preset_quick' },
				{ key: 'full' as PresetKey, labelKey: 'scanner.pipeline.preset_full' },
				{ key: 'prometheus' as PresetKey, labelKey: 'scanner.pipeline.preset_prometheus' },
				{ key: 'custom' as PresetKey, labelKey: 'scanner.pipeline.preset_custom' }
			] as preset}
				<button
					type="button"
					onclick={() => applyPreset(preset.key)}
					class="px-3 py-1.5 text-xs font-medium transition-colors
						{selectedPreset === preset.key
							? 'bg-primary text-text-inverse'
							: 'bg-surface text-muted hover:text-text'}
						{preset.key !== 'custom' ? 'border-r border-border' : ''}"
				>{m[preset.labelKey]()}</button>
			{/each}
		</div>
		<span class="ml-auto text-xs text-muted">
			{m['scanner.pipeline.stages_enabled']().replace('{count}', String(enabledCount))}
		</span>
	</div>

	<!-- Stage cards -->
	<div class="space-y-2">
		{#each stages as stage, i}
			{@const enabled = isStageEnabled(stage.key)}
			{@const expanded = expandedStage === stage.key}
			{@const isLast = i === stages.length - 1}

			<!-- Stage card -->
			<div class="stage-card {enabled ? 'stage-card-active' : ''}">
				<div
					class="stage-header"
					onclick={() => { expandedStage = expanded ? null : stage.key; }}
					role="button"
					tabindex="0"
					onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); expandedStage = expanded ? null : stage.key; } }}
				>
					<!-- Icon -->
					<div class="stage-icon {enabled ? 'stage-icon-active' : ''}">
						<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							{@html stageIcon(stage.icon)}
						</svg>
					</div>

					<!-- Name + description -->
					<div class="flex-1 min-w-0">
						<span class="text-sm font-medium {enabled ? 'text-text' : 'text-muted'}">
							{m[stage.nameKey]()}
						</span>
						<p class="text-xs text-muted mt-0.5 truncate">{m[stage.descKey]()}</p>
					</div>

					<!-- Toggle switch -->
					<button
						class="toggle-switch {enabled ? 'toggle-on' : 'toggle-off'}"
						onclick={(e) => { e.stopPropagation(); toggleStage(stage.key); }}
						role="switch"
						aria-checked={enabled}
						aria-label={m[stage.nameKey]()}
					>
						<span class="toggle-knob"></span>
					</button>

					<!-- Expand chevron -->
					<ChevronDown class="w-3.5 h-3.5 text-muted transition-transform duration-200 {expanded ? 'rotate-180' : ''}" />
				</div>

				<!-- Expandable config panel -->
				{#if expanded}
					<div class="stage-config-panel">
						{#if stage.key === 'icmp'}
							<div class="config-field">
								<label class="config-label">{m['scanner.pipeline.field_timeout']()}</label>
								<div class="flex items-center gap-2">
									<input
										type="number"
										bind:value={config.icmp.timeout}
										min="1"
										max="60"
										onchange={() => onchange?.()}
										class="config-input w-24"
									/>
										<span class="text-xs text-muted">{m['scanner.pipeline.seconds']()}</span>
									</div>
								</div>
							{:else if stage.key === 'snmp'}
								<div class="space-y-3">
									<div class="config-field">
										<label class="config-label">{m['scanner.pipeline.field_community']()}</label>
										<input
											type="text"
											bind:value={config.snmp.community}
											placeholder="public"
											onchange={() => onchange?.()}
											class="config-input w-48"
										/>
									</div>
									<div class="config-field">
										<label class="config-label">{m['scanner.pipeline.field_timeout']()}</label>
										<div class="flex items-center gap-2">
											<input
												type="number"
												bind:value={config.snmp.timeout}
												min="1"
												max="60"
												onchange={() => onchange?.()}
												class="config-input w-24"
											/>
											<span class="text-xs text-muted">{m['scanner.pipeline.seconds']()}</span>
										</div>
									</div>
								</div>
							{:else if stage.key === 'port_scan'}
								<div class="config-field">
									<label class="config-label">{m['scanner.pipeline.field_ports']()}</label>
									<input
										type="text"
										bind:value={config.port_scan.ports}
										placeholder={m['scanner.pipeline.field_ports_placeholder']()}
										onchange={() => onchange?.()}
										class="config-input w-64"
									/>
								</div>
							{:else if stage.key === 'service_detect'}
								<div class="config-note">
									<Info class="w-3.5 h-3.5 shrink-0" />
									<span>{m['scanner.pipeline.note_service_depends']()}</span>
								</div>
							{:else if stage.key === 'prometheus'}
								<div class="config-field">
									<label class="config-label">{m['scanner.pipeline.field_ports']()}</label>
									<input
										type="text"
										bind:value={config.prometheus.ports}
										placeholder="9090"
										onchange={() => onchange?.()}
										class="config-input w-64"
									/>
								</div>
							{:else if stage.key === 'node_exporter'}
								<div class="config-note">
									<Info class="w-3.5 h-3.5 shrink-0" />
									<span>{m['scanner.pipeline.note_node_depends']()}</span>
								</div>
							{/if}
					</div>
				{/if}
			</div>

			<!-- Connector line between stages -->
			{#if !isLast}
				<div class="stage-connector {enabled || isStageEnabled(stages[i + 1].key) ? 'connector-active' : ''}">
					<svg class="w-4 h-5" viewBox="0 0 16 20" fill="none">
						<path d="M8 0v16" stroke="currentColor" stroke-width="1.5" stroke-dasharray="2 2" />
						<path d="M4 13l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
					</svg>
				</div>
			{/if}
		{/each}
	</div>
</div>

<style>
	.pipeline-editor {
		width: 100%;
	}

	.stage-card {
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-surface);
		transition: border-color 0.15s ease, box-shadow 0.15s ease;
	}

	.stage-card-active {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 1px var(--color-primary), 0 0 12px color-mix(in srgb, var(--color-primary) 8%, transparent);
	}

	.stage-header {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
		cursor: pointer;
		user-select: none;
	}

	.stage-icon {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		border-radius: var(--radius-sm);
		background: var(--color-bg);
		color: var(--color-text-muted);
		flex-shrink: 0;
		transition: background 0.15s ease, color 0.15s ease;
	}

	.stage-icon-active {
		background: var(--color-primary);
		color: var(--color-text-inverse);
	}

	/* Toggle switch */
	.toggle-switch {
		position: relative;
		width: 2.25rem;
		height: 1.25rem;
		border-radius: 9999px;
		border: none;
		cursor: pointer;
		transition: background 0.2s ease;
		flex-shrink: 0;
		padding: 0;
	}

	.toggle-off {
		background: var(--color-border);
	}

	.toggle-on {
		background: var(--color-primary);
	}

	.toggle-knob {
		position: absolute;
		top: 2px;
		left: 2px;
		width: calc(1.25rem - 4px);
		height: calc(1.25rem - 4px);
		border-radius: 9999px;
		background: var(--color-text-inverse);
		transition: transform 0.2s ease;
		box-shadow: var(--shadow-sm);
	}

	.toggle-on .toggle-knob {
		transform: translateX(1rem);
	}

	/* Config panel */
	.stage-config-panel {
		padding: 0 1rem 0.875rem 3.75rem;
		border-top: 1px solid var(--color-border);
		margin-top: 0;
		padding-top: 0.75rem;
		animation: slideDown 0.15s ease;
	}

	@keyframes slideDown {
		from { opacity: 0; max-height: 0; }
		to { opacity: 1; max-height: 200px; }
	}

	.config-field {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.config-label {
		font-size: 0.75rem;
		font-weight: 500;
		color: var(--color-text-muted);
	}

	.config-input {
		padding: 0.375rem 0.625rem;
		background: var(--color-bg);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-sm);
		font-size: 0.8125rem;
		color: var(--color-text);
		font-family: var(--font-mono);
		transition: border-color 0.15s ease;
	}

	.config-input:focus {
		border-color: var(--color-primary);
		outline: none;
	}

	.config-note {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.75rem;
		background: var(--color-bg);
		border-radius: var(--radius-sm);
		font-size: 0.75rem;
		color: var(--color-text-muted);
		font-style: italic;
	}

	/* Connector between stages */
	.stage-connector {
		display: flex;
		justify-content: center;
		padding: 0;
		color: var(--color-border);
		transition: color 0.15s ease;
	}

	.connector-active {
		color: var(--color-primary);
	}
</style>
