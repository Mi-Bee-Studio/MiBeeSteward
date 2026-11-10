// Date-filter defaults (#UI-dates): date/datetime filter inputs always SHOW
// a concrete range instead of the bare yyyy/mm/dd placeholder — the page's
// default period when one exists, the last hour (expressed on the input's
// own granularity) otherwise. Pure formatting/layout math, unit-tested.

/** Format a Date for <input type="date"> (local timezone, yyyy-MM-dd). */
export function toLocalDateInput(d: Date): string {
	const p = (n: number) => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Format a Date for <input type="datetime-local"> (yyyy-MM-ddTHH:mm). */
export function toLocalDateTimeInput(d: Date): string {
	const p = (n: number) => String(n).padStart(2, '0');
	return `${toLocalDateInput(d)}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export interface DateRangeInput {
	from: string;
	to: string;
}

/**
 * The default range for a filter input pair, on the input's own granularity:
 * date-only inputs express the window as [day-of-from, day-of-to] (a
 * "last hour" default on a date-only filter renders as today → today),
 * datetime-local inputs keep hour precision.
 */
export function defaultRange(
	kind: 'date' | 'datetime-local',
	windowMs: number,
	now: Date = new Date()
): DateRangeInput {
	const from = new Date(now.getTime() - windowMs);
	if (kind === 'date') {
		return { from: toLocalDateInput(from), to: toLocalDateInput(now) };
	}
	return { from: toLocalDateTimeInput(from), to: toLocalDateTimeInput(now) };
}

/** Heartbeat-trend presets (devices detail) → window milliseconds. */
export function presetWindowMs(preset: string): number {
	switch (preset) {
		case '1h':
			return 3600_000;
		case '6h':
			return 6 * 3600_000;
		case '24h':
			return 24 * 3600_000;
		case '7d':
			return 7 * 24 * 3600_000;
		case '30d':
			return 30 * 24 * 3600_000;
		default:
			return 24 * 3600_000;
	}
}
