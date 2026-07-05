import { describe, expect, it } from 'vitest';

// --- Types mirroring the page interfaces ---

interface ScannerTask {
	id: number;
	name: string;
	targets: string;
	enabled: boolean;
}

interface ScanResult {
	id: number;
	ip: string;
	alive: boolean;
	rtt_ms: number;
}

// --- Search filter logic (scan-tasks page) ---

function filterTasks(tasks: ScannerTask[], query: string): ScannerTask[] {
	if (!query.trim()) return tasks;
	const q = query.toLowerCase();
	return tasks.filter(
		(t) => t.name.toLowerCase().includes(q) || t.targets.toLowerCase().includes(q)
	);
}

// --- Sort logic (scan-results page) ---

type SortColumn = 'ip' | 'status' | 'rtt' | null;
type SortDirection = 'asc' | 'desc';

function sortResults(results: ScanResult[], column: SortColumn, direction: SortDirection): ScanResult[] {
	if (!column) return results;
	const sorted = [...results].sort((a, b) => {
		let cmp = 0;
		if (column === 'ip') {
			cmp = a.ip.localeCompare(b.ip);
		} else if (column === 'status') {
			cmp = Number(a.alive) - Number(b.alive);
		} else if (column === 'rtt') {
			cmp = a.rtt_ms - b.rtt_ms;
		}
		return direction === 'asc' ? cmp : -cmp;
	});
	return sorted;
}

function toggleSort(currentCol: SortColumn, newCol: 'ip' | 'status' | 'rtt', currentDir: SortDirection): { column: SortColumn; direction: SortDirection } {
	if (currentCol === newCol) {
		return { column: currentCol, direction: currentDir === 'asc' ? 'desc' : 'asc' };
	}
	return { column: newCol, direction: 'asc' };
}

// --- Expand/collapse logic (scanner page) ---

function getVisibleUnreachable(total: number, showAll: boolean, limit: number = 5): number {
	if (showAll) return total;
	return Math.min(total, limit);
}

function shouldShowExpandLink(total: number, limit: number = 5): boolean {
	return total > limit;
}

// --- Confirm dialog logic (scanner page) ---

function shouldShowConfirmDialog(selectedCount: number, threshold: number = 10): boolean {
	return selectedCount > threshold;
}

// ===================== TESTS =====================

describe('scan-tasks search filter', () => {
	const tasks: ScannerTask[] = [
		{ id: 1, name: 'Weekly Office Scan', targets: '192.168.1.0/24', enabled: true },
		{ id: 2, name: 'Daily Server Scan', targets: '10.0.0.0/24', enabled: true },
		{ id: 3, name: 'Monthly Full Scan', targets: '172.16.0.0/16', enabled: false },
		{ id: 4, name: 'IoT Discovery', targets: '10.0.99.0/24', enabled: true }
	];

	it('returns all tasks when query is empty', () => {
		expect(filterTasks(tasks, '')).toHaveLength(4);
		expect(filterTasks(tasks, '   ')).toHaveLength(4);
	});

	it('filters by task name (case-insensitive)', () => {
		const result = filterTasks(tasks, 'office');
		expect(result).toHaveLength(1);
		expect(result[0].id).toBe(1);
	});

	it('filters by task name case-insensitive', () => {
		const result = filterTasks(tasks, 'WEEKLY');
		expect(result).toHaveLength(1);
		expect(result[0].name).toBe('Weekly Office Scan');
	});

	it('filters by targets (CIDR)', () => {
		const result = filterTasks(tasks, '10.0');
		expect(result).toHaveLength(2);
		expect(result.map((t) => t.id).sort()).toEqual([2, 4]);
	});

	it('filters by partial IP in targets', () => {
		const result = filterTasks(tasks, '10.0.0');
		expect(result).toHaveLength(1);
		expect(result[0].id).toBe(2);
	});

	it('returns empty when no match', () => {
		expect(filterTasks(tasks, 'nonexistent')).toHaveLength(0);
	});

	it('matches name OR targets', () => {
		// "scan" matches all names
		const result = filterTasks(tasks, 'scan');
		expect(result).toHaveLength(3);
	});

	it('matches partial target string', () => {
		const result = filterTasks(tasks, '172.16');
		expect(result).toHaveLength(1);
		expect(result[0].name).toBe('Monthly Full Scan');
	});
});

describe('scan-results column sort', () => {
	const results: ScanResult[] = [
		{ id: 1, ip: '192.168.1.100', alive: true, rtt_ms: 5 },
		{ id: 2, ip: '10.0.0.1', alive: false, rtt_ms: 0 },
		{ id: 3, ip: '192.168.1.1', alive: true, rtt_ms: 2 },
		{ id: 4, ip: '172.16.0.1', alive: true, rtt_ms: 15 },
		{ id: 5, ip: '192.168.1.50', alive: false, rtt_ms: 0 }
	];

	it('returns original order when no sort column', () => {
		const sorted = sortResults(results, null, 'asc');
		expect(sorted.map((r) => r.id)).toEqual([1, 2, 3, 4, 5]);
	});

	it('sorts by IP ascending (lexicographic)', () => {
		const sorted = sortResults(results, 'ip', 'asc');
		const ips = sorted.map((r) => r.ip);
		expect(ips).toEqual(['10.0.0.1', '172.16.0.1', '192.168.1.1', '192.168.1.100', '192.168.1.50']);
	});

	it('sorts by IP descending', () => {
		const sorted = sortResults(results, 'ip', 'desc');
		const ips = sorted.map((r) => r.ip);
		expect(ips[0]).toBe('192.168.1.50');
		expect(ips[ips.length - 1]).toBe('10.0.0.1');
	});

	it('sorts by status ascending (dead first)', () => {
		const sorted = sortResults(results, 'status', 'asc');
		// dead (alive=false) first = 0, alive = 1
		expect(sorted[0].alive).toBe(false);
		expect(sorted[sorted.length - 1].alive).toBe(true);
	});

	it('sorts by status descending (alive first)', () => {
		const sorted = sortResults(results, 'status', 'desc');
		expect(sorted[0].alive).toBe(true);
		expect(sorted[sorted.length - 1].alive).toBe(false);
	});

	it('sorts by RTT ascending', () => {
		const sorted = sortResults(results, 'rtt', 'asc');
		const rtts = sorted.map((r) => r.rtt_ms);
		for (let i = 1; i < rtts.length; i++) {
			expect(rtts[i]).toBeGreaterThanOrEqual(rtts[i - 1]);
		}
	});

	it('sorts by RTT descending', () => {
		const sorted = sortResults(results, 'rtt', 'desc');
		const rtts = sorted.map((r) => r.rtt_ms);
		for (let i = 1; i < rtts.length; i++) {
			expect(rtts[i]).toBeLessThanOrEqual(rtts[i - 1]);
		}
	});

	it('does not mutate original array', () => {
		const originalOrder = results.map((r) => r.id);
		sortResults(results, 'ip', 'asc');
		expect(results.map((r) => r.id)).toEqual(originalOrder);
	});
});

describe('sort toggle behavior', () => {
	it('sets new column to asc on first click', () => {
		const result = toggleSort(null, 'ip', 'asc');
		expect(result).toEqual({ column: 'ip', direction: 'asc' });
	});

	it('toggles direction when clicking same column', () => {
		const result = toggleSort('ip', 'ip', 'asc');
		expect(result).toEqual({ column: 'ip', direction: 'desc' });
	});

	it('toggles back to asc on third click', () => {
		let result = toggleSort(null, 'ip', 'asc');
		result = toggleSort(result.column, 'ip', result.direction);
		result = toggleSort(result.column, 'ip', result.direction);
		expect(result).toEqual({ column: 'ip', direction: 'asc' });
	});

	it('resets to asc when switching column', () => {
		const result = toggleSort('ip', 'status', 'desc');
		expect(result).toEqual({ column: 'status', direction: 'asc' });
	});
});

describe('unreachable hosts expand/collapse', () => {
	it('shows max 5 by default', () => {
		expect(getVisibleUnreachable(12, false)).toBe(5);
	});

	it('shows all when expanded', () => {
		expect(getVisibleUnreachable(12, true)).toBe(12);
	});

	it('shows all when total <= limit', () => {
		expect(getVisibleUnreachable(3, false)).toBe(3);
	});

	it('shows expand link only when total > 5', () => {
		expect(shouldShowExpandLink(12)).toBe(true);
		expect(shouldShowExpandLink(5)).toBe(false);
		expect(shouldShowExpandLink(3)).toBe(false);
	});

	it('respects custom limit', () => {
		expect(getVisibleUnreachable(20, false, 10)).toBe(10);
		expect(getVisibleUnreachable(20, true, 10)).toBe(20);
		expect(shouldShowExpandLink(15, 10)).toBe(true);
	});
});

describe('confirm dialog for bulk add', () => {
	it('shows dialog when >10 hosts selected', () => {
		expect(shouldShowConfirmDialog(11)).toBe(true);
		expect(shouldShowConfirmDialog(50)).toBe(true);
	});

	it('does not show dialog when <=10 hosts', () => {
		expect(shouldShowConfirmDialog(10)).toBe(false);
		expect(shouldShowConfirmDialog(5)).toBe(false);
		expect(shouldShowConfirmDialog(1)).toBe(false);
	});

	it('respects custom threshold', () => {
		expect(shouldShowConfirmDialog(6, 5)).toBe(true);
		expect(shouldShowConfirmDialog(5, 5)).toBe(false);
	});
});
