import { describe, expect, it } from 'vitest';

describe('test infrastructure', () => {
	it('should run basic assertions', () => {
		expect(1 + 1).toBe(2);
	});

	it('should handle string operations', () => {
		expect('hello'.toUpperCase()).toBe('HELLO');
	});
});
