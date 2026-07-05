/**
 * Safely extracts a human-readable error message from an unknown error value.
 *
 * Handles common error shapes encountered throughout the app:
 * - `Error` instances (native JS errors)
 * - plain `string` messages
 * - API error responses shaped as `{ error: string }`
 * - `null`, `undefined`, and anything else
 */
export function getErrorMessage(err: unknown): string {
	if (err instanceof Error) {
		return err.message;
	}

	if (typeof err === 'string') {
		return err;
	}

	if (typeof err === 'object' && err !== null && 'error' in err) {
		const maybe = (err as Record<string, unknown>).error;
		if (typeof maybe === 'string') {
			return maybe;
		}
	}

	return 'An unexpected error occurred';
}
