export { getErrorMessage } from './error.js';

/** escapeHtml escapes a string for safe interpolation into an HTML context
 *  (element text or a single- or double-quoted attribute value). DataTable
 *  columns render via {@html}, so any user-controlled field (device name,
 *  location, vendor, MAC, …) must be escaped before being placed into the
 *  template string — otherwise a name containing `"` breaks the surrounding
 *  `data-name="..."` attribute and a name containing `<` is an XSS vector.
 *
 *  The order matters: ampersand must be escaped first.
 */
export function escapeHtml(s: string): string {
	if (s == null) return '';
	return String(s)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/** escapeAttr is an alias for escapeHtml clarifying intent at call sites that
 *  build attribute strings (e.g. `data-name="${escapeAttr(name)}"`). */
export const escapeAttr = escapeHtml;
