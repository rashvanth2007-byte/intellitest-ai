/** Device names Windows reserves in every directory, with or without an extension ("nul.txt" too). */
const WIN_RESERVED = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$|clock\$)$/i;

/**
 * Make one path segment safe to create on Windows and POSIX: no separators, ':' (alternate data
 * streams / drive letters), control or wildcard characters, no trailing dots/spaces (Windows strips
 * them, so "a.js." would alias "a.js"), and no reserved device names. Returns '' for "." / "..".
 */
export function safeSegment(s) {
  let out = String(s).replace(/[\0<>:"|?*\x00-\x1f\\/]/g, '_').slice(0, 200).replace(/[. ]+$/, '');
  if (!out) return '';
  if (WIN_RESERVED.test(out.split('.')[0].trimEnd())) out = `_${out}`;
  return out;
}

/** Turn an untrusted client-supplied (or archive) relative path into a safe one (or null). */
export function safeRelPath(p) {
  const parts = String(p || '').replace(/\\/g, '/').replace(/^[a-zA-Z]:/, '').split('/')
    .filter((s) => s && s !== '.' && s !== '..')
    .map(safeSegment)
    .filter(Boolean);
  if (!parts.length) return null;
  return parts.join('/').slice(0, 1000);
}
