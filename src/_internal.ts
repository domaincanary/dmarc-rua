/**
 * Byte helpers shared by the report parser and the email reader.
 *
 * Private to the package: this module is deliberately absent from the exports map, and the
 * underscore prefix marks it as internal. Nothing here is part of the public API.
 *
 * @module
 */

/** Leading bytes of a gzip member (RFC 1952). Frozen: both entrypoints share this array. */
export const GZIP_MAGIC: readonly number[] = Object.freeze([0x1f, 0x8b]);

/** Leading bytes of a zip local file header, the ASCII "PK". Frozen: both entrypoints share this array. */
export const ZIP_MAGIC: readonly number[] = Object.freeze([0x50, 0x4b]);

/**
 * Does `bytes` open with `magic`? Anything shorter than the signature is a no, so a truncated
 * payload is never mistaken for a compressed one.
 *
 * @param bytes The bytes to inspect.
 * @param magic The signature to look for.
 * @returns True when every signature byte matches.
 */
export function hasMagic(bytes: Uint8Array, magic: readonly number[]): boolean {
  if (bytes.byteLength < magic.length) return false;
  return magic.every((b, i) => bytes[i] === b);
}
