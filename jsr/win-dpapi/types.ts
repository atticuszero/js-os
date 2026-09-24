/** Windows Data Protection API types and helpers. @module @neotales/win-dpapi/ffi */

/** Optional data description included in a DPAPI-protected value. */
export type DpapiDescription = string | null;

/** Options passed to DPAPI protection and unprotection. */
export interface DpapiOptions {
  /** Additional entropy required by both operations, or `null`. */
  entropy?: Uint8Array | null;
  /** Data description stored by protection, or `null`. */
  prompt?: DpapiDescription;
  /** Whether DPAPI must avoid displaying a user interface. */
  promptRequired?: boolean;
}

/** Runtime-specific Windows DPAPI operations. */
export interface DpapiBackend {
  /**
   * Protects plaintext with Windows DPAPI.
   * @param plain Plaintext bytes to protect.
   * @param options Optional entropy, description, and prompt behavior.
   * @returns Protected bytes.
   * @throws {Error} If Windows DPAPI or the runtime FFI backend is unavailable.
   */
  protect(plain: Uint8Array, options?: DpapiOptions): Uint8Array;
  /**
   * Unprotects bytes with Windows DPAPI.
   * @param cipher Protected bytes to unprotect.
   * @param options Optional entropy, description, and prompt behavior.
   * @returns Plaintext bytes.
   * @throws {Error} If Windows DPAPI or the runtime FFI backend is unavailable.
   */
  unprotect(cipher: Uint8Array, options?: DpapiOptions): Uint8Array;
}

/** Whether the current runtime is Windows. */
export const WINDOWS = (typeof globalThis.Deno !== "undefined" && Deno.build.os === "windows") ||
  (typeof globalThis.process !== "undefined" && process.platform === "win32");

/**
 * Encodes a string as a null-terminated UTF-16LE buffer.
 * @param value String to encode.
 * @returns Null-terminated UTF-16LE bytes.
 * @example
 * ```ts
 * import { stringToWide } from "@neotales/win-dpapi/ffi";
 *
 * const buffer = stringToWide("application");
 * ```
 */
export function stringToWide(value: string): Uint8Array {
  const buffer = new Uint8Array((value.length + 1) * 2);
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    buffer[index * 2] = code & 0xff;
    buffer[index * 2 + 1] = code >> 8;
  }
  return buffer;
}
