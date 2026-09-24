/**
 * Windows Data Protection API (DPAPI) secret protection.
 *
 * @example Usage
 * ```ts
 * import { dpapiProtect, dpapiUnprotect, isDpapiAvailable } from "@neotales/win-dpapi";
 *
 * if (isDpapiAvailable()) {
 *   const cipher = dpapiProtect(new TextEncoder().encode("secret"));
 *   const plain = dpapiUnprotect(cipher);
 * }
 * ```
 *
 * @module
 */

import { Dpapi, isDpapiAvailable } from "./ffi.ts";
import type { DpapiOptions } from "./types.ts";

export { isDpapiAvailable };
export type { DpapiBackend, DpapiDescription, DpapiOptions } from "./types.ts";

/**
 * Protects bytes with the Windows Data Protection API.
 * @param plain Plaintext bytes to protect.
 * @param options Optional entropy, description, and prompt behavior.
 * @returns Protected bytes.
 * @throws {Error} If Windows DPAPI or the runtime FFI backend is unavailable.
 * @example
 * ```ts
 * import { dpapiProtect } from "@neotales/win-dpapi";
 *
 * const cipher = dpapiProtect(new Uint8Array([0, 255, 1]));
 * ```
 */
export function dpapiProtect(plain: Uint8Array, options?: DpapiOptions): Uint8Array {
  return Dpapi.protect(plain, options);
}

/**
 * Unprotects bytes with the Windows Data Protection API.
 * @param cipher Protected bytes to unprotect.
 * @param options Optional entropy, description, and prompt behavior.
 * @returns Plaintext bytes.
 * @throws {Error} If Windows DPAPI or the runtime FFI backend is unavailable.
 * @example
 * ```ts
 * import { dpapiUnprotect } from "@neotales/win-dpapi";
 *
 * const plain = dpapiUnprotect(cipher);
 * ```
 */
export function dpapiUnprotect(cipher: Uint8Array, options?: DpapiOptions): Uint8Array {
  return Dpapi.unprotect(cipher, options);
}
