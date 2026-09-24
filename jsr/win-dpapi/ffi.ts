/** Native Windows Data Protection API. @module @neotales/win-dpapi/ffi */

import type { DpapiBackend } from "./types.ts";
import { WINDOWS } from "./types.ts";

let unavailableReason =
  "Windows Data Protection API is only available on Windows for the NodeJs, Deno, and Bun runtimes.";
const unavailableDpapi: DpapiBackend = {
  protect(): Uint8Array {
    throw new Error(unavailableReason);
  },
  unprotect(): Uint8Array {
    throw new Error(unavailableReason);
  },
};

let Dpapi = unavailableDpapi;
let available = false;
if (WINDOWS) {
  try {
    if ("Deno" in globalThis)
      Dpapi = (await import("./ffi_deno.ts")).backend;
    else if ("Bun" in globalThis)
      Dpapi = (await import("./ffi_bun.ts")).backend;
    else
      Dpapi = (await import("./ffi_node.ts")).backend;
    available = true;
  } catch (error) {
    unavailableReason = error instanceof Error ? error.message : String(error);
  }
}

/**
 * Reports whether the native backend loaded successfully.
 * @returns `true` when {@link Dpapi} operations are available.
 * @example
 * ```ts
 * import { isDpapiAvailable } from "@neotales/win-dpapi/ffi";
 *
 * console.log(isDpapiAvailable());
 * ```
 */
export function isDpapiAvailable(): boolean {
  return available;
}

/** Raw Windows DPAPI operations that throw when unavailable. */
export { Dpapi };
export { type DpapiBackend, type DpapiDescription, type DpapiOptions, WINDOWS } from "./types.ts";
