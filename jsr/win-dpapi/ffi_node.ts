/** Node.js FFI backend for Windows DPAPI. */

import { createRequire } from "node:module";
import type { DpapiBackend, DpapiOptions } from "./types.ts";
import { stringToWide } from "./types.ts";

interface NodeFfi {
  dlopen(
    path: string,
    symbols: Record<string, unknown>,
  ): { functions: Record<string, (...args: unknown[]) => unknown> };
  getRawPointer(value: Uint8Array): bigint;
  getUint8(pointer: bigint, offset: number): number;
  setUint8(pointer: bigint, offset: number, value: number): void;
  toArrayBuffer(pointer: bigint, length: number): ArrayBuffer;
}

const require = createRequire(import.meta.url);
const specifier = "node:ffi";
let ffi: NodeFfi;

try {
  ffi = require(specifier);
} catch (cause) {
  throw new Error(
    `Unable to load ${specifier}. Run Node.js >= 26 with --experimental-ffi on Windows. This package has no fallback FFI implementation.`,
    { cause },
  );
}

let crypt32: ReturnType<NodeFfi["dlopen"]>;
let kernel32: ReturnType<NodeFfi["dlopen"]>;
try {
  crypt32 = ffi.dlopen("crypt32.dll", {
    CryptProtectData: {
      arguments: ["pointer", "pointer", "pointer", "pointer", "pointer", "u32", "pointer"],
      return: "i32",
    },
    CryptUnprotectData: {
      arguments: ["pointer", "pointer", "pointer", "pointer", "pointer", "u32", "pointer"],
      return: "i32",
    },
  });
  kernel32 = ffi.dlopen("kernel32.dll", {
    GetLastError: { arguments: [], return: "u32" },
    LocalFree: { arguments: ["pointer"], return: "pointer" },
  });
} catch (cause) {
  throw new Error(
    "Unable to bind crypt32.dll and kernel32.dll through node:ffi. Run Node.js >= 26 with --experimental-ffi on Windows.",
    { cause },
  );
}

const SIZEOF_DATA_BLOB = 16;
const OFF_CB_DATA = 0;
const OFF_PB_DATA = 8;
const CRYPTPROTECT_UI_FORBIDDEN = 1;

interface NativeBlob {
  buffer: Uint8Array;
  data: Uint8Array | null;
}

function blob(data: Uint8Array | null | undefined): NativeBlob {
  const copy = data === null || data === undefined ? null : data.slice();
  const buffer = new Uint8Array(SIZEOF_DATA_BLOB);
  const view = new DataView(buffer.buffer);
  view.setUint32(OFF_CB_DATA, copy?.length ?? 0, true);
  view.setBigUint64(OFF_PB_DATA, copy === null ? 0n : ffi.getRawPointer(copy), true);
  return { buffer, data: copy };
}

function readWideString(pointer: bigint): string {
  if (pointer === 0n)
    return "";
  const characters: number[] = [];
  for (let offset = 0;; offset += 2) {
    const low = ffi.getUint8(pointer, offset);
    const high = ffi.getUint8(pointer, offset + 1);
    if (low === 0 && high === 0)
      break;
    characters.push(low | (high << 8));
  }
  return String.fromCharCode(...characters);
}

function readBytes(pointer: bigint, length: number): Uint8Array {
  if (pointer === 0n || length === 0)
    return new Uint8Array();
  return new Uint8Array(ffi.toArrayBuffer(pointer, length));
}

function wipeBuffer(buffer: Uint8Array | null): void {
  buffer?.fill(0);
}

function wipePointer(pointer: bigint, length: number): void {
  if (pointer === 0n)
    return;
  for (let index = 0; index < length; index++)
    ffi.setUint8(pointer, index, 0);
}

function free(pointer: bigint): void {
  if (pointer !== 0n)
    kernel32.functions.LocalFree(pointer);
}

function optionsParts(options?: DpapiOptions): {
  entropy: NativeBlob;
  description: Uint8Array | null;
  flags: number;
} {
  return {
    entropy: blob(options?.entropy),
    description: options?.prompt === null || options?.prompt === undefined
      ? null
      : stringToWide(options.prompt),
    flags: options?.promptRequired ? CRYPTPROTECT_UI_FORBIDDEN : 0,
  };
}

function readOutput(output: Uint8Array): { pointer: bigint; length: number } {
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  return {
    pointer: view.getBigUint64(OFF_PB_DATA, true),
    length: view.getUint32(OFF_CB_DATA, true),
  };
}

/** Raw DPAPI operations implemented through Node.js FFI. */
export const backend: DpapiBackend = {
  protect(plain, options): Uint8Array {
    const input = blob(plain);
    const parts = optionsParts(options);
    const output = new Uint8Array(SIZEOF_DATA_BLOB);
    let outputPointer = 0n;
    let outputLength = 0;
    try {
      const success = crypt32.functions.CryptProtectData(
        input.buffer,
        parts.description,
        parts.entropy.data === null ? null : parts.entropy.buffer,
        null,
        null,
        parts.flags,
        output,
      );
      if (!success)
        throw new Error(
          `CryptProtectData failed with Win32 error ${kernel32.functions.GetLastError()}`,
        );
      const result = readOutput(output);
      outputPointer = result.pointer;
      outputLength = result.length;
      if (outputPointer === 0n && outputLength !== 0)
        throw new Error("CryptProtectData returned an invalid output buffer.");
      return readBytes(outputPointer, outputLength);
    } finally {
      wipePointer(outputPointer, outputLength);
      free(outputPointer);
      wipeBuffer(input.buffer);
      wipeBuffer(input.data);
      wipeBuffer(parts.entropy.buffer);
      wipeBuffer(parts.entropy.data);
      wipeBuffer(parts.description);
      wipeBuffer(output);
    }
  },
  unprotect(cipher, options): Uint8Array {
    const input = blob(cipher);
    const parts = optionsParts(options);
    const output = new Uint8Array(SIZEOF_DATA_BLOB);
    const descriptionOutput = new Uint8Array(8);
    let outputPointer = 0n;
    let outputLength = 0;
    let descriptionPointer = 0n;
    try {
      const success = crypt32.functions.CryptUnprotectData(
        input.buffer,
        descriptionOutput,
        parts.entropy.data === null ? null : parts.entropy.buffer,
        null,
        null,
        parts.flags,
        output,
      );
      if (!success)
        throw new Error(
          `CryptUnprotectData failed with Win32 error ${kernel32.functions.GetLastError()}`,
        );
      const result = readOutput(output);
      outputPointer = result.pointer;
      outputLength = result.length;
      descriptionPointer = new DataView(
        descriptionOutput.buffer,
        descriptionOutput.byteOffset,
        descriptionOutput.byteLength,
      ).getBigUint64(0, true);
      if (descriptionPointer !== 0n)
        readWideString(descriptionPointer);
      if (outputPointer === 0n && outputLength !== 0)
        throw new Error("CryptUnprotectData returned an invalid output buffer.");
      return readBytes(outputPointer, outputLength);
    } finally {
      wipePointer(outputPointer, outputLength);
      free(outputPointer);
      free(descriptionPointer);
      wipeBuffer(input.buffer);
      wipeBuffer(input.data);
      wipeBuffer(parts.entropy.buffer);
      wipeBuffer(parts.entropy.data);
      wipeBuffer(parts.description);
      wipeBuffer(descriptionOutput);
      wipeBuffer(output);
    }
  },
};
