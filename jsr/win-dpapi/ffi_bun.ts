/** Bun FFI backend for Windows DPAPI. */

import type { DpapiBackend, DpapiOptions } from "./types.ts";
import { stringToWide } from "./types.ts";

interface BunFfi {
  dlopen(
    path: string,
    symbols: Record<string, unknown>,
  ): { symbols: Record<string, (...args: unknown[]) => unknown> };
  ptr(value: Uint8Array): number;
  read: {
    ptr(value: Uint8Array, offset: number): bigint;
    u8(pointer: number, offset: number): number;
    u32(value: Uint8Array, offset: number): number;
  };
  toArrayBuffer(pointer: number, byteOffset: number, length: number): ArrayBuffer;
  write: {
    u8(pointer: number, offset: number, value: number): void;
  };
}

const specifier = "bun:ffi";
let ffi: BunFfi;

try {
  ffi = await import(/* @vite-ignore */ specifier);
} catch (cause) {
  throw new Error(`Unable to load ${specifier}. Run this backend in Bun.`, { cause });
}

const crypt32 = ffi.dlopen("crypt32.dll", {
  CryptProtectData: {
    args: ["ptr", "ptr", "ptr", "ptr", "ptr", "u32", "ptr"],
    returns: "i32",
  },
  CryptUnprotectData: {
    args: ["ptr", "ptr", "ptr", "ptr", "ptr", "u32", "ptr"],
    returns: "i32",
  },
});
const kernel32 = ffi.dlopen("kernel32.dll", {
  GetLastError: { args: [], returns: "u32" },
  LocalFree: { args: ["ptr"], returns: "ptr" },
});

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
  view.setBigUint64(OFF_PB_DATA, copy === null ? 0n : BigInt(ffi.ptr(copy)), true);
  return { buffer, data: copy };
}

function readWideString(pointer: number): string {
  if (pointer === 0)
    return "";
  const characters: number[] = [];
  for (let offset = 0;; offset += 2) {
    const low = ffi.read.u8(pointer, offset);
    const high = ffi.read.u8(pointer, offset + 1);
    if (low === 0 && high === 0)
      break;
    characters.push(low | (high << 8));
  }
  return String.fromCharCode(...characters);
}

function readBytes(pointer: number, length: number): Uint8Array {
  if (pointer === 0 || length === 0)
    return new Uint8Array();
  return new Uint8Array(ffi.toArrayBuffer(pointer, 0, length));
}

function wipeBuffer(buffer: Uint8Array | null): void {
  buffer?.fill(0);
}

function wipePointer(pointer: number, length: number): void {
  if (pointer === 0)
    return;
  for (let index = 0; index < length; index++)
    ffi.write.u8(pointer, index, 0);
}

function free(pointer: number): void {
  if (pointer !== 0)
    kernel32.symbols.LocalFree(pointer);
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

function readOutput(output: Uint8Array): { pointer: number; length: number } {
  return {
    pointer: Number(ffi.read.ptr(output, OFF_PB_DATA)),
    length: ffi.read.u32(output, OFF_CB_DATA),
  };
}

function entropyPointer(entropy: NativeBlob): number | null {
  return entropy.data === null ? null : ffi.ptr(entropy.buffer);
}

/** Raw DPAPI operations implemented through Bun FFI. */
export const backend: DpapiBackend = {
  protect(plain, options): Uint8Array {
    const input = blob(plain);
    const parts = optionsParts(options);
    const output = new Uint8Array(SIZEOF_DATA_BLOB);
    let outputPointer = 0;
    let outputLength = 0;
    try {
      const success = crypt32.symbols.CryptProtectData(
        ffi.ptr(input.buffer),
        parts.description === null ? null : ffi.ptr(parts.description),
        entropyPointer(parts.entropy),
        null,
        null,
        parts.flags,
        ffi.ptr(output),
      );
      if (!success)
        throw new Error(
          `CryptProtectData failed with Win32 error ${kernel32.symbols.GetLastError()}`,
        );
      const result = readOutput(output);
      outputPointer = result.pointer;
      outputLength = result.length;
      if (outputPointer === 0 && outputLength !== 0)
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
    let outputPointer = 0;
    let outputLength = 0;
    let descriptionPointer = 0;
    try {
      const success = crypt32.symbols.CryptUnprotectData(
        ffi.ptr(input.buffer),
        ffi.ptr(descriptionOutput),
        entropyPointer(parts.entropy),
        null,
        null,
        parts.flags,
        ffi.ptr(output),
      );
      if (!success)
        throw new Error(
          `CryptUnprotectData failed with Win32 error ${kernel32.symbols.GetLastError()}`,
        );
      const result = readOutput(output);
      outputPointer = result.pointer;
      outputLength = result.length;
      descriptionPointer = Number(ffi.read.ptr(descriptionOutput, 0));
      if (descriptionPointer !== 0)
        readWideString(descriptionPointer);
      if (outputPointer === 0 && outputLength !== 0)
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
