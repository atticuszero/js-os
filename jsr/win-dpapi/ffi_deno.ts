import type { DpapiBackend, DpapiOptions } from "./types.ts";
import { stringToWide } from "./types.ts";

interface DenoFfi {
  dlopen(
    path: string,
    symbols: Record<string, unknown>,
  ): { symbols: Record<string, (...args: unknown[]) => unknown> };
  UnsafePointer: {
    create(value: bigint): Deno.PointerValue<unknown>;
    of(value: Uint8Array): Deno.PointerValue<unknown>;
    value(pointer: Deno.PointerValue<unknown>): number | bigint;
  };
  UnsafePointerView: new (pointer: unknown) => {
    getUint8(offset: number): number;
    setUint8(offset: number, value: number): void;
  };
}

const deno = (globalThis as typeof globalThis & { Deno?: DenoFfi }).Deno;
if (!deno)
  throw new Error("Deno FFI is unavailable.");

const crypt32 = deno.dlopen(
  "crypt32.dll",
  {
    CryptProtectData: {
      parameters: ["pointer", "pointer", "pointer", "pointer", "pointer", "u32", "pointer"],
      result: "i32",
    },
    CryptUnprotectData: {
      parameters: ["pointer", "pointer", "pointer", "pointer", "pointer", "u32", "pointer"],
      result: "i32",
    },
  } as const,
);
const kernel32 = deno.dlopen(
  "kernel32.dll",
  {
    GetLastError: { parameters: [], result: "u32" },
    LocalFree: { parameters: ["pointer"], result: "pointer" },
  } as const,
);
const { symbols } = crypt32;
const { symbols: k32 } = kernel32;

const SIZEOF_DATA_BLOB = 16;
const OFF_CB_DATA = 0;
const OFF_PB_DATA = 8;
const CRYPTPROTECT_UI_FORBIDDEN = 1;

interface NativeBlob {
  buffer: Uint8Array;
  data: Uint8Array | null;
}

function pointerOf(buffer: Uint8Array): Deno.PointerValue<unknown> {
  return deno.UnsafePointer.of(buffer);
}

function blob(data: Uint8Array | null | undefined): NativeBlob {
  const copy = data === null || data === undefined ? null : data.slice();
  const buffer = new Uint8Array(SIZEOF_DATA_BLOB);
  const view = new DataView(buffer.buffer);
  view.setUint32(OFF_CB_DATA, copy?.length ?? 0, true);
  view.setBigUint64(
    OFF_PB_DATA,
    copy === null ? 0n : BigInt(deno.UnsafePointer.value(deno.UnsafePointer.of(copy))),
    true,
  );
  return { buffer, data: copy };
}

function readU32(view: DataView, offset: number): number {
  return view.getUint32(offset, true);
}

function readPointer(view: DataView, offset: number): bigint {
  return view.getBigUint64(offset, true);
}

function readBytes(pointer: bigint, length: number): Uint8Array {
  if (pointer === 0n || length === 0)
    return new Uint8Array();
  const view = new deno.UnsafePointerView(deno.UnsafePointer.create(pointer));
  const buffer = new Uint8Array(length);
  for (let index = 0; index < length; index++)
    buffer[index] = view.getUint8(index);
  return buffer;
}

function readWideString(pointer: bigint): string {
  if (pointer === 0n)
    return "";
  const view = new deno.UnsafePointerView(deno.UnsafePointer.create(pointer));
  const characters: number[] = [];
  for (let offset = 0;; offset += 2) {
    const low = view.getUint8(offset);
    const high = view.getUint8(offset + 1);
    if (low === 0 && high === 0)
      break;
    characters.push(low | (high << 8));
  }
  return String.fromCharCode(...characters);
}

function wipeBuffer(buffer: Uint8Array | null): void {
  buffer?.fill(0);
}

function wipePointer(pointer: bigint, length: number): void {
  if (pointer === 0n || length === 0)
    return;
  const view = new deno.UnsafePointerView(deno.UnsafePointer.create(pointer));
  for (let index = 0; index < length; index++)
    view.setUint8(index, 0);
}

function free(pointer: bigint): void {
  if (pointer !== 0n)
    k32.LocalFree(deno.UnsafePointer.create(pointer));
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
  return { pointer: readPointer(view, OFF_PB_DATA), length: readU32(view, OFF_CB_DATA) };
}

/** Deno FFI backend for Windows DPAPI. */
export const backend: DpapiBackend = {
  protect(plain, options): Uint8Array {
    const input = blob(plain);
    const parts = optionsParts(options);
    const output = new Uint8Array(SIZEOF_DATA_BLOB);
    let outputPointer = 0n;
    let outputLength = 0;
    try {
      const success = symbols.CryptProtectData(
        pointerOf(input.buffer),
        parts.description === null ? null : pointerOf(parts.description),
        parts.entropy.data === null ? null : pointerOf(parts.entropy.buffer),
        null,
        null,
        parts.flags,
        pointerOf(output),
      );
      if (!success)
        throw new Error(`CryptProtectData failed with error code ${k32.GetLastError()}`);
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
      const success = symbols.CryptUnprotectData(
        pointerOf(input.buffer),
        pointerOf(descriptionOutput),
        parts.entropy.data === null ? null : pointerOf(parts.entropy.buffer),
        null,
        null,
        parts.flags,
        pointerOf(output),
      );
      if (!success)
        throw new Error(`CryptUnprotectData failed with error code ${k32.GetLastError()}`);
      const result = readOutput(output);
      outputPointer = result.pointer;
      outputLength = result.length;
      descriptionPointer = readPointer(
        new DataView(
          descriptionOutput.buffer,
          descriptionOutput.byteOffset,
          descriptionOutput.byteLength,
        ),
        0,
      );
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
