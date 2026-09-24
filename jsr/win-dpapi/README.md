# @neotales/win-dpapi

Windows Data Protection API (DPAPI) secret protection.

[![GitHub version](https://badge.fury.io/gh/neotales%2Fjs-os.svg)](https://badge.fury.io/gh/neotales/js-os)

## Installation

```sh
deno add jsr:@neotales/win-dpapi
npx jsr add @neotales/win-dpapi
```

## Protection API

The package root protects and unprotects opaque secret bytes with the Windows DPAPI. A protected value can normally be unprotected by the same Windows user on the same computer.

```ts
import { dpapiProtect, dpapiUnprotect, isDpapiAvailable } from "jsr:@neotales/win-dpapi";

if (!isDpapiAvailable())
  throw new Error("Windows DPAPI FFI is unavailable");

const secret = new TextEncoder().encode("secret");
const entropy = new TextEncoder().encode("application context");
const protectedSecret = dpapiProtect(secret, {
  entropy,
  prompt: "My application secret",
  promptRequired: true,
});

const unprotectedSecret = dpapiUnprotect(protectedSecret, { entropy });
console.log(new TextDecoder().decode(unprotectedSecret));
```

`entropy` is optional additional data that must be supplied again when unprotecting. `prompt` is stored as the data description. `promptRequired` sets `CRYPTPROTECT_UI_FORBIDDEN` and makes the operation fail instead of displaying a prompt. DPAPI is a Windows-only API; importing the package on another platform is supported, but `isDpapiAvailable()` returns `false` and protection operations throw.

## Native API

`@neotales/win-dpapi/ffi` exposes the runtime-dispatching `Dpapi` backend for callers that need the native protect and unprotect operations directly. It is safe to import on unsupported runtimes; call `isDpapiAvailable()` before invoking it.

```ts
import { Dpapi, isDpapiAvailable } from "jsr:@neotales/win-dpapi/ffi";

if (!isDpapiAvailable())
  throw new Error("Windows DPAPI FFI is unavailable");

const cipher = Dpapi.protect(new Uint8Array([0, 255, 1]));
const plain = Dpapi.unprotect(cipher);
```

`Dpapi.protect` and `Dpapi.unprotect` throw when the OS or runtime FFI backend is unavailable. The backend loads Deno, Bun, or Node FFI according to the current runtime and does not silently return placeholder data.

## Runtime Support

Deno requires `--allow-ffi`. Without it, `isDpapiAvailable()` returns `false` and DPAPI operations explain the missing permission.

Node.js requires Node 26 or later with `--experimental-ffi` and a Windows process. This package does not provide a fallback FFI implementation; when native Node FFI or `crypt32.dll` is unavailable, the operation reports that the backend could not be loaded.

DPAPI is a Windows-only API. Use `isDpapiAvailable()` before calling `dpapiProtect()` or `dpapiUnprotect()`; unsupported platforms return `false` and operations throw a clear unavailable error.

## License

[MIT License](./LICENSE.md)
