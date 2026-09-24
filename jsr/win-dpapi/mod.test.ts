import assert from "node:assert/strict";
import { test } from "node:test";
import { dpapiProtect, dpapiUnprotect, isDpapiAvailable } from "./mod.ts";
import { Dpapi, isDpapiAvailable as isNativeDpapiAvailable } from "./ffi.ts";

test("DPAPI availability reports a boolean", () => {
  assert.equal(typeof isDpapiAvailable(), "boolean");
  assert.equal(isDpapiAvailable(), isNativeDpapiAvailable());
});

test("DPAPI is explicitly unavailable on non-Windows runtimes", {
  skip: Deno.build.os === "windows",
}, () => {
  assert.equal(isDpapiAvailable(), false);
  assert.throws(() => dpapiProtect(new Uint8Array([0, 255, 1])), /Windows Data Protection API/);
  assert.throws(() => dpapiUnprotect(new Uint8Array([0, 255, 1])), /Windows Data Protection API/);
  assert.throws(() => Dpapi.protect(new Uint8Array([0, 255, 1])), /Windows Data Protection API/);
  assert.throws(() => Dpapi.unprotect(new Uint8Array([0, 255, 1])), /Windows Data Protection API/);
});

test("DPAPI protection roundtrips plaintext and validates entropy", {
  skip: Deno.build.os !== "windows" || !isDpapiAvailable(),
}, () => {
  const plaintext = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const entropy = new Uint8Array([9, 8, 7, 6]);
  const cipher = dpapiProtect(plaintext, {
    entropy,
    prompt: "neotales-win-dpapi-test",
    promptRequired: true,
  });

  assert.notDeepEqual(cipher, plaintext);
  assert.deepEqual(dpapiUnprotect(cipher, { entropy }), plaintext);
  assert.throws(() => dpapiUnprotect(cipher, { entropy: new Uint8Array([1, 2, 3, 4]) }));
});
