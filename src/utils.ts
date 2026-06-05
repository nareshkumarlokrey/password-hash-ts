import { DEFAULT_OPTIONS, HashOptions } from "./types";

/** Encode a Uint8Array to base64url string without padding. */
export function encodeBase64Url(data: Uint8Array): string {
  const Buf: any = (globalThis as any).Buffer;
  if (typeof Buf !== "undefined" && typeof Buf.from === "function") {
    return Buf.from(data)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  let str = "";
  for (let i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
  const b64 = btoa(str);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode a base64url string to Uint8Array */
export function decodeBase64Url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const normalized = b64 + pad;
  const Buf: any = (globalThis as any).Buffer;
  if (typeof Buf !== "undefined" && typeof Buf.from === "function") {
    return new Uint8Array(Buf.from(normalized, "base64"));
  }
  const bin = atob(normalized);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

export function isNode(): boolean {
  return (
    typeof process !== "undefined" &&
    !!(process.versions && process.versions.node)
  );
}

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function"
  ) {
    const b = new Uint8Array(length);
    globalThis.crypto.getRandomValues(b);
    return b;
  }
  // Node
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const crypto = require("crypto");
  return new Uint8Array(crypto.randomBytes(length));
}

/** Constant-time comparison of two Uint8Array values. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  if (isNode()) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require("crypto");
    try {
      const Buf: any = (globalThis as any).Buffer;
      return crypto.timingSafeEqual(Buf.from(a), Buf.from(b));
    } catch {
      // fallback
    }
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Derive a key using PBKDF2. Returns derived bytes. */
export async function pbkdf2Derive(
  password: string,
  salt: Uint8Array,
  iterations: number,
  keyLen: number,
  hash: "SHA-256" | "SHA-384" | "SHA-512",
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const passKey = enc.encode(password);

  // Use Web Crypto when available
  let subtle: any = undefined;
  if (
    typeof (globalThis as any).crypto !== "undefined" &&
    (globalThis as any).crypto.subtle
  )
    subtle = (globalThis as any).crypto.subtle;
  if (!subtle && isNode()) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require("crypto");
    if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle)
      subtle = nodeCrypto.webcrypto.subtle;
  }
  if (subtle && typeof subtle.importKey === "function") {
    const key = await subtle.importKey(
      "raw",
      passKey,
      { name: "PBKDF2" },
      false,
      ["deriveBits"],
    );
    const params: any = { name: "PBKDF2", hash, salt: salt.buffer, iterations };
    const bits = await subtle.deriveBits(params, key, keyLen * 8);
    return new Uint8Array(bits);
  }

  // Node fallback using crypto.pbkdf2
  return await new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require("crypto");
    const Buf: any = (globalThis as any).Buffer;
    crypto.pbkdf2(
      passKey,
      Buf.from(salt),
      iterations,
      keyLen,
      hash.replace("SHA-", "sha"),
      (err: Error | null, derived: any) => {
        if (err) return reject(err);
        resolve(new Uint8Array(derived));
      },
    );
  });
}

export function normalizeOptions(opts?: HashOptions) {
  return { ...DEFAULT_OPTIONS, ...(opts || {}) };
}
