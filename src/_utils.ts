import { DEFAULT_OPTIONS, HashOptions } from "./types";

function getNodeCrypto(): any | null {
  try {
    // use eval to avoid bundlers statically resolving `require('crypto')`
    // eslint-disable-next-line no-eval
    const rq: any = eval("require");
    return rq("crypto");
  } catch {
    return null;
  }
}

export function encodeBase64Url(data: Uint8Array): string {
  const Buf: any = (globalThis as any).Buffer;
  if (Buf && typeof Buf.from === "function")
    return Buf.from(data)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  let s = "";
  for (let i = 0; i < data.length; i++) s += String.fromCharCode(data[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64Url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const normalized = b64 + pad;
  const Buf: any = (globalThis as any).Buffer;
  if (Buf && typeof Buf.from === "function")
    return new Uint8Array(Buf.from(normalized, "base64"));
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

export function randomBytes(length: number): Uint8Array {
  if (
    typeof (globalThis as any).crypto !== "undefined" &&
    typeof (globalThis as any).crypto.getRandomValues === "function"
  ) {
    const b = new Uint8Array(length);
    (globalThis as any).crypto.getRandomValues(b);
    return b;
  }
  const crypto = getNodeCrypto();
  if (!crypto) throw new Error("crypto not available");
  return new Uint8Array(crypto.randomBytes(length));
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  if (isNode()) {
    const crypto = getNodeCrypto();
    try {
      const Buf: any = (globalThis as any).Buffer;
      if (crypto) return crypto.timingSafeEqual(Buf.from(a), Buf.from(b));
    } catch {
      // fallback
    }
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function pbkdf2Derive(
  password: string,
  salt: Uint8Array,
  iterations: number,
  keyLen: number,
  hash: "SHA-256" | "SHA-384" | "SHA-512",
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const passKey = enc.encode(password);
  // Try WebCrypto
  let subtle: any = undefined;
  if (
    typeof (globalThis as any).crypto !== "undefined" &&
    (globalThis as any).crypto.subtle
  )
    subtle = (globalThis as any).crypto.subtle;
  if (!subtle && isNode()) {
    const nodeCrypto = getNodeCrypto();
    if (nodeCrypto && nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle)
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
  // Node fallback
  return await new Promise((resolve, reject) => {
    const crypto = getNodeCrypto();
    const Buf: any = (globalThis as any).Buffer;
    if (!crypto) return reject(new Error("node crypto not available"));
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
