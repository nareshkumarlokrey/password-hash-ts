import {
  decodeBase64Url,
  pbkdf2Derive,
  timingSafeEqual,
  normalizeOptions,
  randomBytes,
} from "./_utils";
import { HashOptions } from "./types";

const HASH_REGEX =
  /^pbkdf2\$(sha256|sha384|sha512)\$(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/;

/** Parse a stored hash into components. */
export function parseHash(stored: string) {
  const m = HASH_REGEX.exec(stored);
  if (!m) throw new Error("invalid hash format");
  return {
    algorithm: m[1],
    iterations: parseInt(m[2], 10),
    saltB64: m[3],
    hashB64: m[4],
  };
}

export async function verifyPassword(
  password: string,
  storedHash: string,
): Promise<boolean> {
  if (typeof password !== "string" || password.length === 0) return false;
  let parsed;
  try {
    parsed = parseHash(storedHash);
  } catch {
    return false;
  }
  const salt = decodeBase64Url(parsed.saltB64);
  const expected = decodeBase64Url(parsed.hashB64);
  const webAlgo = `SHA-${parsed.algorithm.replace("sha", "")}` as
    | "SHA-256"
    | "SHA-384"
    | "SHA-512";
  const derived = await pbkdf2Derive(
    password,
    salt,
    parsed.iterations,
    expected.length,
    webAlgo,
  );
  return timingSafeEqual(derived, expected);
}

export function isHash(value: string): boolean {
  return HASH_REGEX.test(value);
}

export function hashInfo(hash: string) {
  const p = parseHash(hash);
  const salt = decodeBase64Url(p.saltB64);
  const h = decodeBase64Url(p.hashB64);
  return {
    algorithm: p.algorithm,
    iterations: p.iterations,
    saltLength: salt.length,
    hashLength: h.length,
  };
}

export function needsRehash(hash: string, options?: HashOptions): boolean {
  try {
    const info = hashInfo(hash);
    const opts = normalizeOptions(options);
    if (info.algorithm !== opts.algorithm) return true;
    if (info.iterations < opts.iterations) return true;
    if (info.saltLength !== opts.saltLength) return true;
    if (info.hashLength !== opts.hashLength) return true;
    return false;
  } catch {
    return true;
  }
}

export function generateSalt(length?: number): string {
  const len =
    typeof length === "number" && length > 0
      ? length
      : normalizeOptions().saltLength;
  const s = randomBytes(len);
  const Buf: any = (globalThis as any).Buffer;
  if (Buf && typeof Buf.from === "function") {
    return Buf.from(s)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  let str = "";
  for (let i = 0; i < s.length; i++) str += String.fromCharCode(s[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function compareHashes(a: string, b: string): boolean {
  try {
    const enc = new TextEncoder();
    const da = enc.encode(a);
    const db = enc.encode(b);
    return timingSafeEqual(da, db);
  } catch {
    return false;
  }
}

export function estimateStrength(password: string) {
  const len = password.length;
  let score = 0;
  if (len >= 8) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  const level =
    score <= 2
      ? "weak"
      : score === 3
        ? "medium"
        : score === 4
          ? "strong"
          : "very-strong";
  return { score, level } as const;
}
