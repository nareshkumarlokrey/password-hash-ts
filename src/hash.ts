import {
  encodeBase64Url,
  randomBytes,
  pbkdf2Derive,
  normalizeOptions,
} from "./_utils";
import { HashOptions } from "./types";

/**
 * Hash a password using PBKDF2 and return a self-contained string.
 * Format: pbkdf2$sha256$iterations$salt$hash
 */
export async function hashPassword(
  password: string,
  options?: HashOptions,
): Promise<string> {
  if (typeof password !== "string" || password.length === 0)
    throw new Error("password must be a non-empty string");
  const opts = normalizeOptions(options);
  if (opts.iterations <= 0) throw new Error("iterations must be > 0");

  const salt = randomBytes(opts.saltLength);
  const webAlgo = `SHA-${opts.algorithm.replace("sha", "")}` as
    | "SHA-256"
    | "SHA-384"
    | "SHA-512";
  const derived = await pbkdf2Derive(
    password,
    salt,
    opts.iterations,
    opts.hashLength,
    webAlgo,
  );

  const saltB64 = encodeBase64Url(salt);
  const hashB64 = encodeBase64Url(derived);

  const formatted = [
    `pbkdf2`,
    opts.algorithm,
    String(opts.iterations),
    saltB64,
    hashB64,
  ].join("$");
  return formatted;
}
