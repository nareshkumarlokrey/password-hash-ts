/**
 * Options for hashing operations.
 */
export interface HashOptions {
  iterations?: number;
  saltLength?: number;
  hashLength?: number;
  algorithm?: "sha256" | "sha384" | "sha512";
}

/**
 * Parsed information about a stored hash.
 */
export interface HashInfo {
  algorithm: string;
  iterations: number;
  saltLength: number;
  hashLength: number;
}

export interface StrengthResult {
  score: number;
  level: "weak" | "medium" | "strong" | "very-strong";
}

export const DEFAULT_OPTIONS: Required<HashOptions> = {
  iterations: 100000,
  saltLength: 16,
  hashLength: 32,
  algorithm: "sha256",
};
