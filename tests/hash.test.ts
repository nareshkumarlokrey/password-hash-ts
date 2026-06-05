import { describe, it, expect } from "vitest";
import { hashPassword, isHash, estimateStrength } from "../src";

describe("hashPassword / isHash", () => {
  it("produces a valid hash", async () => {
    const h = await hashPassword("secret123!");
    expect(typeof h).toBe("string");
    expect(isHash(h)).toBe(true);
  });

  it("estimates strength", () => {
    const r = estimateStrength("secret123!");
    expect(r.score).toBeGreaterThanOrEqual(1);
  });
});
