import { describe, it, expect } from "vitest";
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  generateSalt,
} from "../src";

describe("verifyPassword", () => {
  it("verifies correct password", async () => {
    const h = await hashPassword("mypassword");
    const ok = await verifyPassword("mypassword", h);
    expect(ok).toBe(true);
  });

  it("rejects incorrect password", async () => {
    const h = await hashPassword("mypassword");
    const ok = await verifyPassword("wrong", h);
    expect(ok).toBe(false);
  });

  it("generateSalt returns string", () => {
    const s = generateSalt(12);
    expect(typeof s).toBe("string");
  });

  it("needsRehash returns boolean", async () => {
    const h = await hashPassword("a");
    expect(needsRehash(h, { iterations: 200000 })).toBe(true);
  });
});
