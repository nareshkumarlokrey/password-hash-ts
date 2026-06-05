import {
  hashPassword,
  verifyPassword,
  isHash,
  hashInfo,
  needsRehash,
  estimateStrength,
  generateSalt,
} from "../dist/index.mjs";

const password = "MyStrongPassword123!";

console.log("Password:", password);

const hash = await hashPassword(password);
console.log("Hash:", hash);

const info = hashInfo(hash);
console.log("Hash info:", info);

const ok = await verifyPassword(password, hash);
console.log("Verify (correct):", ok);

const wrong = await verifyPassword("wrongpass", hash);
console.log("Verify (wrong):", wrong);

console.log("isHash:", isHash(hash));
console.log("needsRehash (iterations=200000):", needsRehash(hash, { iterations: 200000 }));

console.log("estimateStrength:", estimateStrength(password));

console.log("generateSalt(12):", generateSalt(12));
