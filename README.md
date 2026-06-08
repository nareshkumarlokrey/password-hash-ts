<!--
<meta name="description" content="Password-hash-ts — Zero-dependency TypeScript library providing secure PBKDF2 password hashing for Node.js, React, and browsers. Supports Web Crypto and Node crypto, ESM/CJS builds, and a browser bundle." />
<meta name="keywords" content="password hashing,pbkdf2,sha256,typescript,webcrypto,nodejs,react,crypto,security" />
-->

# password-hash-ts
Current version: v1.0.1

Password-hash-ts is a zero-dependency TypeScript library for secure PBKDF2 password hashing across Node.js, React, and browser environments. It uses platform-native cryptography (Web Crypto / Node.js crypto), produces self-contained hashes, and ships ESM, CJS and browser bundles.

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/nareshkumarlokrey/password-hash-ts/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Short description: Secure, portable PBKDF2 password hashing for Node, React, and browser apps.

Examples

Node.js (ESM)

```js
import { hashPassword, verifyPassword, isHash, needsRehash, estimateStrength } from "password-hash-ts";

const password = "MyStrongPassword123!";
const hash = await hashPassword(password);
console.log("Hash:", hash);
console.log("Verify:", await verifyPassword(password, hash));
```

Node.js (CommonJS)

```js
const { hashPassword, verifyPassword } = require("password-hash-ts");

(async () => {
	const hash = await hashPassword("secret123");
	console.log("Hash:", hash);
	console.log("Verify:", await verifyPassword("secret123", hash));
})();
```

React (hooks)

```jsx
import React, { useEffect, useState } from "react";
import { hashPassword, verifyPassword } from "password-hash-ts";

function Example() {
	const [hash, setHash] = useState(null);

	useEffect(() => {
		(async () => {
			const h = await hashPassword("MyReactPassword!");
			setHash(h);
			const ok = await verifyPassword("MyReactPassword!", h);
			console.log("Verified in React:", ok);
		})();
	}, []);

	return <div>Hash: {hash}</div>;
}

export default Example;
```

Features

- PBKDF2 with SHA-256 (default)
- Cross-platform: Web Crypto and Node.js crypto
- Self-contained hash format: pbkdf2$sha256$iterations$salt$hash
- Zero runtime dependencies
