import assert from "node:assert/strict";
import test from "node:test";

import { staleServerOrigins } from "../lib/permission-policy.js";

test("revokes every obsolete optional HTTPS server origin", () => {
  assert.deepEqual(
    staleServerOrigins(
      [
        "http://localhost/*",
        "https://old.example/*",
        "https://vault.example/*",
        "https://old.example/*",
      ],
      "https://vault.example/*"
    ),
    ["https://old.example/*"]
  );
});

test("revokes all optional HTTPS origins for a built-in loopback server", () => {
  assert.deepEqual(
    staleServerOrigins(["http://127.0.0.1/*", "https://old.example/*"]),
    ["https://old.example/*"]
  );
  assert.deepEqual(staleServerOrigins(null), []);
});
