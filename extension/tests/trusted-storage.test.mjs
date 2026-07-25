import assert from "node:assert/strict";
import test from "node:test";

import { requireTrustedStorageArea } from "../lib/trusted-storage.js";

test("returns storage only after trusted-context isolation succeeds", async () => {
  const calls = [];
  const area = {
    setAccessLevel: async (options) => calls.push(options),
  };
  assert.equal(await requireTrustedStorageArea(area), area);
  assert.deepEqual(calls, [{ accessLevel: "TRUSTED_CONTEXTS" }]);
});

test("fails closed when storage isolation is absent or rejected", async () => {
  await assert.rejects(requireTrustedStorageArea({}), /unavailable/i);
  await assert.rejects(
    requireTrustedStorageArea({
      setAccessLevel: async () => {
        throw new Error("denied");
      },
    }),
    /could not be enforced/i
  );
});
