/**
 * Require Chrome to isolate a storage area from content scripts before use.
 * Secret-bearing callers must fail closed if the API is unavailable or the
 * browser refuses the requested access level.
 */
export async function requireTrustedStorageArea(area) {
  if (!area || typeof area.setAccessLevel !== "function") {
    throw new Error("Trusted extension storage isolation is unavailable.");
  }
  try {
    await area.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  } catch {
    throw new Error("Trusted extension storage isolation could not be enforced.");
  }
  return area;
}
