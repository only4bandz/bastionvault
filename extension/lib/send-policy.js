export const SIGNING_UNAVAILABLE =
  "Your sender identity could not be confirmed. Nothing was sent; retry or choose anonymous mode explicitly.";

/** Resolve the identity required by signed mode without silently downgrading. */
export async function senderIdForMode({ signed, cachedId, lookup }) {
  if (!signed) return null;
  let id = cachedId;
  if (!id) {
    try {
      id = await lookup();
    } catch {
      throw new Error(SIGNING_UNAVAILABLE);
    }
  }
  if (typeof id !== "string" || !id) throw new Error(SIGNING_UNAVAILABLE);
  return id;
}
