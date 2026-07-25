/** Optional HTTPS origins that are no longer needed for the selected server. */
export function staleServerOrigins(grantedOrigins, retainedPattern = null) {
  if (!Array.isArray(grantedOrigins)) return [];
  return [...new Set(grantedOrigins)].filter(
    (origin) =>
      typeof origin === "string" &&
      origin.startsWith("https://") &&
      origin !== retainedPattern
  );
}
