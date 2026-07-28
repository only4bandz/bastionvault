// Rough local password-strength estimate (no network). Returns {label, ok, level}.
//
// Lives in a shared module so the background worker can compute it while the
// password is still in hand, and the popup can render the verdict without
// ever receiving the password itself.

export function passwordStrength(pw) {
  if (!pw) return { label: "No password", ok: false, level: 0 };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score >= 5) return { label: "Strong password", ok: true, level: 3 };
  if (score >= 3) return { label: "Fair password", ok: false, level: 2 };
  return { label: "Weak password", ok: false, level: 1 };
}
