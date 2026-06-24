// Bastion inline autofill — runs on web pages (classic content script, no
// imports). When the user focuses a login field, it asks the background for
// accounts matching this site and shows a dropdown anchored under the field.
// Picking one fills the username/password directly in the page DOM.
//
// The background only ever returns non-secret metadata for the list (SUGGEST);
// the password is fetched (CREDS) and written into the field only when the user
// explicitly picks an account.
(() => {
  if (window.__bastionInjected) return; // guard against double-injection
  window.__bastionInjected = true;

  let overlay = null;
  let activeField = null;

  const esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const HOST = () => location.hostname.toLowerCase().replace(/^www\./, "");

  // Is this an input we should offer to fill?
  function isLoginField(el) {
    if (!el || el.tagName !== "INPUT" || el.disabled || el.readOnly) return false;
    const t = (el.type || "text").toLowerCase();
    if (t === "password" || t === "email") return true;
    if (!["text", "tel", ""].includes(t)) return false;
    const hint = `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder}`.toLowerCase();
    const looksUser = /user|email|login|account|e-mail/.test(hint);
    // Plain text field only qualifies if it looks like a username OR the form
    // also has a password field (typical login layout).
    return looksUser || !!(el.form && el.form.querySelector('input[type="password"]'));
  }

  const CSS = `
    .bx-list { font: 13px -apple-system, "Segoe UI", Roboto, sans-serif; background: #12151d;
      border: 1px solid #232838; border-radius: 12px; overflow: hidden;
      box-shadow: 0 12px 32px rgba(0,0,0,.5); color: #eef0f6; }
    .bx-head { display:flex; align-items:center; gap:6px; padding: 8px 12px; font-size: 11px;
      font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: #8a90a6;
      border-bottom: 1px solid #232838; }
    .bx-head svg { width: 14px; height: 14px; }
    .bx-row { display:flex; align-items:center; gap: 10px; padding: 9px 12px; cursor: pointer; }
    .bx-row:hover { background: #181c26; }
    .bx-ico { width: 28px; height: 28px; border-radius: 7px; flex: none; display:grid;
      place-items:center; color:#fff; font-weight:700; font-size: 13px; }
    .bx-meta { min-width: 0; }
    .bx-t { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .bx-s { color: #8a90a6; font-size: 11.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  `;
  const SHIELD =
    '<svg viewBox="0 0 32 32"><path fill="#7c6cff" d="M16 2l11 4v8.5c0 7-4.7 12.9-11 15.5C9.7 27.4 5 21.5 5 14.5V6l11-4z"/><circle cx="16" cy="14.5" r="3" fill="#12151d"/><path fill="#12151d" d="M14.6 15.5h2.8l1 5.5h-4.8z"/></svg>';

  function colorFor(title) {
    const palette = ["#7c6cff", "#3ad29f", "#ff7a59", "#47b5ff", "#f7b955", "#ff5d9e", "#19c3c3"];
    let h = 0;
    for (let i = 0; i < title.length; i++) h = (h * 31 + title.charCodeAt(i)) >>> 0;
    return palette[h % palette.length];
  }

  function removeOverlay() {
    overlay?.remove();
    overlay = null;
  }

  function setNative(el, value) {
    const desc = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillFields(field, username, password) {
    const scope = field.form || document;
    const pw = scope.querySelector('input[type="password"]:not([disabled]):not([readonly])');
    if (pw && password) setNative(pw, password);
    // username: the focused field if it's not the password, else find one
    let user = field.type !== "password" ? field : null;
    if (!user) {
      const cands = Array.from(scope.querySelectorAll("input")).filter(
        (i) => i.type !== "password" && !i.disabled && ["text", "email", "tel", ""].includes((i.type || "").toLowerCase())
      );
      const hint = (i) => `${i.name} ${i.id} ${i.autocomplete}`.toLowerCase();
      user = cands.find((i) => /user|email|login|account/.test(hint(i))) || cands[0] || null;
    }
    if (user && username) setNative(user, username);
  }

  function showOverlay(field, items) {
    removeOverlay();
    const rect = field.getBoundingClientRect();

    const hostEl = document.createElement("div");
    hostEl.style.position = "absolute";
    hostEl.style.zIndex = "2147483647";
    hostEl.style.left = `${window.scrollX + rect.left}px`;
    hostEl.style.top = `${window.scrollY + rect.bottom + 4}px`;
    hostEl.style.width = `${Math.max(rect.width, 240)}px`;

    const shadow = hostEl.attachShadow({ mode: "open" });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    shadow.adoptedStyleSheets = [sheet];

    const rows = items
      .map(
        (it) => `<div class="bx-row" data-id="${esc(it.id)}">
          <div class="bx-ico" style="background:${colorFor(it.title || "")}">${esc((it.title || "?")[0].toUpperCase())}</div>
          <div class="bx-meta"><div class="bx-t">${esc(it.title)}</div><div class="bx-s">${esc(it.username || "Login")}</div></div>
        </div>`
      )
      .join("");
    const wrap = document.createElement("div");
    wrap.className = "bx-list";
    wrap.innerHTML = `<div class="bx-head">${SHIELD} Bastion · ${items.length}</div>${rows}`;
    shadow.appendChild(wrap);
    document.documentElement.appendChild(hostEl);
    overlay = hostEl;

    shadow.querySelectorAll(".bx-row").forEach((row) => {
      // mousedown (not click) so it fires before the field's blur tears us down.
      row.addEventListener("mousedown", async (e) => {
        e.preventDefault();
        const r = await chrome.runtime.sendMessage({ type: "CREDS", id: row.dataset.id }).catch(() => null);
        if (r?.ok) fillFields(field, r.username, r.password);
        removeOverlay();
      });
    });
  }

  async function suggest(field) {
    activeField = field;
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: "SUGGEST", host: HOST() });
    } catch {
      return; // background not ready
    }
    if (field !== activeField) return; // focus moved on
    if (res?.ok && res.items?.length) showOverlay(field, res.items);
    else removeOverlay();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      if (isLoginField(e.target)) suggest(e.target);
    },
    true
  );
  document.addEventListener(
    "focusout",
    () => {
      activeField = null;
      setTimeout(removeOverlay, 200); // allow a row mousedown to win the race
    },
    true
  );
  // Reposition is hard across layouts; just dismiss on scroll/resize/Escape.
  window.addEventListener("scroll", removeOverlay, true);
  window.addEventListener("resize", removeOverlay, true);
  document.addEventListener("keydown", (e) => e.key === "Escape" && removeOverlay(), true);
})();
