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

  // ── password generator (inline copy of lib/generator.js; content scripts
  // can't import ES modules) ──
  const GEN_SETS = {
    lower: "abcdefghijkmnpqrstuvwxyz",
    upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
    digits: "23456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?",
  };
  function randInt(n) {
    const max = Math.floor(0xffffffff / n) * n;
    const buf = new Uint32Array(1);
    let x;
    do {
      crypto.getRandomValues(buf);
      x = buf[0];
    } while (x >= max);
    return x % n;
  }
  function genPassword(length = 20) {
    const sets = [GEN_SETS.lower, GEN_SETS.upper, GEN_SETS.digits, GEN_SETS.symbols];
    const pool = sets.join("");
    const chars = sets.map((s) => s[randInt(s.length)]);
    while (chars.length < length) chars.push(pool[randInt(pool.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

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

  // A password field where we should offer to GENERATE a new one (sign-up /
  // change-password), rather than suggest existing logins.
  function isNewPasswordField(el) {
    if (!el || el.tagName !== "INPUT" || (el.type || "").toLowerCase() !== "password") return false;
    const ac = (el.autocomplete || "").toLowerCase();
    if (ac === "new-password") return true;
    if (ac === "current-password") return false;
    const hint = `${el.name} ${el.id}`.toLowerCase();
    if (/new|confirm|signup|sign-up|register|create|repeat/.test(hint)) return true;
    // Sign-up forms typically have two password fields (password + confirm).
    const scope = el.form || document;
    return scope.querySelectorAll('input[type="password"]').length >= 2;
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
    .bx-gen { display:flex; align-items:center; gap:10px; padding: 12px; }
    .bx-pw { flex:1; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 14px;
      letter-spacing: .3px; word-break: break-all; color: #eef0f6; }
    .bx-regen { flex:none; width:34px; height:34px; border:none; border-radius:9px;
      background:#181c26; color:#9a8cff; cursor:pointer; display:grid; place-items:center; }
    .bx-regen:hover { background:#232838; }
    .bx-regen svg { width:18px; height:18px; }
    .bx-len { display:flex; align-items:center; gap:10px; padding: 0 12px 10px; color:#8a90a6; font-size:12px; }
    .bx-len b { color:#eef0f6; }
    .bx-range { flex:1; accent-color:#7c6cff; }
    .bx-use { display:block; width: calc(100% - 24px); margin: 0 12px 12px; padding: 9px;
      border:none; border-radius:10px; cursor:pointer; font-weight:700; font-size: 13px; color:#fff;
      background: linear-gradient(135deg, #7c6cff, #5a47e6); }
    .bx-save-body { padding: 12px; }
    .bx-input { width:100%; box-sizing:border-box; margin-top:4px; padding:8px 10px; border-radius:9px;
      border:1px solid #232838; background:#181c26; color:#eef0f6; font-size:13px; outline:none; }
    .bx-input:focus { border-color:#7c6cff; }
    .bx-lbl { font-size:11px; color:#8a90a6; margin-top:8px; }
    .bx-host { display:flex; align-items:center; gap:8px; font-weight:600; }
    .bx-btns { display:flex; gap:8px; padding: 0 12px 12px; }
    .bx-btns button { flex:1; padding:9px; border:none; border-radius:10px; cursor:pointer; font-weight:700; font-size:13px; }
    .bx-not { background:#181c26; color:#8a90a6; }
    .bx-not:hover { background:#232838; }
    .bx-do { background: linear-gradient(135deg, #7c6cff, #5a47e6); color:#fff; }
    .bx-msg { padding: 0 12px 10px; font-size:12px; color:#f7b955; }
  `;
  const REGEN =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>';
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

  // Don't write into hidden/offscreen/zero-size fields (same eligibility rule as
  // the popup's injected fill) — avoids feeding credentials to a decoy field.
  function fillable(el) {
    if (!el || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05;
  }

  function fillFields(field, username, password) {
    const scope = field.form || document;
    const pw = Array.from(scope.querySelectorAll('input[type="password"]:not([disabled]):not([readonly])')).find(fillable);
    if (pw && password) setNative(pw, password);
    // username: the focused field if it's not the password, else find a visible one
    let user = field.type !== "password" && fillable(field) ? field : null;
    if (!user) {
      const cands = Array.from(scope.querySelectorAll("input")).filter(
        (i) => i.type !== "password" && ["text", "email", "tel", ""].includes((i.type || "").toLowerCase()) && fillable(i)
      );
      const hint = (i) => `${i.name} ${i.id} ${i.autocomplete}`.toLowerCase();
      user = cands.find((i) => /user|email|login|account/.test(hint(i))) || cands[0] || null;
    }
    if (user && username) setNative(user, username);
  }

  // Create the positioned shadow-DOM host anchored under `field` and return its
  // shadow root. Callers fill in the content.
  function mountOverlay(field) {
    removeOverlay();
    const rect = field.getBoundingClientRect();
    const hostEl = document.createElement("div");
    hostEl.style.position = "absolute";
    hostEl.style.zIndex = "2147483647";
    hostEl.style.left = `${window.scrollX + rect.left}px`;
    hostEl.style.top = `${window.scrollY + rect.bottom + 4}px`;
    hostEl.style.width = `${Math.max(rect.width, 240)}px`;
    const shadow = hostEl.attachShadow({ mode: "closed" }); // page JS can't read host.shadowRoot
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    shadow.adoptedStyleSheets = [sheet];
    document.documentElement.appendChild(hostEl);
    overlay = hostEl;
    return shadow;
  }

  function showOverlay(field, items) {
    const shadow = mountOverlay(field);
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

  // Suggest a generated password for a new-password field, with a regenerate
  // button. "Use password" fills this field and any sibling confirm field.
  function showGenerator(field) {
    const shadow = mountOverlay(field);
    const wrap = document.createElement("div");
    wrap.className = "bx-list";
    wrap.innerHTML = `
      <div class="bx-head">${SHIELD} Suggested password</div>
      <div class="bx-gen"><div class="bx-pw"></div><button class="bx-regen" title="Generate another">${REGEN}</button></div>
      <div class="bx-len"><span>Length: <b class="bx-lenval">20</b></span><input class="bx-range" type="range" min="8" max="64" value="20" /></div>
      <button class="bx-use">Use password</button>`;
    shadow.appendChild(wrap);

    const pwEl = shadow.querySelector(".bx-pw");
    const range = shadow.querySelector(".bx-range");
    const lenval = shadow.querySelector(".bx-lenval");
    const render = () => {
      lenval.textContent = range.value;
      pwEl.textContent = genPassword(Number(range.value));
    };
    render();

    range.addEventListener("input", render);
    shadow.querySelector(".bx-regen").addEventListener("mousedown", (e) => {
      e.preventDefault(); // keep field focus / overlay alive
      render();
    });
    shadow.querySelector(".bx-use").addEventListener("mousedown", (e) => {
      e.preventDefault();
      const pw = pwEl.textContent;
      const scope = field.form || document;
      scope
        .querySelectorAll('input[type="password"]:not([disabled]):not([readonly])')
        .forEach((p) => setNative(p, pw)); // fills password + confirm
      removeOverlay();
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
      const el = e.target;
      if (el?.tagName === "INPUT" && (el.type || "").toLowerCase() === "password" && isNewPasswordField(el)) {
        activeField = el;
        return showGenerator(el);
      }
      if (isLoginField(el)) suggest(el);
    },
    true
  );
  // Dismiss on an explicit click outside the overlay and the field — NOT on
  // focusout/scroll, which fire spuriously on scripted login pages (Microsoft,
  // Google) and made the dropdown flicker out instantly. The overlay is
  // absolutely positioned in document space, so it tracks the field on scroll.
  document.addEventListener(
    "mousedown",
    (e) => {
      if (!overlay) return;
      const path = e.composedPath ? e.composedPath() : [];
      if (path.includes(overlay) || e.target === activeField) return;
      removeOverlay();
    },
    true
  );
  document.addEventListener("keydown", (e) => e.key === "Escape" && removeOverlay(), true);

  // ── "Save to Bastion?" after a sign-up ──
  let saveEl = null;
  const removeSave = () => {
    saveEl?.remove();
    saveEl = null;
  };

  function bestUsername(scope) {
    const inputs = Array.from((scope || document).querySelectorAll("input"));
    const email = inputs.find((i) => (i.type || "").toLowerCase() === "email" && i.value);
    if (email) return email.value.trim();
    const userlike = inputs.find(
      (i) => i.value && (i.type || "").toLowerCase() !== "password" && /user|email|login|account/i.test(`${i.name} ${i.id} ${i.autocomplete}`)
    );
    return userlike ? userlike.value.trim() : "";
  }

  // When a password field was filled and the form is submitted, stage it.
  function stageFromForm(scope) {
    const pwField = (scope || document).querySelector('input[type="password"]');
    const pw = pwField && pwField.value;
    if (!pw) return;
    chrome.runtime
      .sendMessage({ type: "STAGE_SAVE", host: HOST(), url: location.origin + location.pathname, username: bestUsername(scope), password: pw })
      .catch(() => {});
  }

  // Only genuine user gestures may stage credentials: synthetic events fired
  // by page scripts (el.dispatchEvent) must not be able to push values into
  // the save pipeline behind the user's back.
  document.addEventListener("submit", (e) => e.isTrusted && stageFromForm(e.target), true);
  document.addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted) return;
      const btn = e.target.closest && e.target.closest("button, input[type=submit], [role=button]");
      if (!btn) return;
      const label = `${btn.textContent || ""} ${btn.value || ""}`;
      if (btn.type === "submit" || /next|sign\s?up|create|register|continue|submit|done|save/i.test(label)) {
        stageFromForm(btn.form || document);
      }
    },
    true
  );
  // Capture the username/email as it's typed (often a step before the password).
  document.addEventListener(
    "change",
    (e) => {
      if (!e.isTrusted) return;
      const el = e.target;
      if (el?.tagName !== "INPUT" || !el.value) return;
      const t = (el.type || "").toLowerCase();
      if (t === "email" || (t !== "password" && /user|email|login|account/i.test(`${el.name} ${el.id} ${el.autocomplete}`))) {
        chrome.runtime.sendMessage({ type: "STAGE_USER", username: el.value.trim() }).catch(() => {});
      }
    },
    true
  );

  function showSavePrompt(pending) {
    removeSave();
    const hostEl = document.createElement("div");
    hostEl.style.position = "fixed";
    hostEl.style.zIndex = "2147483647";
    hostEl.style.top = "16px";
    hostEl.style.right = "16px";
    hostEl.style.width = "300px";
    const shadow = hostEl.attachShadow({ mode: "closed" }); // page JS can't read host.shadowRoot
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    shadow.adoptedStyleSheets = [sheet];
    const wrap = document.createElement("div");
    wrap.className = "bx-list";
    wrap.innerHTML = `
      <div class="bx-head">${SHIELD} Save to Bastion?</div>
      <div class="bx-save-body">
        <div class="bx-host"><div class="bx-ico" style="background:${colorFor(pending.host)};width:24px;height:24px;border-radius:6px;font-size:12px">${esc((pending.host || "?")[0].toUpperCase())}</div>${esc(pending.host)}</div>
        <div class="bx-lbl">Username</div>
        <input class="bx-input" id="bx-user" value="${esc(pending.username || "")}" placeholder="you@example.com" />
        <div class="bx-lbl">Password · captured ✓</div>
      </div>
      <div class="bx-msg" id="bx-msg" style="display:none"></div>
      <div class="bx-btns"><button class="bx-not">Not now</button><button class="bx-do">Save</button></div>`;
    shadow.appendChild(wrap);
    document.documentElement.appendChild(hostEl);
    saveEl = hostEl;

    shadow.querySelector(".bx-not").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "CLEAR_PENDING" }).catch(() => {});
      removeSave();
    });
    shadow.querySelector(".bx-do").addEventListener("click", async () => {
      const username = shadow.querySelector("#bx-user").value.trim();
      const r = await chrome.runtime.sendMessage({ type: "SAVE_LOGIN", username, title: pending.host }).catch(() => null);
      if (r?.ok) {
        removeSave();
      } else {
        const msg = shadow.querySelector("#bx-msg");
        msg.style.display = "block";
        msg.textContent = r?.locked ? "Open the Bastion popup to unlock, then save." : r?.error || "Could not save.";
      }
    });
  }

  // On each page load, offer to save a credential staged on a previous step.
  (async () => {
    try {
      const r = await chrome.runtime.sendMessage({ type: "PENDING_SAVE", host: HOST() });
      if (r?.ok && r.pending) showSavePrompt(r.pending);
    } catch {
      /* background not ready */
    }
  })();
})();
