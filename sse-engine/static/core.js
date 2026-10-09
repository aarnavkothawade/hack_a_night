/* Shared UI helpers: API calls, toasts, global error reporting.
 * Plaintext is only ever written with textContent, never innerHTML. */
(() => {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const toaster = document.getElementById("toaster");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const ICON_PATHS = {
    success: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    error: '<path d="M12 9.5v3.5M12 16.5h.01"/><path d="M10.3 4.2 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z"/>',
    info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
    close: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  };

  function svg(name) {
    const ns = "http://www.w3.org/2000/svg";
    const el = document.createElementNS(ns, "svg");
    el.setAttribute("viewBox", "0 0 24 24");
    el.setAttribute("class", "icon");
    el.setAttribute("fill", "none");
    el.setAttribute("stroke", "currentColor");
    el.setAttribute("stroke-width", "1.75");
    el.setAttribute("stroke-linecap", "round");
    el.setAttribute("stroke-linejoin", "round");
    el.setAttribute("aria-hidden", "true");
    el.innerHTML = ICON_PATHS[name]; // static, trusted markup
    return el;
  }

  /** Build an element: h("div", {class: "x"}, "text", child) */
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  /* Toasts ---------------------------------------------------------------- */
  function toast(message, kind = "info", { title, timeout } = {}) {
    if (!toaster) return;
    const ms = timeout ?? (kind === "error" ? 9000 : 4500);
    const close = h("button", { type: "button", class: "icon-btn", "aria-label": "Dismiss" }, svg("close"));
    const node = h(
      "div",
      { class: `toast toast-${kind}`, role: kind === "error" ? "alert" : "status", dataset: { state: "entering" } },
      svg(kind === "error" ? "error" : kind === "success" ? "success" : "info"),
      h("div", {}, title ? h("div", { class: "toast-title" }, title) : null, h("div", { class: "toast-msg" }, message)),
      close,
    );
    toaster.append(node);
    while (toaster.children.length > 4) toaster.firstElementChild.remove();
    requestAnimationFrame(() => requestAnimationFrame(() => delete node.dataset.state));

    let remaining = ms;
    let started = Date.now();
    let timer = setTimeout(dismiss, remaining);
    const pause = () => { clearTimeout(timer); remaining -= Date.now() - started; };
    const resume = () => { started = Date.now(); clearTimeout(timer); timer = setTimeout(dismiss, Math.max(remaining, 1200)); };
    node.addEventListener("mouseenter", pause);
    node.addEventListener("mouseleave", resume);
    const onVisibility = () => (document.hidden ? pause() : resume());
    document.addEventListener("visibilitychange", onVisibility);
    close.addEventListener("click", dismiss);

    function dismiss() {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      if (!node.isConnected) return;
      node.dataset.state = "leaving";
      setTimeout(() => node.remove(), reduceMotion.matches ? 0 : 170);
    }
    return dismiss;
  }

  /* API ------------------------------------------------------------------- */
  class ApiError extends Error {
    constructor(message, status) { super(message); this.name = "ApiError"; this.status = status; }
  }

  async function api(url, { method = "GET", json, form } = {}) {
    const headers = { Accept: "application/json" };
    let body;
    if (method !== "GET") headers["X-CSRF-Token"] = csrf;
    if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
    if (form !== undefined) body = form;
    let res;
    try {
      res = await fetch(url, { method, headers, body, credentials: "same-origin" });
    } catch {
      throw new ApiError("Could not reach the portal. Is the server still running?", 0);
    }
    let data = null;
    if ((res.headers.get("content-type") || "").includes("application/json")) {
      data = await res.json().catch(() => null);
    }
    if (!res.ok) throw new ApiError(data?.error || `Request failed with HTTP ${res.status}.`, res.status);
    if (data === null) throw new ApiError("The portal returned an unexpected response.", res.status);
    return data;
  }

  function reportError(err, title = "Request failed") {
    const message = err instanceof Error ? err.message : String(err);
    toast(message, "error", { title });
  }

  /* Global error reporting: nothing fails silently ------------------------- */
  window.addEventListener("error", (event) => {
    toast(event.message || "Unknown script error", "error", { title: "JavaScript error" });
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason;
    toast(reason?.message || String(reason), "error", { title: reason instanceof ApiError ? "Request failed" : "Unexpected error" });
  });

  /* Formatting ------------------------------------------------------------- */
  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }
  const dateFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  function fmtDate(iso) {
    const d = new Date(iso);
    return Number.isNaN(d.valueOf()) ? iso : dateFmt.format(d);
  }
  function localizeTimes(root = document) {
    root.querySelectorAll("time[datetime]").forEach((t) => {
      t.textContent = fmtDate(t.getAttribute("datetime"));
      t.title = t.getAttribute("datetime");
    });
  }

  /* Small behaviours available on every page ------------------------------- */
  document.addEventListener("click", async (event) => {
    const copyBtn = event.target.closest("[data-copy]");
    if (copyBtn) {
      const target = document.querySelector(copyBtn.dataset.copy);
      const text = copyBtn.dataset.copyText || target?.textContent?.trim() || "";
      try {
        await navigator.clipboard.writeText(text);
        toast("Copied to clipboard.", "success", { timeout: 1800 });
      } catch {
        toast("Clipboard access was blocked by the browser.", "error", { title: "Copy failed" });
      }
    }
    const revealBtn = event.target.closest("[data-reveal]");
    if (revealBtn) {
      const input = document.querySelector(revealBtn.dataset.reveal);
      if (input) {
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        revealBtn.setAttribute("aria-label", show ? "Hide key" : "Show key");
      }
    }
  });

  document.addEventListener("DOMContentLoaded", () => localizeTimes());

  window.SSE = { api, toast, reportError, h, fmtBytes, fmtDate, localizeTimes, ApiError, reduceMotion };
})();
