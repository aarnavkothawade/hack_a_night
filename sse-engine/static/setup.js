/* Setup: client-side pre-validation of credentials.json. The server validates again. */
(() => {
  "use strict";
  const { toast } = window.SSE;
  const textarea = document.getElementById("credentials-json");
  const status = document.getElementById("credentials-status");
  const fileInput = document.getElementById("credentials-file");
  const fileName = document.getElementById("credentials-file-name");
  const form = document.getElementById("setup-form");

  function check(raw) {
    let data;
    try { data = JSON.parse(raw); } catch { return "Not valid JSON yet."; }
    if (!data || typeof data !== "object" || Array.isArray(data)) return "Must be a JSON object.";
    const kinds = ["web", "installed"].filter((k) => k in data);
    if (kinds.length !== 1) return 'Needs exactly one "web" or "installed" client.';
    const client = data[kinds[0]];
    for (const key of ["client_id", "client_secret"]) {
      if (typeof client?.[key] !== "string" || !client[key].trim()) return `Missing ${key}.`;
    }
    if (!Array.isArray(client.redirect_uris) || !client.redirect_uris.length) return "Missing redirect_uris.";
    return null;
  }

  function show(message, ok) {
    status.textContent = message;
    status.dataset.state = ok ? "ok" : "error";
  }

  textarea?.addEventListener("input", () => {
    const raw = textarea.value.trim();
    if (!raw) { status.textContent = ""; delete status.dataset.state; return; }
    const problem = check(raw);
    show(problem || "Looks valid. It will be checked again on save.", !problem);
  });

  fileInput?.addEventListener("change", async () => {
    const file = fileInput.files[0];
    fileInput.closest(".file-input").dataset.hasFile = file ? "true" : "false";
    fileName.textContent = file ? file.name : "Choose file…";
    if (!file) return;
    if (file.size > 64 * 1024) { toast("credentials.json must be smaller than 64 KB.", "error", { title: "File too large" }); return; }
    const problem = check(await file.text());
    if (problem) toast(problem, "error", { title: "credentials.json looks invalid" });
    else toast("credentials.json looks valid. Save to store it.", "success", { timeout: 2500 });
  });

  form?.addEventListener("submit", (e) => {
    const raw = textarea.value.trim();
    if (raw && check(raw)) {
      e.preventDefault();
      show(check(raw), false);
      toast(check(raw), "error", { title: "Fix the pasted JSON first" });
      textarea.focus();
    }
  });
})();
