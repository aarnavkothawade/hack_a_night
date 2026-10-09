/* Dashboard: encrypted preview, upload, boolean search, verify, decrypt-on-request. */
(() => {
  "use strict";
  const { api, toast, reportError, h, fmtBytes, fmtDate, reduceMotion } = window.SSE;
  const $ = (sel, root = document) => root.querySelector(sel);

  const iconTpl = $("#tpl-icons");
  const icon = (name) => iconTpl.content.querySelector(`[data-icon="${name}"] svg`).cloneNode(true);

  const setBusy = (btn, busy) => {
    if (!btn) return;
    btn.setAttribute("aria-busy", busy ? "true" : "false");
    btn.disabled = !!busy;
  };

  /* Encrypt & upload ----------------------------------------------------- */
  const form = $("#upload-form");
  const fileInput = $("#file-input");
  const dropzone = $("#dropzone");
  const preview = $("#preview");
  const commitBtn = $("#commit-btn");
  const MAX_BYTES = 5 * 1024 * 1024;

  let current = null; // { file, staging_id, doc_id, ... }
  let stageSeq = 0;

  function showPreview() {
    if (!preview.hidden) return;
    preview.hidden = false;
    preview.dataset.state = "entering";
    requestAnimationFrame(() => requestAnimationFrame(() => delete preview.dataset.state));
  }

  function hidePreview() {
    preview.hidden = true;
    delete preview.dataset.state;
  }

  /* Ciphertext "settles" from random hex into the real value. Rare event, so a little delight is fine. */
  function revealHex(el, value) {
    if (reduceMotion.matches) { el.textContent = value; return; }
    const hex = "0123456789abcdef";
    const start = performance.now();
    const duration = 420;
    const frame = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const settled = Math.floor((1 - Math.pow(1 - t, 3)) * value.length);
      let out = value.slice(0, settled);
      for (let i = settled; i < value.length; i++) out += hex[(Math.random() * 16) | 0];
      el.textContent = out;
      if (t < 1) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }

  function renderPreview(file, data) {
    $("#preview-filename").textContent = file.name;
    const set = (key, value) => { const el = preview.querySelector(`[data-field="${key}"]`); if (el) el.textContent = value; };
    set("doc_id", data.doc_id);
    set("blob_size", data.blob_size.toLocaleString());
    set("nonce_hex", data.nonce_hex);
    set("tag_hex", data.tag_hex);
    set("keyword_count", data.keyword_count.toLocaleString());
    set("kind_label", data.kind === "pdf"
      ? `PDF, ${data.pages} page${data.pages === 1 ? "" : "s"}. The original file is encrypted; its text is indexed.`
      : "Text");
    set("blind_fields", data.blind_fields.length ? `+ blind index: ${data.blind_fields.join(", ")}` : "");
    showPreview();
    delete preview.dataset.state;
    revealHex(preview.querySelector('[data-field="ciphertext_head"]'), data.ciphertext_head);
  }

  async function stage(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      toast("The file is larger than 5 MB.", "error", { title: "File too large" });
      return;
    }
    if (file.size === 0) {
      toast("The file is empty.", "error", { title: "Nothing to encrypt" });
      return;
    }
    const seq = ++stageSeq;
    const previous = current?.staging_id;
    const fd = new FormData();
    fd.append("file", file);
    fd.append("department", form.elements.department.value);
    fd.append("classification", form.elements.classification.value);
    if (!preview.hidden) preview.dataset.state = "busy";
    try {
      const data = await api("/preview", { method: "POST", form: fd });
      if (seq !== stageSeq) return; // a newer selection won
      current = { file, ...data };
      renderPreview(file, data);
      if (previous) discardRemote(previous);
    } catch (err) {
      if (seq !== stageSeq) return;
      delete preview.dataset.state;
      reportError(err, "Encryption failed");
      if (!current) resetUpload();
    }
  }

  function discardRemote(stagingId) {
    api("/preview/discard", { method: "POST", json: { staging_id: stagingId } }).catch((err) =>
      reportError(err, "Could not discard the old preview"),
    );
  }

  function resetUpload() {
    stageSeq++;
    current = null;
    fileInput.value = "";
    hidePreview();
  }

  fileInput.addEventListener("change", () => stage(fileInput.files[0]));

  ["dragenter", "dragover"].forEach((type) =>
    dropzone.addEventListener(type, (e) => { e.preventDefault(); dropzone.dataset.drag = "true"; }),
  );
  ["dragleave", "dragend"].forEach((type) =>
    dropzone.addEventListener(type, (e) => {
      if (type === "dragleave" && dropzone.contains(e.relatedTarget)) return;
      delete dropzone.dataset.drag;
    }),
  );
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    delete dropzone.dataset.drag;
    const file = e.dataTransfer?.files?.[0];
    if (file) stage(file);
  });
  // Dropping a file anywhere else must not navigate away from the portal.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  let fieldTimer;
  form.addEventListener("input", (e) => {
    if (e.target === fileInput || !current) return;
    clearTimeout(fieldTimer);
    fieldTimer = setTimeout(() => stage(current.file), 350); // re-encrypt metadata with the new fields
  });
  form.addEventListener("submit", (e) => e.preventDefault());

  $("#discard-btn").addEventListener("click", () => {
    if (current) discardRemote(current.staging_id);
    resetUpload();
    toast("Preview discarded. Nothing was stored.", "info", { timeout: 2500 });
  });

  commitBtn?.addEventListener("click", async () => {
    if (!current) return;
    setBusy(commitBtn, true);
    try {
      const result = await api("/upload", { method: "POST", json: { staging_id: current.staging_id } });
      const where = result.provider === "drive" ? "Google Drive" : "local storage";
      toast(`Document ${result.doc_id.slice(0, 8)}… is in ${where}, with ${result.postings_added} index postings.`, "success", {
        title: "Encrypted and stored",
      });
      addDocRow(result);
      bumpStats(result);
      resetUpload();
    } catch (err) {
      if (err.status === 410 && current) {
        toast("The preview expired, so the file was encrypted again. Review it and save.", "info", { title: "Preview refreshed" });
        stage(current.file);
      } else {
        reportError(err, "Upload failed");
      }
    } finally {
      setBusy(commitBtn, false);
    }
  });

  /* Vault table ---------------------------------------------------------- */
  const docsBody = $("#docs-table tbody");

  function addDocRow(doc) {
    $("#docs-empty").hidden = true;
    const tr = h(
      "tr",
      { dataset: { doc: doc.doc_id, state: "new" } },
      h("td", {}, h("span", { class: "mono id" }, doc.doc_id)),
      h("td", { class: "hide-sm" }, h("span", { class: "provider" }, icon(doc.provider === "drive" ? "cloud" : "folder"), doc.provider === "drive" ? "Drive" : "Local")),
      h("td", { class: "num" }, fmtBytes(doc.blob_size)),
      h("td", { class: "hide-sm" }, h("time", { datetime: new Date().toISOString(), title: "just now" }, "Just now")),
      h("td", { class: "right" }, verifyButton(doc.doc_id)),
    );
    docsBody.prepend(tr);
  }

  function verifyButton(docId) {
    return h("button", { type: "button", class: "btn btn-ghost btn-sm", dataset: { verify: docId } }, icon("shield"), h("span", {}, "Verify"));
  }

  function bumpStats(result) {
    const add = (id, n) => { const el = $(id); el.textContent = (parseInt(el.textContent.replace(/\D/g, ""), 10) + n).toLocaleString(); };
    add("#stat-documents", 1);
    add("#stat-postings", result.postings_added);
    const bytes = $("#stat-bytes");
    bytes.dataset.bytes = String(Number(bytes.dataset.bytes) + result.blob_size);
    bytes.textContent = fmtBytes(Number(bytes.dataset.bytes));
  }

  /* Verification --------------------------------------------------------- */
  function renderChecks(report) {
    const pass = report.status === "pass";
    return h(
      "div",
      { class: "verify-panel" },
      h(
        "div",
        { class: "verify-head" },
        h("span", { class: `badge ${pass ? "badge-sealed" : "badge-danger"}` }, icon(pass ? "check" : "x"), pass ? "Pass" : "Fail"),
        pass ? "Ciphertext, metadata and index entries all verify." : "One or more integrity checks failed.",
      ),
      h(
        "ul",
        { class: "checks" },
        report.checks.map((c) =>
          h(
            "li",
            { class: "check", dataset: { ok: String(c.ok) } },
            icon(c.ok ? "check" : "x"),
            h("div", {}, h("span", { class: "check-name" }, c.name), " ", h("span", { class: "check-detail" }, c.detail)),
          ),
        ),
      ),
    );
  }

  async function verify(docId, btn) {
    setBusy(btn, true);
    try {
      const report = await api(`/verify/${encodeURIComponent(docId)}`);
      if (report.status !== "pass") toast(`Document ${docId.slice(0, 8)}… failed verification.`, "error", { title: "Integrity failure" });
      return renderChecks(report);
    } catch (err) {
      reportError(err, "Verification failed");
      return null;
    } finally {
      setBusy(btn, false);
    }
  }

  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-verify]");
    if (!btn) return;
    const docId = btn.dataset.verify;
    const row = btn.closest("tr");
    if (row) {
      const existing = row.nextElementSibling?.classList.contains("verify-row") ? row.nextElementSibling : null;
      if (existing) { existing.remove(); return; }
      const panel = await verify(docId, btn);
      if (panel) row.after(h("tr", { class: "verify-row" }, h("td", { colspan: "5" }, panel)));
      return;
    }
    const result = btn.closest(".result");
    if (result) {
      result.querySelector(".verify-panel")?.remove();
      const panel = await verify(docId, btn);
      if (panel) { openBody(result).prepend(panel); }
    }
  });

  /* Search --------------------------------------------------------------- */
  const searchForm = $("#search-form");
  const q = $("#q");
  const statusEl = $("#search-status");
  const results = $("#results");
  const emptyEl = $("#search-empty");
  const searchBtn = searchForm.querySelector('button[type="submit"]');
  let lastQuery = "";

  const OPERATORS = new Set(["and", "or", "not"]);
  function highlightTerms(query) {
    return query
      .split(/[\s()]+/)
      .filter((t) => t && !t.includes(":") && !OPERATORS.has(t.toLowerCase()))
      .flatMap((t) => t.toLowerCase().replace(/['’`]/g, "").split(/[^\p{L}\p{N}]+/u))
      .filter((t) => t.length > 0);
  }

  function renderPlaintext(text, terms) {
    const pre = h("pre", { class: "plaintext", tabindex: "0" });
    if (!terms.length) { pre.textContent = text; return pre; }
    const escaped = terms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    const re = new RegExp(`(?<![\\p{L}\\p{N}])(${escaped.join("|")})(?![\\p{L}\\p{N}])`, "giu");
    let last = 0;
    for (const m of text.matchAll(re)) {
      pre.append(document.createTextNode(text.slice(last, m.index)), h("mark", {}, m[0]));
      last = m.index + m[0].length;
    }
    pre.append(document.createTextNode(text.slice(last)));
    return pre;
  }

  function openBody(result) {
    let body = result.querySelector(".result-body");
    if (!body) { body = h("div", { class: "result-body" }); result.append(body); }
    result.dataset.open = "true";
    return body;
  }

  function closePlaintext(result) {
    result.querySelector(".plain-wrap")?.remove(); // remove, not just hide: plaintext leaves the DOM
    const body = result.querySelector(".result-body");
    if (body && !body.children.length) { body.remove(); delete result.dataset.open; }
    const btn = result.querySelector("[data-decrypt]");
    btn.replaceChildren(icon("unlock"), h("span", {}, "Decrypt"));
  }

  function showPlaintext(result, doc) {
    const body = openBody(result);
    result.querySelector(".plain-wrap")?.remove();
    if (!doc.ok) {
      body.append(h("div", { class: "plain-wrap callout callout-danger" }, icon("alert"), h("p", {}, doc.error)));
      return;
    }
    const badges = Object.entries(doc.fields || {}).map(([k, v]) => h("span", { class: "badge badge-neutral" }, `${k}: ${v}`));
    body.append(
      h(
        "div",
        { class: "plain-wrap stack" },
        h(
          "div",
          { class: "result-title" },
          icon("file"),
          h("span", {}, doc.filename),
          doc.kind === "pdf" ? h("span", { class: "badge badge-sealed" }, `PDF · ${doc.pages} page${doc.pages === 1 ? "" : "s"}`) : null,
          ...badges,
          doc.truncated ? h("span", { class: "badge badge-warn" }, "truncated") : null,
          h("a", { class: "btn btn-ghost btn-sm download-link", href: `/documents/${encodeURIComponent(result.dataset.doc)}/download` },
            icon("download"), h("span", {}, doc.kind === "pdf" ? "Download PDF" : "Download")),
        ),
        doc.kind === "pdf" ? h("p", { class: "muted small" }, "Text extracted from the PDF. Download to see the original layout.") : null,
        renderPlaintext(doc.text, highlightTerms(lastQuery)),
      ),
    );
    result.querySelector("[data-decrypt]").replaceChildren(icon("eye-off"), h("span", {}, "Hide plaintext"));
  }

  async function decrypt(ids, btn) {
    setBusy(btn, true);
    try {
      const param = ids === "all" ? "1" : ids.join(",");
      const data = await api(`/search?q=${encodeURIComponent(lastQuery)}&decrypt=${param}`);
      const decrypted = data.decrypted || {};
      for (const [docId, doc] of Object.entries(decrypted)) {
        const result = results.querySelector(`.result[data-doc="${docId}"]`);
        if (result) showPlaintext(result, doc);
      }
      const failed = Object.values(decrypted).filter((d) => !d.ok).length;
      if (failed) toast(`${failed} document(s) failed their integrity check.`, "error", { title: "Decryption refused" });
    } catch (err) {
      reportError(err, "Decryption failed");
    } finally {
      setBusy(btn, false);
    }
  }

  function renderStatus(data) {
    const verified = data.verified
      ? h("span", { class: "badge badge-sealed" }, icon("check"), "Verified complete")
      : h("span", { class: "badge badge-danger" }, icon("alert"),
          `Incomplete: ${data.problems.missing_postings} missing, ${data.problems.tampered_postings} tampered`);
    const lookups = [`${data.keyword_lookups} trapdoor scan${data.keyword_lookups === 1 ? "" : "s"}`, `${data.labels_read} labels read`];
    if (data.field_lookups) lookups.push(`${data.field_lookups} blind-index lookup${data.field_lookups === 1 ? "" : "s"}`);
    const decryptAll = data.count
      ? h("button", { type: "button", class: "btn btn-ghost btn-sm", id: "decrypt-all" }, icon("unlock"), h("span", {}, "Decrypt all"))
      : null;
    statusEl.replaceChildren(
      h("span", { class: "count" }, data.count === 0 ? "No matches" : `${data.count} match${data.count === 1 ? "" : "es"}`),
      verified,
      h("span", { class: "leak", title: "What the index host observes for this query" }, icon("eye-off"), `Server saw: ${lookups.join(" · ")}`),
      h("span", { class: "spacer" }),
      decryptAll,
    );
    statusEl.hidden = false;
    decryptAll?.addEventListener("click", () => decrypt("all", decryptAll));
  }

  function renderResults(data) {
    renderStatus(data);
    emptyEl.hidden = data.count > 0;
    if (data.count === 0) {
      emptyEl.querySelector("p strong").textContent = "No documents match.";
      emptyEl.querySelector("p.muted").textContent = "Words are normalized: lowercase, punctuation removed, and stopwords such as “the” and “of” are not indexed.";
    }
    const items = data.results.map((r, i) => {
      const decryptBtn = h("button", { type: "button", class: "btn btn-ghost btn-sm", dataset: { decrypt: r.doc_id } }, icon("unlock"), h("span", {}, "Decrypt"));
      const li = h(
        "li",
        { class: "result", dataset: { doc: r.doc_id, state: "entering" } },
        h(
          "div",
          { class: "result-row" },
          h(
            "div",
            { class: "result-id" },
            h("span", { class: "mono", title: r.doc_id }, r.doc_id),
            h("span", { class: "result-meta" }, icon(r.provider === "drive" ? "cloud" : "folder"), `${fmtBytes(r.blob_size)} · ${fmtDate(r.uploaded_at)}`),
          ),
          h("div", { class: "result-actions" }, verifyButton(r.doc_id), decryptBtn),
        ),
      );
      decryptBtn.addEventListener("click", () => (li.querySelector(".plain-wrap") ? closePlaintext(li) : decrypt([r.doc_id], decryptBtn)));
      const delay = reduceMotion.matches ? 0 : Math.min(i, 8) * 35;
      setTimeout(() => requestAnimationFrame(() => delete li.dataset.state), delay);
      return li;
    });
    results.replaceChildren(...items);
  }

  searchForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const query = q.value.trim();
    if (!query) {
      toast("Type a keyword or a boolean query such as merger AND NOT draft.", "info", { title: "Empty query" });
      q.focus();
      return;
    }
    setBusy(searchBtn, true);
    try {
      const data = await api(`/search?q=${encodeURIComponent(query)}`);
      lastQuery = query;
      renderResults(data);
    } catch (err) {
      reportError(err, "Search failed");
    } finally {
      setBusy(searchBtn, false);
    }
  });

  searchForm.querySelectorAll("[data-insert]").forEach((chip) =>
    chip.addEventListener("click", () => {
      const token = chip.dataset.insert;
      const start = q.selectionStart ?? q.value.length;
      const end = q.selectionEnd ?? q.value.length;
      const before = q.value.slice(0, start);
      const after = q.value.slice(end);
      const pad = before && !/\s$/.test(before) ? " " : "";
      let insert = token === "( )" ? "()" : token.endsWith(":") ? token : `${token} `;
      q.value = before + pad + insert + after;
      const caret = before.length + pad.length + (token === "( )" ? 1 : insert.length);
      q.focus();
      q.setSelectionRange(caret, caret);
    }),
  );
})();
