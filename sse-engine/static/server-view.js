/* Server view: client-side leak check and label expansion. Nothing typed here is sent anywhere. */
(() => {
  "use strict";
  const input = document.getElementById("leak-input");
  const out = document.getElementById("leak-result");
  const toggle = document.getElementById("labels-toggle");
  const grid = document.getElementById("label-grid");

  function pageText() {
    const clone = document.getElementById("main").cloneNode(true);
    clone.querySelectorAll("[data-leak-ignore], .leak-cols, script").forEach((n) => n.remove());
    return clone.textContent.toLowerCase();
  }

  let haystack = null;
  let timer;
  input?.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const needle = input.value.trim().toLowerCase();
      if (!needle) {
        out.textContent = "Runs only in your browser and greps this page’s text.";
        delete out.dataset.state;
        return;
      }
      haystack ??= pageText();
      let count = 0;
      for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + needle.length)) count++;
      out.dataset.state = count ? "found" : "clean";
      out.textContent = count
        ? `Found ${count} time${count === 1 ? "" : "s"} on this page. Short hex-like strings can match ciphertext by chance.`
        : "0 occurrences. The server-visible data does not contain this text.";
    }, 120);
  });

  toggle?.addEventListener("click", () => {
    const collapsed = grid.classList.toggle("is-collapsed");
    toggle.setAttribute("aria-expanded", String(!collapsed));
    toggle.textContent = collapsed ? `Show all ${grid.children.length}` : "Collapse";
  });
})();
