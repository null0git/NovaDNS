// NovaDNS shared front-end utilities (vanilla JS, no framework/build step).

const Nova = (() => {
  function toast(message, type = "success") {
    let stack = document.querySelector(".toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "toast-stack";
      document.body.appendChild(stack);
    }
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = message;
    stack.appendChild(el);
    setTimeout(() => {
      el.style.transition = "opacity .2s ease";
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 200);
    }, 3200);
  }

  async function api(url, options = {}) {
    const opts = Object.assign({ headers: { "Content-Type": "application/json" } }, options);
    if (opts.body && typeof opts.body !== "string") opts.body = JSON.stringify(opts.body);
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      toast((data && data.error) || `Request failed (${res.status})`, "error");
      throw new Error((data && data.error) || res.status);
    }
    return data;
  }

  function openModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.add("open");
  }
  function closeModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.remove("open");
  }

  function skeletonRows(container, count = 5, cols = 4) {
    container.innerHTML = "";
    for (let i = 0; i < count; i++) {
      const tr = document.createElement("tr");
      for (let c = 0; c < cols; c++) {
        const td = document.createElement("td");
        const div = document.createElement("div");
        div.className = "skel skel-row";
        div.style.width = `${50 + Math.random() * 40}%`;
        td.appendChild(div);
        tr.appendChild(td);
      }
      container.appendChild(tr);
    }
  }

  function confirmDanger(message) {
    return window.confirm(message);
  }

  function initTheme() {
    const stored = localStorage.getItem("novadns-theme") || "system";
    applyTheme(stored);
  }
  function applyTheme(mode) {
    localStorage.setItem("novadns-theme", mode);
    let effective = mode;
    if (mode === "system") {
      effective = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.setAttribute("data-theme", effective);
    document.querySelectorAll("[data-theme-option]").forEach(b => {
      b.classList.toggle("active", b.dataset.themeOption === mode);
    });
  }

  function initSidebar() {
    const btn = document.getElementById("sidebar-toggle");
    const sidebar = document.querySelector(".sidebar");
    if (btn && sidebar) btn.addEventListener("click", () => sidebar.classList.toggle("open"));
  }

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => (btn.textContent = orig), 1200);
      }
      toast("Copied to clipboard");
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initSidebar();
    document.querySelectorAll("[data-theme-option]").forEach(b => {
      b.addEventListener("click", () => applyTheme(b.dataset.themeOption));
    });
    document.querySelectorAll("[data-close-modal]").forEach(b => {
      b.addEventListener("click", () => closeModal(b.dataset.closeModal));
    });
    document.querySelectorAll("[data-copy]").forEach(b => {
      b.addEventListener("click", () => copyText(b.dataset.copy, b));
    });
  });

  return { toast, api, openModal, closeModal, skeletonRows, confirmDanger, copyText, applyTheme };
})();
