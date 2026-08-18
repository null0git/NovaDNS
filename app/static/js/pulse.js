// Drives the "live query pulse" strip: polls recent query log entries and
// renders them as packets drifting across a wire. This is the dashboard's
// signature element tying the loading/empty states back to what the
// product actually does (move DNS packets around).

const SOURCE_COLOR = {
  cache: "#4C8CFF", authoritative: "#34D399", forward: "#A78BFA",
  blocked: "#F0506E", rewritten: "#F5A524", maintenance: "#5B6478",
};

function renderPulseStrip(el, entries) {
  const track = el.querySelector(".pulse-track") || (() => {
    const t = document.createElement("div");
    t.className = "pulse-track";
    el.appendChild(t);
    return t;
  })();
  if (!entries.length) {
    track.innerHTML = `<span class="packet"><span class="dot" style="background:#5B6478"></span>waiting for queries…</span>`;
    return;
  }
  const doubled = entries.concat(entries); // seamless loop
  track.innerHTML = doubled.map(e => {
    const color = SOURCE_COLOR[e.source] || "#8D96AC";
    return `<span class="packet"><span class="dot" style="background:${color}"></span>${e.qname} <span style="color:var(--text-faint)">${e.qtype}</span></span>`;
  }).join("");
}

function startPulsePolling(elId, url, intervalMs = 4000) {
  const el = document.getElementById(elId);
  if (!el) return;
  const tick = () => {
    fetch(url).then(r => r.json()).then(data => renderPulseStrip(el, data.entries || []))
      .catch(() => {});
  };
  tick();
  setInterval(tick, intervalMs);
}
