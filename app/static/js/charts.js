// Minimal canvas-based charts — deliberately dependency-free so NovaDNS
// never needs a CDN or Node build step to render its own dashboard.

function drawSparkline(canvas, values, color = "#4C8CFF") {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  if (!values.length) return;
  const max = Math.max(...values, 1), min = Math.min(...values, 0);
  const range = (max - min) || 1;
  const step = w / (values.length - 1 || 1);

  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + "55");
  grad.addColorStop(1, color + "00");

  ctx.beginPath();
  values.forEach((v, i) => {
    const x = i * step, y = h - ((v - min) / range) * (h - 6) - 3;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();

  ctx.beginPath();
  values.forEach((v, i) => {
    const x = i * step, y = h - ((v - min) / range) * (h - 6) - 3;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
}

function drawDonut(canvas, segments) {
  // segments: [{value, color}]
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const total = segments.reduce((a, s) => a + s.value, 0) || 1;
  const cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - 6, lw = Math.max(8, r * 0.32);
  let start = -Math.PI / 2;
  segments.forEach(seg => {
    const angle = (seg.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r - lw / 2, start, start + angle);
    ctx.strokeStyle = seg.color; ctx.lineWidth = lw; ctx.lineCap = "butt"; ctx.stroke();
    start += angle;
  });
}

function drawBars(canvas, values, labels, color = "#4C8CFF") {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...values, 1);
  const gap = 8;
  const bw = (w - gap * (values.length - 1)) / values.length;
  values.forEach((v, i) => {
    const bh = (v / max) * (h - 18);
    const x = i * (bw + gap);
    const y = h - bh - 14;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, y, bw, bh, 3) : ctx.rect(x, y, bw, bh);
    ctx.fill();
    if (labels && labels[i]) {
      ctx.fillStyle = "#8D96AC";
      ctx.font = "10px JetBrains Mono, monospace";
      ctx.textAlign = "center";
      ctx.fillText(labels[i], x + bw / 2, h - 3);
    }
  });
}
