const state = { days: [], entries: [], day: null, sev: "all", q: "", bug: "all",
              stack: JSON.parse(localStorage.getItem("evc-stack") || "[]") };
const $ = (id) => document.getElementById(id);

async function init() {
  const days = await (await fetch("data/days.json")).json();
  state.days = days;
  const sel = $("daySelect");
  days.forEach((d) => {
    const o = document.createElement("option");
    o.value = d; o.textContent = prettyDate(d);
    sel.appendChild(o);
  });
  sel.addEventListener("change", () => loadDay(sel.value));
  $("search").addEventListener("input", (e) => { state.q = e.target.value.toLowerCase(); render(); });
  $("bugSelect").addEventListener("change", (e) => { state.bug = e.target.value; render(); });
  document.querySelectorAll("#sevPills button").forEach((b) =>
    b.addEventListener("click", () => {
      document.querySelectorAll("#sevPills button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      state.sev = b.dataset.sev;
      render();
    }));
  $("stackAdd").addEventListener("click", addStack);
  $("stackInput").addEventListener("keydown", (e) => { if (e.key === "Enter") addStack(); });
  $("modalClose").addEventListener("click", closeModal);
  $("modalBackdrop").addEventListener("click", (e) => { if (e.target.id === "modalBackdrop") closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  if (days.length) loadDay(days[0]);
}

function prettyDate(d) {
  const [y, m, day] = d.split("-").map(Number);
  return new Date(y, m - 1, day).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
}

async function loadDay(day) {
  state.day = day;
  showSkeletons();
  state.entries = await (await fetch(`data/${day}.json`)).json();
  buildBugOptions();
  countUp($("stTotal"), state.entries.length);
  countUp($("stCrit"), state.entries.filter((e) => e.severity === "CRITICAL").length);
  countUp($("stKev"), state.entries.filter((e) => e.exploited).length);
  render();
}

function buildBugOptions() {
  const sel = $("bugSelect");
  const cur = state.bug;
  sel.innerHTML = `<option value="all">All bug classes</option>`;
  [...new Set(state.entries.map((e) => e.bug_class).filter(Boolean))].sort()
    .forEach((b) => {
      const o = document.createElement("option");
      o.value = b; o.textContent = b;
      sel.appendChild(o);
    });
  sel.value = [...sel.options].some((o) => o.value === cur) ? cur : "all";
  state.bug = sel.value;
}

function countUp(el, n) {
  const t0 = performance.now(), dur = 700;
  function tick(t) {
    const p = Math.min(1, (t - t0) / dur);
    el.textContent = Math.round(n * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function showSkeletons() {
  const sec = $("sections");
  sec.innerHTML = `<div class="grid">${"<div class='skel'></div>".repeat(8)}</div>`;
  $("empty").classList.add("hidden");
  $("featuredWrap").classList.add("hidden");
  $("resultline").textContent = "Loading…";
}

function priority(e) {
  const s = typeof e.score === "number" ? e.score : 0;
  return [(e.exploited ? 0 : 1), (e.severity === "CRITICAL" ? 0 : e.severity === "HIGH" ? 1 : 2), -s];
}
function cmpPrio(a, b) {
  const pa = priority(a), pb = priority(b);
  for (let i = 0; i < pa.length; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

function filtered() {
  return state.entries.filter((e) => {
    if (state.sev === "exploited" && !e.exploited) return false;
    if (state.sev === "stack" && !stackHit(e)) return false;
    if (state.sev !== "all" && state.sev !== "exploited" && state.sev !== "stack" && e.severity !== state.sev) return false;
    if (state.bug !== "all" && e.bug_class !== state.bug) return false;
    if (state.q) {
      const hay = `${e.id} ${e.vendor} ${e.product} ${e.bug_class} ${e.problem} ${e.solution}`.toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  }).sort(cmpPrio);
}

function stackHit(e) {
  if (!state.stack.length) return false;
  const hay = `${e.vendor} ${e.product}`.toLowerCase();
  return state.stack.some((k) => hay.includes(k));
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

/* ---------- my stack ---------- */
function saveStack() { localStorage.setItem("evc-stack", JSON.stringify(state.stack)); }
function addStack() {
  const v = $("stackInput").value.trim().toLowerCase();
  if (v && !state.stack.includes(v)) { state.stack.push(v); saveStack(); }
  $("stackInput").value = "";
  renderStack(); render();
}
function renderStack() {
  const box = $("stackChips");
  box.innerHTML = "";
  state.stack.forEach((k) => {
    const c = document.createElement("span");
    c.className = "stack-chip";
    c.innerHTML = `${esc(k)} <button aria-label="Remove ${esc(k)}">✕</button>`;
    c.querySelector("button").addEventListener("click", () => {
      state.stack = state.stack.filter((x) => x !== k);
      saveStack(); renderStack(); render();
    });
    box.appendChild(c);
  });
  const hits = state.entries.filter(stackHit).length;
  const pill = document.querySelector('#sevPills [data-sev="stack"]');
  if (pill) pill.innerHTML = `My stack${hits ? ` <span class="n">${hits}</span>` : ""}`;
}

/* ---------- tiles ---------- */
function tile(e, i) {
  const t = document.createElement("button");
  const hit = stackHit(e);
  t.className = `tile sev-${esc(e.severity)}${hit ? " stack-hit" : ""}`;
  t.style.animationDelay = `${Math.min(i, 24) * 28}ms`;
  t.setAttribute("aria-label", `${e.id} details`);
  t.innerHTML = `
    ${hit ? `<span class="stack-ribbon">In your stack</span>` : ""}
    <span class="tile-top">
      <span class="sevbadge ${esc(e.severity)}">${esc(e.severity)}</span>
      <span class="score ${esc(e.severity)}">${esc(e.score)}</span>
    </span>
    <span class="cve-id">${esc(e.id)}</span>
    ${e.vendor ? `<span class="vendor">${esc(e.vendor)}</span>` : ""}
    <span class="product">${esc(e.product || "Product pending NVD analysis")}${e.versions ? ` <span class="ver">${esc(e.versions)}</span>` : ""}</span>
    <span class="tile-foot">
      ${e.exploited ? `<span class="minichip kevflag">Exploited</span>` : (e.bug_class ? `<span class="minichip">${esc(e.bug_class)}</span>` : `<span></span>`)}
      <span class="details-link">Details →</span>
    </span>`;
  t.addEventListener("click", () => openModal(e));
  return t;
}

function render() {
  renderStack();
  const list = filtered();
  $("empty").classList.toggle("hidden", list.length > 0);
  $("resultline").textContent =
    list.length === state.entries.length
      ? `${state.entries.length} vulnerabilities published ${prettyDate(state.day)} — tap any card for the full breakdown`
      : `Showing ${list.length} of ${state.entries.length}`;

  // featured: top 3 by priority
  const feat = $("featured"), fwrap = $("featuredWrap");
  const top = list.slice(0, 3);
  if (top.length && state.sev === "all" && !state.q && state.bug === "all") {
    fwrap.classList.remove("hidden");
    feat.innerHTML = "";
    top.forEach((e, i) => {
      const f = document.createElement("button");
      f.className = `feat sev-${esc(e.severity)}${stackHit(e) ? " stack-hit" : ""}`;
      f.style.animationDelay = `${i * 90}ms`;
      f.innerHTML = `
        <span class="feat-sev"><span class="sevbadge ${esc(e.severity)}">${esc(e.severity)}</span><span class="score ${esc(e.severity)}">${esc(e.score)}</span></span>
        <span class="feat-main">
          <span class="cve-id">${esc(e.id)}</span>
          <span class="feat-vp">${esc([e.vendor, e.product].filter(Boolean).join(" · ") || "Pending NVD analysis")}${e.fixed_in ? ` <span class="ver">· fixed in ${esc(e.fixed_in)}</span>` : ""}</span>
          <span class="feat-why">${esc(e.problem.slice(0, 140))}…</span>
          <span class="chips">${e.exploited ? `<span class="chip kevflag">Exploited in the wild</span>` : ""}${e.bug_class ? `<span class="chip">${esc(e.bug_class)}</span>` : ""}${stackHit(e) ? `<span class="chip">In your stack</span>` : ""}</span>
        </span>`;
      f.addEventListener("click", () => openModal(e));
      feat.appendChild(f);
    });
  } else {
    fwrap.classList.add("hidden");
  }

  // grouped sections
  const sec = $("sections");
  sec.innerHTML = "";
  const groups = [
    ["Exploited in the wild", list.filter((e) => e.exploited), "kev"],
    ["Critical", list.filter((e) => !e.exploited && e.severity === "CRITICAL"), "crit"],
    ["High & medium", list.filter((e) => !e.exploited && e.severity !== "CRITICAL"), ""],
  ];
  let n = 0;
  groups.forEach(([label, items, cls]) => {
    if (!items.length) return;
    const h = document.createElement("h2");
    h.className = `sechead ${cls}`;
    h.innerHTML = `${esc(label)} <span class="count">${items.length}</span>`;
    sec.appendChild(h);
    const g = document.createElement("div");
    g.className = "grid";
    items.forEach((e) => g.appendChild(tile(e, n++)));
    sec.appendChild(g);
  });
}

/* ---------- modal ---------- */
function openModal(e) {
  const hit = stackHit(e);
  const body = $("modalBody");
  body.innerHTML = `
    <div class="m-head">
      <span class="m-sev ${esc(e.severity)}">${esc(e.severity)}</span>
      <span class="m-score">${esc(e.score)}</span>
      <span class="m-cve">${esc(e.id)}</span>
      ${e.exploited ? `<span class="m-kev">Exploited in the wild</span>` : ""}
      ${hit ? `<span class="m-kev" style="background:rgba(45,212,191,.14);color:var(--teal);border-color:rgba(45,212,191,.4)">In your stack</span>` : ""}
    </div>
    <div class="dgrid">
      <div class="dblock"><div class="k">Vendor</div><div class="v">${esc(e.vendor || "Pending NVD analysis")}</div></div>
      <div class="dblock"><div class="k">Product</div><div class="v">${esc(e.product || "Pending NVD analysis")}</div></div>
      <div class="dblock"><div class="k">Affected versions</div><div class="v mono">${esc(e.versions || "—")}</div></div>
      <div class="dblock"><div class="k">Fixed in</div><div class="v mono">${esc(e.fixed_in || "—")}</div></div>
      <div class="dblock"><div class="k">Published</div><div class="v mono">${esc(e.date || "—")}</div></div>
      ${e.bug_class ? `<div class="dblock"><div class="k">Bug class</div><div class="v">${esc(e.bug_class)}</div></div>` : ""}
    </div>
    <div class="dsection problem"><div class="k">The problem</div><p>${esc(e.problem)}</p></div>
    ${e.attack && e.attack.length ? `<div class="dsection attack"><div class="k">Attack profile</div><div class="atkchips">${e.attack.map((a) => `<span>${esc(a)}</span>`).join("")}</div></div>` : ""}
    <div class="dsection solution"><div class="k">The solution</div><p>${esc(e.solution)}</p></div>
    <div class="refbtns">
      ${e.patch ? `<a href="${esc(e.patch)}" target="_blank" rel="noopener">Vendor patch / advisory</a>` : ""}
      <a class="ghost" href="${esc(e.nvd)}" target="_blank" rel="noopener">NVD details</a>
      ${e.exploit_public ? `<a class="ghost" href="https://www.google.com/search?q=${esc(e.id)}+exploit" target="_blank" rel="noopener">Public exploit info</a>` : ""}
    </div>`;
  $("modalBackdrop").classList.remove("hidden");
  document.body.classList.add("modal-open");
}

function closeModal() {
  $("modalBackdrop").classList.add("hidden");
  document.body.classList.remove("modal-open");
}

init();
