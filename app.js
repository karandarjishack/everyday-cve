const state = { days: [], entries: [], day: null, sev: "all", q: "" };
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
  document.querySelectorAll("#sevPills button").forEach((b) =>
    b.addEventListener("click", () => {
      document.querySelectorAll("#sevPills button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      state.sev = b.dataset.sev;
      render();
    }));
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
  state.entries = await (await fetch(`data/${day}.json`)).json();
  countUp($("stTotal"), state.entries.length);
  countUp($("stCrit"), state.entries.filter((e) => e.severity === "CRITICAL").length);
  countUp($("stKev"), state.entries.filter((e) => e.exploited).length);
  render();
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

function filtered() {
  return state.entries.filter((e) => {
    if (state.sev === "exploited" && !e.exploited) return false;
    if (state.sev !== "all" && state.sev !== "exploited" && e.severity !== state.sev) return false;
    if (state.q) {
      const hay = `${e.id} ${e.vendor} ${e.product} ${e.bug_class} ${e.problem} ${e.solution}`.toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  });
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

function render() {
  const list = filtered();
  const grid = $("grid");
  grid.innerHTML = "";
  $("empty").classList.toggle("hidden", list.length > 0);
  $("resultline").textContent =
    list.length === state.entries.length
      ? `${state.entries.length} vulnerabilities published ${prettyDate(state.day)} — tap any card for the full breakdown`
      : `Showing ${list.length} of ${state.entries.length}`;

  list.forEach((e, i) => {
    const t = document.createElement("button");
    t.className = `tile sev-${esc(e.severity)}`;
    t.setAttribute("aria-label", `${e.id} details`);
    t.innerHTML = `
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
    grid.appendChild(t);
  });
}

function openModal(e) {
  const body = $("modalBody");
  body.innerHTML = `
    <div class="m-head">
      <span class="m-sev ${esc(e.severity)}">${esc(e.severity)}</span>
      <span class="m-score">${esc(e.score)}</span>
      <span class="m-cve">${esc(e.id)}</span>
      ${e.exploited ? `<span class="m-kev">Exploited in the wild</span>` : ""}
    </div>
    <div class="dgrid">
      <div class="dblock"><div class="k">Vendor</div><div class="v">${esc(e.vendor || "Pending NVD analysis")}</div></div>
      <div class="dblock"><div class="k">Product</div><div class="v">${esc(e.product || "Pending NVD analysis")}</div></div>
      <div class="dblock"><div class="k">Affected versions</div><div class="v mono">${esc(e.versions || "—")}</div></div>
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
