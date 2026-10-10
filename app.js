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
  const box = $("cards");
  box.innerHTML = "";
  $("empty").classList.toggle("hidden", list.length > 0);
  $("resultline").textContent =
    list.length === state.entries.length
      ? `${state.entries.length} vulnerabilities published ${prettyDate(state.day)}`
      : `Showing ${list.length} of ${state.entries.length}`;

  list.forEach((e) => {
    const card = document.createElement("div");
    card.className = `card sev-${esc(e.severity)}`;
    const vp = [e.vendor, e.product].filter(Boolean).join(" · ");
    card.innerHTML = `
      <button class="card-head" aria-expanded="false">
        <span class="sevblock"><span class="sev ${esc(e.severity)}">${esc(e.severity)}</span><span class="score">${esc(e.score)}</span></span>
        <span class="card-main">
          <span class="cve-id">${esc(e.id)}</span>
          <span class="cve-sub">${vp ? `<strong>${esc(vp)}</strong>` : `<em>Vendor pending NVD analysis</em>`}</span>
          <span class="chips">
            ${e.bug_class ? `<span class="chip">${esc(e.bug_class)}</span>` : ""}
            ${e.exploited ? `<span class="chip kevflag">Exploited in the wild</span>` : ""}
          </span>
        </span>
        <span class="chev">▾</span>
      </button>
      <div class="detail">
        <div class="dgrid">
          <div class="dblock"><div class="k">Vendor</div><div class="v">${esc(e.vendor || "—")}</div></div>
          <div class="dblock"><div class="k">Product</div><div class="v">${esc(e.product || "—")}</div></div>
          <div class="dblock"><div class="k">Affected versions</div><div class="v mono">${esc(e.versions || "—")}</div></div>
          <div class="dblock"><div class="k">Published</div><div class="v mono">${esc(e.date || "—")}</div></div>
        </div>
        <div class="dsection problem"><div class="k">The problem</div><p>${esc(e.problem)}</p></div>
        ${e.attack && e.attack.length ? `<div class="dsection attack"><div class="k">Attack profile</div><div class="atkchips">${e.attack.map((a) => `<span>${esc(a)}</span>`).join("")}</div></div>` : ""}
        <div class="dsection solution"><div class="k">The solution</div><p>${esc(e.solution)}</p></div>
        <div class="refbtns">
          ${e.patch ? `<a href="${esc(e.patch)}" target="_blank" rel="noopener">Vendor patch / advisory</a>` : ""}
          <a class="ghost" href="${esc(e.nvd)}" target="_blank" rel="noopener">NVD details</a>
          ${e.exploit_public ? `<a class="ghost" href="https://www.google.com/search?q=${esc(e.id)}+exploit" target="_blank" rel="noopener">Public exploit info</a>` : ""}
        </div>
      </div>`;
    const head = card.querySelector(".card-head");
    head.addEventListener("click", () => {
      card.classList.toggle("open");
      head.setAttribute("aria-expanded", card.classList.contains("open"));
    });
    box.appendChild(card);
  });
}

init();
