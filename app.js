const state = { days: [], entries: [], day: null, sev: "all", q: "" };

const $ = (id) => document.getElementById(id);

async function init() {
  const days = await (await fetch("data/days.json")).json();
  state.days = days;
  const sel = $("daySelect");
  days.forEach((d) => {
    const o = document.createElement("option");
    o.value = d;
    o.textContent = prettyDate(d);
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
    })
  );
  if (days.length) loadDay(days[0]);
}

function prettyDate(d) {
  const [y, m, day] = d.split("-").map(Number);
  return new Date(y, m - 1, day).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
}

async function loadDay(day) {
  state.day = day;
  state.entries = await (await fetch(`data/${day}.json`)).json();
  render();
}

function filtered() {
  return state.entries.filter((e) => {
    if (state.sev === "exploited" && !e.exploited) return false;
    if (state.sev !== "all" && state.sev !== "exploited" && e.severity !== state.sev) return false;
    if (state.q) {
      const hay = `${e.id} ${e.product} ${e.bug_class} ${e.problem} ${e.solution}`.toLowerCase();
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

  const total = state.entries.length;
  const crit = state.entries.filter((e) => e.severity === "CRITICAL").length;
  const kev = state.entries.filter((e) => e.exploited).length;
  $("stats").textContent = `${total} new CVEs · ${crit} critical · ${kev} exploited in the wild${list.length !== total ? ` · showing ${list.length}` : ""}`;

  list.forEach((e) => {
    const card = document.createElement("div");
    card.className = "card";
    const meta = [e.product, e.bug_class].filter(Boolean).join(" · ");
    card.innerHTML = `
      <button class="card-head" aria-expanded="false">
        <span class="badge ${esc(e.severity)}">${esc(e.severity)} ${esc(e.score)}</span>
        ${e.exploited ? '<span class="kev">Exploited</span>' : ""}
        <span class="cve-id">${esc(e.id)}</span>
        <span class="cve-meta">${esc(meta)}</span>
        <span class="chev">▾</span>
      </button>
      <div class="card-body">
        ${e.bug_class ? `<span class="bugclass">${esc(e.bug_class)}</span>` : ""}
        ${e.product ? `<p style="margin-top:8px"><strong>Affects:</strong> ${esc(e.product)}${e.versions ? ` (${esc(e.versions)})` : ""}</p>` : ""}
        <div class="section-label">The problem</div>
        <p>${esc(e.problem)}</p>
        <div class="section-label">The solution</div>
        <p>${esc(e.solution)}</p>
        <div class="links">
          ${e.patch ? `<a href="${esc(e.patch)}" target="_blank" rel="noopener">Vendor patch / advisory</a>` : ""}
          <a href="${esc(e.nvd)}" target="_blank" rel="noopener">NVD details</a>
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
