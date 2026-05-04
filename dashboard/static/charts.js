/* Honeynet Dashboard — client-side JS
   Fetches data from the Flask API and renders Chart.js charts + tables.
   SocketIO connection pushes new_event in real time for the live feed.
*/

const API = {
  summary: "/api/summary",
  stats:   "/api/stats",
  top:     "/api/top",
  events:  "/api/events",
};

// ── Chart.js timeline ─────────────────────────────────────────────────────────

let timelineChart = null;

function initTimeline(labels, ssh, http, mysql) {
  const ctx = document.getElementById("timeline-chart").getContext("2d");
  timelineChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "SSH",
          data: ssh,
          backgroundColor: "rgba(255,123,114,0.7)",
          borderColor: "#ff7b72",
          borderWidth: 1,
        },
        {
          label: "HTTP",
          data: http,
          backgroundColor: "rgba(255,166,87,0.7)",
          borderColor: "#ffa657",
          borderWidth: 1,
        },
        {
          label: "MySQL",
          data: mysql,
          backgroundColor: "rgba(121,192,255,0.7)",
          borderColor: "#79c0ff",
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          labels: { color: "#c9d1d9", font: { size: 12 } },
        },
      },
      scales: {
        x: {
          stacked: true,
          ticks: { color: "#8b949e", font: { size: 10 }, maxTicksLimit: 12 },
          grid:  { color: "#21262d" },
        },
        y: {
          stacked: true,
          ticks:   { color: "#8b949e", precision: 0 },
          grid:    { color: "#21262d" },
        },
      },
    },
  });
}

// ── Table helpers ─────────────────────────────────────────────────────────────

function fillTable(tbodyId, rows, keyField, maxLen) {
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = "";
  rows.slice(0, 15).forEach(r => {
    const val = maxLen && r.value && r.value.length > maxLen
      ? r.value.slice(0, maxLen) + "…"
      : (r.value ?? "—");
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${val}</td><td>${r.count.toLocaleString()}</td>`;
    tbody.appendChild(tr);
  });
}

// ── Summary stats ─────────────────────────────────────────────────────────────

function updateSummary(data) {
  document.getElementById("s-total").textContent = data.total_events.toLocaleString();
  document.getElementById("s-24h").textContent   = data.events_24h.toLocaleString();
  document.getElementById("s-ssh").textContent   = data.ssh_24h.toLocaleString();
  document.getElementById("s-http").textContent  = data.http_24h.toLocaleString();
  document.getElementById("s-mysql-label").textContent = `MySQL: ${data.mysql_24h.toLocaleString()} hits`;
}

// ── Live feed ─────────────────────────────────────────────────────────────────

const MAX_FEED_ROWS = 50;

function svcClass(svc) {
  return { ssh: "svc-ssh", http: "svc-http", mysql: "svc-mysql" }[svc] ?? "";
}

function eventDetail(ev) {
  if (ev.service === "ssh")   return `user=${ev.username ?? "—"} pass=${ev.password ?? "—"}`;
  if (ev.service === "http")  return `${ev.method ?? ""} ${ev.path ?? ""}`.trim();
  if (ev.service === "mysql") return `user=${ev.username ?? "—"} plugin=${ev.auth_plugin ?? "—"}`;
  return "";
}

function addFeedRow(ev) {
  const tbody = document.getElementById("feed-body");
  const ts = ev.ts ? ev.ts.replace("T", " ").slice(0, 19) : "—";
  const cls = svcClass(ev.service);
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${ts}</td>
    <td class="${cls}">${ev.service ?? "—"}</td>
    <td>${ev.source_ip ?? "—"}</td>
    <td>${ev.country ?? "—"}</td>
    <td>${eventDetail(ev)}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > MAX_FEED_ROWS) {
    tbody.removeChild(tbody.lastChild);
  }
}

// ── Bootstrap: load all data ──────────────────────────────────────────────────

async function load() {
  try {
    const [summary, stats, top, events] = await Promise.all([
      fetch(API.summary).then(r => r.json()),
      fetch(API.stats).then(r => r.json()),
      fetch(API.top).then(r => r.json()),
      fetch(API.events + "?limit=50").then(r => r.json()),
    ]);

    updateSummary(summary);

    // Timeline chart
    const labels = stats.map(s => s.hour);
    initTimeline(
      labels,
      stats.map(s => s.ssh),
      stats.map(s => s.http),
      stats.map(s => s.mysql),
    );

    // Tables
    fillTable("tbl-ips",       top.top_ips,       "value", 18);
    fillTable("tbl-usernames", top.top_usernames,  "value", 20);
    fillTable("tbl-paths",     top.top_paths,      "value", 28);
    fillTable("tbl-countries", top.top_countries,  "value", 16);

    // Seed live feed (newest first)
    [...events].reverse().forEach(addFeedRow);

  } catch (err) {
    console.error("Load error:", err);
  }
}

// ── SocketIO ──────────────────────────────────────────────────────────────────

const socket = io({ transports: ["websocket", "polling"] });

socket.on("connect", () => {
  document.getElementById("live-status").textContent = "● LIVE";
  document.getElementById("live-status").style.background = "#238636";
});

socket.on("disconnect", () => {
  document.getElementById("live-status").textContent = "○ OFFLINE";
  document.getElementById("live-status").style.background = "#6e7681";
});

socket.on("new_event", ev => {
  addFeedRow(ev);
  // Bump the 24h counter live
  const el = document.getElementById("s-24h");
  if (el && el.textContent !== "—") {
    el.textContent = (parseInt(el.textContent.replace(/,/g, ""), 10) + 1).toLocaleString();
  }
});

// Refresh summary + top tables every 60s without reloading the page
setInterval(async () => {
  try {
    const [summary, top] = await Promise.all([
      fetch(API.summary).then(r => r.json()),
      fetch(API.top).then(r => r.json()),
    ]);
    updateSummary(summary);
    fillTable("tbl-ips",       top.top_ips,       "value", 18);
    fillTable("tbl-usernames", top.top_usernames,  "value", 20);
    fillTable("tbl-paths",     top.top_paths,      "value", 28);
    fillTable("tbl-countries", top.top_countries,  "value", 16);
  } catch (_) {}
}, 60_000);

// Kick it off
load();
