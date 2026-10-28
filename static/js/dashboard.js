/* Dashboard logic. Polls the Flask API every 2 seconds. */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(url, opts) {
  let r;
  try { r = await fetch(url, opts); }
  catch (_) { throw new Error("Cannot connect to the backend. Check that the Flask server is running."); }
  let d = {};
  try { d = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) throw new Error(d.error || "Request failed (HTTP " + r.status + ")");
  return d;
}
function showApiError(error) {
  const el = $("api-error");
  if (!el) return;
  el.textContent = error.message || String(error);
  el.hidden = false;
}
function clearApiError() {
  const el = $("api-error");
  if (el) { el.hidden = true; el.textContent = ""; }
}
function toast(msg) {
  const t = $("toast"); t.textContent = msg; t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2800);
}
const sources = (list) => (list || []).map((s) => esc(s[0]) + " (" + s[1] + ")").join(", ") || "-";
const sev = (s) => '<span class="badge b-' + esc(s) + '">' + esc(s) + "</span>";

/* ---------------- Dashboard page ---------------- */
let trafficChart, synChart;
function initCharts() {
  if (typeof Chart === "undefined") { toast("Chart.js could not load (offline?). See README."); return; }
  Chart.defaults.color = "#8a99b5";
  const grid = { color: "#25324d" };
  trafficChart = new Chart($("chart-traffic"), { type: "line",
    data: { labels: [], datasets: [
      { label: "All packets", data: [], borderColor: "#3b82f6", tension: .3 },
      { label: "TCP packets", data: [], borderColor: "#22d3ee", tension: .3 }] },
    options: { animation: false, scales: { x: { grid }, y: { grid, beginAtZero: true } } } });
  synChart = new Chart($("chart-syn"), { type: "bar",
    data: { labels: [], datasets: [
      { label: "Initial SYN count", data: [], backgroundColor: [] },
      { type: "line", label: "Threshold", data: [], borderColor: "#ef4444", borderDash: [6, 4], pointRadius: 0 }] },
    options: { animation: false, scales: { x: { grid }, y: { grid, beginAtZero: true } } } });
}
function updateCharts(st) {
  if (!trafficChart || !st.settings) return;
  const tl = st.timeline, labels = tl.map((w) => w.t);
  trafficChart.data.labels = labels;
  trafficChart.data.datasets[0].data = tl.map((w) => w.total);
  trafficChart.data.datasets[1].data = tl.map((w) => w.tcp);
  trafficChart.update();
  synChart.data.labels = labels;
  synChart.data.datasets[0].data = tl.map((w) => w.syn);
  synChart.data.datasets[0].backgroundColor = tl.map((w) => (w.suspicious ? "#f59e0b" : "#22c55e"));
  synChart.data.datasets[1].data = tl.map(() => st.settings.syn_threshold);
  synChart.update();
}
function renderStatus(s) {
  const st = s.stats || {};
  $("c-total").textContent = st.total_packets ?? 0;
  $("c-tcp").textContent = st.tcp_packets ?? 0;
  $("c-syn").textContent = st.syn_packets ?? 0;
  $("c-src").textContent = st.unique_sources ?? 0;
  $("c-susp").textContent = st.suspicious_windows ?? 0;
  const el = $("c-status");
  el.textContent = s.state.toUpperCase();
  el.className = s.state === "running" ? "ok" : s.state === "error" ? "bad" : "";
  $("c-sub").textContent = s.running ? s.mode + " · " + s.uptime_seconds + "s" : "idle";
  $("btn-start").disabled = s.running; $("btn-stop").disabled = !s.running;
  const box = $("err-box");
  box.hidden = !(s.error); box.textContent = s.error || "";
}
function renderAlertsMini(list) {
  const b = $("alert-body");
  if (!list.length) { b.innerHTML = '<tr><td colspan="6" class="muted">No alerts yet.</td></tr>'; return; }
  b.innerHTML = list.slice(0, 8).map((a) => "<tr><td>" + esc(a.created_at) + "</td><td>" + sev(a.severity) +
    "</td><td>" + a.max_syn_count + "</td><td>" + a.threshold + "</td><td>" + a.window_seconds + "s x" +
    a.repeat_count + "</td><td>" + sources(JSON.parse(a.sources || "[]").slice(0, 2)) + "</td></tr>").join("");
}
function renderSources(list) {
  const b = $("src-body");
  if (!list || !list.length) { b.innerHTML = '<tr><td colspan="4" class="muted">No data yet.</td></tr>'; return; }
  b.innerHTML = list.map((s) => "<tr><td>" + esc(s.ip) + "</td><td>" + s.syn + "</td><td>" + s.tcp +
    "</td><td>" + esc(s.last_seen) + "</td></tr>").join("");
}
async function refresh() {
  try {
    const [s, st, al] = await Promise.all([api("/api/status"), api("/api/statistics"), api("/api/alerts?limit=8")]);
    renderStatus(s); updateCharts(st); renderSources(st.sources); renderAlertsMini(al.alerts);
    clearApiError();
  } catch (e) { showApiError(e); }
}
function settingsBody(prefix) {
  return { window_seconds: +$(prefix + "window").value, syn_threshold: +$(prefix + "thr").value,
           per_source_threshold: +$(prefix + "per").value };
}
async function initDashboard() {
  initCharts();
  api("/api/interfaces").then((d) => {
    $("iface-list").innerHTML = d.interfaces.map((i) => '<option value="' + esc(i) + '">').join("");
    if (!d.scapy_available) toast("Scapy not found: only Simulation mode and PCAP analysis will work.");
  }).catch(showApiError);
  $("btn-start").onclick = async () => {
    try {
      const body = settingsBody("f-"); body.mode = $("f-mode").value; body.interface = $("f-iface").value;
      await api("/api/monitor/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      toast("Monitoring started");
    } catch (e) { toast(e.message); $("err-box").hidden = false; $("err-box").textContent = e.message; }
    refresh();
  };
  $("btn-stop").onclick = async () => {
    try { await api("/api/monitor/stop", { method: "POST" }); toast("Monitoring stopped"); }
    catch (e) { toast(e.message); }
    refresh();
  };
  $("btn-pcap").onclick = analyzePcap;
  refresh(); setInterval(refresh, 2000);
}
async function analyzePcap() {
  const f = $("p-file").files[0], out = $("pcap-result");
  if (!f) { toast("Choose a .pcap or .pcapng file first."); return; }
  const fd = new FormData(); fd.append("file", f);
  const s = settingsBody("p-");
  Object.keys(s).forEach((k) => fd.append(k, s[k]));
  out.innerHTML = '<p class="muted">Analyzing...</p>';
  try {
    const r = await api("/api/pcap/analyze", { method: "POST", body: fd });
    const t = r.totals;
    let html = '<p><b>' + esc(r.message) + '</b> (file: ' + esc(r.filename) + ', session #' + r.session_id + ')</p>' +
      '<div class="summary"><span>Packets: <b>' + t.total_packets + '</b></span><span>TCP: <b>' + t.tcp_packets +
      '</b></span><span>Initial SYN: <b>' + t.syn_packets + '</b></span><span>Sources: <b>' + t.unique_sources +
      '</b></span><span>Windows: <b>' + t.windows_analyzed + '</b></span><span>Suspicious windows: <b class="warn">' +
      t.suspicious_windows + '</b></span></div>';
    if (r.suspicious.length) {
      html += '<div class="table-wrap"><table><thead><tr><th>Window start</th><th>Window end</th><th>SYNs</th><th>Severity</th><th>Top sources</th></tr></thead><tbody>' +
        r.suspicious.map((w) => "<tr><td>" + esc(w.window_start) + "</td><td>" + esc(w.window_end) + "</td><td>" +
          w.syn_count + "</td><td>" + sev(w.severity) + "</td><td>" + sources(w.top_sources) + "</td></tr>").join("") +
        "</tbody></table></div>";
    } else html += '<p class="ok">No suspicious windows with the chosen thresholds.</p>';
    out.innerHTML = html;
    refresh();
  } catch (e) { out.innerHTML = '<p class="errbox">' + esc(e.message) + "</p>"; }
}

/* ---------------- Alerts page ---------------- */
async function loadAlerts() {
  try {
    const inc = $("show-cleared").checked ? "1" : "0";
    const d = await api("/api/alerts?limit=300&include_cleared=" + inc);
    $("alerts-body").innerHTML = d.alerts.map((a) => "<tr><td>" + a.id + "</td><td>" + esc(a.created_at) + "</td><td>" +
      sev(a.severity) + "</td><td>" + a.max_syn_count + "</td><td>" + a.threshold + " / " + a.per_source_threshold +
      "</td><td>" + esc(a.window_start) + " (" + a.window_seconds + "s)</td><td>" + a.repeat_count + "</td><td>" +
      sources(JSON.parse(a.sources || "[]")) + "</td><td>" + esc(a.status) + (a.hidden ? " (cleared)" : "") + "</td><td>" +
      (a.status === "new" ? '<button class="btn blue small" onclick="ackAlert(' + a.id + ')">Acknowledge</button> ' : "") +
      (!a.hidden ? '<button class="btn red small" onclick="clearAlert(' + a.id + ')">Clear</button>' : "") +
      "</td></tr>").join("") || '<tr><td colspan="10" class="muted">No alerts.</td></tr>';
    clearApiError();
  } catch (e) { showApiError(e); }
}
async function ackAlert(id) {
  try { await api("/api/alerts/" + id + "/acknowledge", { method: "POST" }); await loadAlerts(); }
  catch (e) { showApiError(e); }
}
async function clearAlert(id) {
  try {
    await api("/api/alerts/clear", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    await loadAlerts();
  } catch (e) { showApiError(e); }
}
function initAlerts() {
  $("show-cleared").onchange = loadAlerts;
  $("btn-clear-all").onclick = async () => {
    try {
      await api("/api/alerts/clear", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      toast("Alerts cleared from display"); await loadAlerts();
    } catch (e) { showApiError(e); }
  };
  loadAlerts(); setInterval(loadAlerts, 4000);
}

/* ---------------- Reports page ---------------- */
async function loadReports() {
  try {
    const d = await api("/api/reports?suspicious_only=" + ($("only-susp").checked ? "1" : "0"));
    $("sess-body").innerHTML = d.sessions.map((s) => "<tr><td>" + s.id + "</td><td>" + esc(s.mode) + "</td><td>" +
      esc(s.source_label) + "</td><td>" + esc(s.started_at) + "</td><td>" + esc(s.ended_at || "-") + "</td><td>" +
      s.window_seconds + "s</td><td>" + s.syn_threshold + " / " + s.per_source_threshold + "</td><td>" + s.total_packets +
      "</td><td>" + s.syn_packets + "</td><td>" + s.suspicious_windows + "</td><td>" + esc(s.status) + "</td></tr>").join("") ||
      '<tr><td colspan="11" class="muted">No sessions yet.</td></tr>';
    $("win-body").innerHTML = d.windows.map((w) => "<tr><td>" + w.session_id + "</td><td>" + esc(w.window_start) +
      "</td><td>" + esc(w.window_end) + "</td><td>" + w.tcp_packets + "</td><td>" + w.syn_count + "</td><td>" +
      w.unique_sources + '</td><td><span class="badge b-' + esc(w.detection_status) + '">' + esc(w.detection_status) +
      "</span></td><td>" + sev(w.severity) + "</td><td>" + sources(JSON.parse(w.top_sources || "[]")) + "</td></tr>").join("") ||
      '<tr><td colspan="9" class="muted">No windows yet.</td></tr>';
    clearApiError();
  } catch (e) { showApiError(e); }
}
function initReports() { $("only-susp").onchange = loadReports; loadReports(); setInterval(loadReports, 5000); }

const page = document.body.dataset.page;
if (page === "dashboard") initDashboard();
if (page === "alerts") initAlerts();
if (page === "reports") initReports();
