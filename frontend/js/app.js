"use strict";

const API_URL = "http://192.168.56.10:8000";
const REFRESH_MS = 5000;
const LIVE_MODES = ["wazuh", "live"];

const LEVEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const GENERIC_STEPS = {
  critical: [
    "Treat this as an active incident: immediately notify the network owner and relevant leadership.",
    "Isolate the affected device or segment and restrict access from the source address.",
    "Preserve evidence (logs, timestamps, and source addresses) before recovery, then report according to your incident procedure.",
  ],
  high: [
    "Verify whether this activity is expected. Check with the owner of the affected device or segment.",
    "If the activity is unrecognized, restrict the source address (for example, with a router firewall) and isolate the affected device.",
    "Preserve the event time, source address, and relevant logs, then report according to your incident procedure.",
  ],
  medium: [
    "Review other logs from the same source address for the last few minutes.",
    "Monitor for recurrence. If it happens again, treat it as a high-severity event.",
  ],
  low: ["No immediate action is required. Review during routine checks."],
};

const $ = (selector) => document.querySelector(selector);
const state = { alerts: [], summary: {}, seen: null, fresh: new Set(), rows: new Map(), selected: null, bannerAlert: null, loading: false, auto: true, hasData: false };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function validDate(ts) {
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? null : date;
}
function formatTime(ts) {
  const d = validDate(ts);
  return d ? d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "-";
}
function formatDateTime(ts) {
  const d = validDate(ts);
  return d ? d.toLocaleString("en-GB", { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "-";
}

function levelOf(alert) {
  const value = String(alert.severity || "").toLowerCase();
  return LEVEL[value] ? value : "low";
}
function segmentOf(alert) {
  const value = String(alert.segment || "").toUpperCase();
  return value === "IT" || value === "OT" ? value : "";
}
const keyOf = (alert) => String(alert.id ?? `${alert.timestamp}|${alert.source_ip}|${alert.description}`);
const newestFirst = (a, b) => new Date(b.timestamp) - new Date(a.timestamp);

function severityBadge(alert) {
  const level = levelOf(alert);
  return el("span", `severity ${level}`, LEVEL[level]);
}
function segmentChip(segment) {
  return el("span", `segment ${segment.toLowerCase()}`, segment || "-");
}

function stepsFor(alert) {
  const raw = alert.mitigation;
  const list = Array.isArray(raw) ? raw.map(String) : typeof raw === "string" ? raw.split("\n") : [];
  const steps = list.map((s) => s.trim()).filter(Boolean);
  return steps.length ? { steps, generic: false } : { steps: GENERIC_STEPS[levelOf(alert)], generic: true };
}

/* ---------- Rendering ---------- */

function renderMode(mode) {
  const live = LIVE_MODES.includes(String(mode || "").toLowerCase());
  const badge = $("#data-mode");
  badge.dataset.live = String(live);
  badge.textContent = live ? "Wazuh Data" : "Simulated Data";
  badge.title = live ? "" : "Sample data for interface development; it is not sourced from Wazuh.";
}

function setBanner(stateName, headline, detail, counts, alert) {
  $("#status-banner").dataset.state = stateName;
  $("#status-headline").textContent = headline;
  $("#status-detail").textContent = detail;
  $("#status-counts").textContent = counts || "";
  state.bannerAlert = alert || null;
  $("#status-action").hidden = !alert;
}

function describe(alert) {
  return `Latest: ${alert.description}, from ${alert.source_ip || "unknown source"}, at ${formatTime(alert.timestamp)}.`;
}

function renderBanner() {
  const alerts = state.alerts;
  const pick = (level) => alerts.filter((a) => levelOf(a) === level).sort(newestFirst);
  const critical = pick("critical"), high = pick("high"), medium = pick("medium");
  const total = Number.isFinite(state.summary.total_alerts) ? state.summary.total_alerts : alerts.length;
  const countOf = (level, list) => (Number.isFinite(state.summary[`${level}_alerts`]) ? state.summary[`${level}_alerts`] : list.length);
  const criticalCount = countOf("critical", critical), highCount = countOf("high", high);

  let counts = `${total} alerts recorded.`;
  if (alerts.some(segmentOf)) {
    const n = (seg) => alerts.filter((a) => segmentOf(a) === seg).length;
    counts += ` IT segment: ${n("IT")}. OT segment: ${n("OT")}.`;
  }

  if (criticalCount + highCount > 0) {
    const headline = criticalCount > 0
      ? `${criticalCount} critical alert${criticalCount === 1 ? "" : "s"}${highCount > 0 ? ` and ${highCount} high-severity alert${highCount === 1 ? "" : "s"}` : ""}`
      : `${highCount} high-severity alert${highCount === 1 ? "" : "s"}`;
    const top = critical[0] || high[0];
    setBanner("danger", headline, top ? describe(top) : "Open the alerts list to view details.", counts, top);
  } else if (medium.length > 0) {
    setBanner("warn", `Requires attention: ${medium.length} medium-severity alert${medium.length === 1 ? "" : "s"}`, `No high-severity alerts. ${describe(medium[0])}`, counts, medium[0]);
  } else {
    setBanner("ok", "Monitoring Normal", total === 0 ? "No alerts have been recorded yet." : "No high- or medium-severity alerts.", counts);
  }
}

function renderCards() {
  for (const level of Object.keys(LEVEL)) {
    const fromApi = state.summary[`${level}_alerts`];
    const count = Number.isFinite(fromApi) ? fromApi : state.alerts.filter((a) => levelOf(a) === level).length;
    $(`#count-${level}`).textContent = count.toLocaleString("en-GB");
  }
}

function tableMessage(text) {
  const cell = el("td", "table-message", text);
  cell.colSpan = 5;
  $("#alerts-body").replaceChildren(el("tr", "", undefined));
  $("#alerts-body").firstChild.appendChild(cell);
}

function renderTable() {
  const body = $("#alerts-body");
  state.rows.clear();
  if (state.alerts.length === 0) return tableMessage("No alerts yet. The network appears normal.");

  const rows = [...state.alerts].sort(newestFirst).map((alert) => {
    const key = keyOf(alert);
    const level = levelOf(alert);
    const row = el("tr", `row-${level}${state.fresh.has(key) ? " is-new" : ""}`);

    const timeCell = el("td", "mono", formatTime(alert.timestamp));
    if (state.fresh.has(key)) timeCell.appendChild(el("span", "new-chip", "New"));
    const segmentCell = el("td");
    segmentCell.appendChild(segmentOf(alert) ? segmentChip(segmentOf(alert)) : el("span", "muted", "-"));
    const sourceCell = el("td", "mono", alert.source_ip || "-");
    const eventCell = el("td");
    const link = el("button", "row-link", alert.description || "(no description)");
    link.type = "button";
    eventCell.appendChild(link);
    const levelCell = el("td");
    levelCell.appendChild(severityBadge(alert));

    row.append(timeCell, segmentCell, sourceCell, eventCell, levelCell);
    row.addEventListener("click", () => openDetail(alert));
    state.rows.set(key, link);
    return row;
  });
  body.replaceChildren(...rows);
}

/* ---------- Detail panel ---------- */

function renderDetail(alert) {
  const segment = segmentOf(alert);
  $("#detail-title").textContent = alert.description || "(no description)";
  $("#detail-badges").replaceChildren(severityBadge(alert), ...(segment ? [segmentChip(segment)] : []));

  const facts = [["Time", formatDateTime(alert.timestamp)], ["Source", alert.source_ip || "-"], ["Segment", segment || "Not specified"]];
  if (alert.rule) facts.push(["Detection Rule", String(alert.rule)]);
  $("#detail-facts").replaceChildren(...facts.map(([label, value]) => {
    const item = el("div");
    item.append(el("dt", "", label), el("dd", "", value));
    return item;
  }));

  $("#detail-explanation").hidden = !alert.detail;
  $("#detail-text").textContent = alert.detail || "";

  const { steps, generic } = stepsFor(alert);
  $("#detail-steps").replaceChildren(...steps.map((step) => el("li", "", step)));
  $("#detail-note").textContent = generic ? "General guidance based on severity. This detection rule does not have a specific recommendation yet." : "";
}

function openDetail(alert) {
  state.selected = keyOf(alert);
  renderDetail(alert);
  $("#detail").inert = false;
  $("#detail").classList.add("is-open");
  $("#detail-overlay").classList.add("is-open");
  $("#detail-close").focus();
}

function closeDetail() {
  if (!$("#detail").classList.contains("is-open")) return;
  $("#detail").classList.remove("is-open");
  $("#detail-overlay").classList.remove("is-open");
  $("#detail").inert = true;
  const link = state.rows.get(state.selected);
  state.selected = null;
  if (link && link.isConnected) link.focus();
}

/* ---------- Data fetching ---------- */

async function fetchJson(path) {
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned status ${response.status}`);
  return response.json();
}

async function loadDashboard() {
  if (state.loading) return;
  state.loading = true;
  $("#refresh-button").disabled = true;
  if (!state.hasData) tableMessage("Loading data from server...");

  try {
    const [alertsData, summary] = await Promise.all([fetchJson("/api/alerts"), fetchJson("/api/summary")]);
    const alerts = Array.isArray(alertsData.alerts) ? alertsData.alerts : [];
    const keys = alerts.map(keyOf);

    // Tandai "New" hanya setelah pemuatan pertama.
    state.fresh = new Set(state.seen ? keys.filter((k) => !state.seen.has(k)) : []);
    state.seen = new Set([...(state.seen || []), ...keys]);
    Object.assign(state, { alerts, summary: summary || {}, hasData: true });

    renderMode(alertsData.mode);
    renderBanner();
    renderCards();
    renderTable();
    const updated = $("#updated-at");
    updated.textContent = `Diperbarui ${formatTime(new Date())}`;
    updated.classList.remove("warn");
  } catch (error) {
    console.error("Failed to load dashboard:", error);
    const updated = $("#updated-at");
    updated.classList.add("warn");
    if (state.hasData) {
      updated.textContent = `Refresh failed at ${formatTime(new Date())}. Showing the last available data.`;
    } else {
      updated.textContent = "Not connected";
      setBanner("unknown", "Data unavailable", "The GarudaShield server cannot be reached. Check the backend service, then click Refresh Now.");
      tableMessage("No data to display.");
    }
  } finally {
    state.loading = false;
    $("#refresh-button").disabled = false;
  }
}

/* ---------- Initialization ---------- */

let timer = null;
function startAutoRefresh() {
  clearInterval(timer);
  if (state.auto) timer = setInterval(() => { if (!document.hidden) loadDashboard(); }, REFRESH_MS);
}

$("#refresh-button").addEventListener("click", loadDashboard);
$("#auto-toggle").addEventListener("click", (event) => {
  state.auto = !state.auto;
  event.currentTarget.setAttribute("aria-pressed", String(state.auto));
  event.currentTarget.textContent = `Auto-refresh: ${state.auto ? "On" : "Off"}`;
  startAutoRefresh();
});
$("#status-action").addEventListener("click", () => state.bannerAlert && openDetail(state.bannerAlert));
$("#detail-close").addEventListener("click", closeDetail);
$("#detail-overlay").addEventListener("click", closeDetail);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDetail(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden) loadDashboard(); });
window.addEventListener("hashchange", () => {
  document.querySelectorAll(".nav-link").forEach((link) => link.classList.toggle("active", link.getAttribute("href") === location.hash));
});

loadDashboard();
startAutoRefresh();