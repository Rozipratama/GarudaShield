"use strict";

/*
 * Dashboard GarudaShield.
 *
 * GET /api/alerts  -> { mode, alerts: [{ timestamp, source_ip, description, severity }] }
 * GET /api/summary -> { total_alerts, high_alerts }
 *
 * Field opsional per alert (kalau belum ada, tampilan tetap jalan):
 *   segment     "IT" atau "OT"
 *   detail      penjelasan singkat kejadian (string)
 *   rule        nama atau ID aturan deteksi (string)
 *   mitigation  langkah awal (array of string, atau string dipisah baris baru)
 *   id          ID unik alert (untuk penanda "Baru")
 */

// Dilayani FastAPI di port 8000 -> alamat relatif. Dibuka dari server lain (mis. Live Server) -> backend lokal.
const API_URL = "http://192.168.56.10:8000";
const REFRESH_MS = 5000;
const LIVE_MODES = ["wazuh", "live"]; // nilai "mode" dari backend saat data sudah asli

const LEVEL = { critical: "Kritis", high: "Tinggi", medium: "Sedang", low: "Rendah" };
const GENERIC_STEPS = {
  critical: [
    "Anggap ini insiden aktif: segera hubungi penanggung jawab jaringan dan pimpinan terkait.",
    "Isolasi perangkat atau segmen yang terlibat dan batasi akses alamat sumber.",
    "Simpan bukti (log, waktu, alamat sumber) sebelum pemulihan, lalu laporkan sesuai prosedur satuan.",
  ],
  high: [
    "Pastikan apakah aktivitas ini dikenal. Tanyakan ke penanggung jawab perangkat atau segmen terkait.",
    "Jika tidak dikenal, batasi akses alamat sumber (misalnya blokir di firewall router) dan isolasi perangkat yang terlibat.",
    "Simpan bukti berupa waktu kejadian, alamat sumber, dan log terkait, lalu laporkan sesuai prosedur satuan.",
  ],
  medium: [
    "Periksa log lain dari alamat sumber yang sama dalam beberapa menit terakhir.",
    "Pantau apakah kejadian berulang. Jika berulang, perlakukan sebagai tingkat tinggi.",
  ],
  low: ["Tidak perlu tindakan segera. Tinjau saat pemeriksaan rutin."],
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
  return d ? d.toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "-";
}
function formatDateTime(ts) {
  const d = validDate(ts);
  return d ? d.toLocaleString("id-ID", { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "-";
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

/* ---------- Tampilan ---------- */

function renderMode(mode) {
  const live = LIVE_MODES.includes(String(mode || "").toLowerCase());
  const badge = $("#data-mode");
  badge.dataset.live = String(live);
  badge.textContent = live ? "Data Wazuh" : "Data simulasi";
  badge.title = live ? "" : "Data contoh untuk pengembangan antarmuka, belum berasal dari Wazuh.";
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
  return `Terbaru: ${alert.description}, dari ${alert.source_ip || "sumber tidak diketahui"}, pukul ${formatTime(alert.timestamp)}.`;
}

function renderBanner() {
  const alerts = state.alerts;
  const pick = (level) => alerts.filter((a) => levelOf(a) === level).sort(newestFirst);
  const critical = pick("critical"), high = pick("high"), medium = pick("medium");
  const total = Number.isFinite(state.summary.total_alerts) ? state.summary.total_alerts : alerts.length;
  const countOf = (level, list) => (Number.isFinite(state.summary[`${level}_alerts`]) ? state.summary[`${level}_alerts`] : list.length);
  const criticalCount = countOf("critical", critical), highCount = countOf("high", high);

  let counts = `${total} peringatan tercatat.`;
  if (alerts.some(segmentOf)) {
    const n = (seg) => alerts.filter((a) => segmentOf(a) === seg).length;
    counts += ` Segmen IT: ${n("IT")}. Segmen OT: ${n("OT")}.`;
  }

  if (criticalCount + highCount > 0) {
    const headline = criticalCount > 0
      ? `Ada ${criticalCount} peringatan kritis${highCount > 0 ? ` dan ${highCount} tinggi` : ""}`
      : `Ada ${highCount} peringatan tinggi`;
    const top = critical[0] || high[0];
    setBanner("danger", headline, top ? describe(top) : "Buka daftar peringatan untuk melihat rinciannya.", counts, top);
  } else if (medium.length > 0) {
    setBanner("warn", `Perlu perhatian: ${medium.length} peringatan sedang`, `Tidak ada peringatan tinggi. ${describe(medium[0])}`, counts, medium[0]);
  } else {
    setBanner("ok", "Terpantau normal", total === 0 ? "Belum ada peringatan tercatat." : "Tidak ada peringatan tinggi atau sedang.", counts);
  }
}

function renderCards() {
  for (const level of Object.keys(LEVEL)) {
    const fromApi = state.summary[`${level}_alerts`];
    const count = Number.isFinite(fromApi) ? fromApi : state.alerts.filter((a) => levelOf(a) === level).length;
    $(`#count-${level}`).textContent = count.toLocaleString("id-ID");
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
  if (state.alerts.length === 0) return tableMessage("Belum ada peringatan. Jaringan terpantau normal.");

  const rows = [...state.alerts].sort(newestFirst).map((alert) => {
    const key = keyOf(alert);
    const level = levelOf(alert);
    const row = el("tr", `row-${level}${state.fresh.has(key) ? " is-new" : ""}`);

    const timeCell = el("td", "mono", formatTime(alert.timestamp));
    if (state.fresh.has(key)) timeCell.appendChild(el("span", "new-chip", "Baru"));
    const segmentCell = el("td");
    segmentCell.appendChild(segmentOf(alert) ? segmentChip(segmentOf(alert)) : el("span", "muted", "-"));
    const sourceCell = el("td", "mono", alert.source_ip || "-");
    const eventCell = el("td");
    const link = el("button", "row-link", alert.description || "(tanpa deskripsi)");
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

/* ---------- Panel detail ---------- */

function renderDetail(alert) {
  const segment = segmentOf(alert);
  $("#detail-title").textContent = alert.description || "(tanpa deskripsi)";
  $("#detail-badges").replaceChildren(severityBadge(alert), ...(segment ? [segmentChip(segment)] : []));

  const facts = [["Waktu", formatDateTime(alert.timestamp)], ["Sumber", alert.source_ip || "-"], ["Segmen", segment || "Belum ditentukan"]];
  if (alert.rule) facts.push(["Aturan deteksi", String(alert.rule)]);
  $("#detail-facts").replaceChildren(...facts.map(([label, value]) => {
    const item = el("div");
    item.append(el("dt", "", label), el("dd", "", value));
    return item;
  }));

  $("#detail-explanation").hidden = !alert.detail;
  $("#detail-text").textContent = alert.detail || "";

  const { steps, generic } = stepsFor(alert);
  $("#detail-steps").replaceChildren(...steps.map((step) => el("li", "", step)));
  $("#detail-note").textContent = generic ? "Saran umum berdasarkan tingkat keparahan. Aturan deteksi ini belum punya saran khusus." : "";
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

/* ---------- Pengambilan data ---------- */

async function fetchJson(path) {
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} mengembalikan status ${response.status}`);
  return response.json();
}

async function loadDashboard() {
  if (state.loading) return;
  state.loading = true;
  $("#refresh-button").disabled = true;
  if (!state.hasData) tableMessage("Memuat data dari server...");

  try {
    const [alertsData, summary] = await Promise.all([fetchJson("/api/alerts"), fetchJson("/api/summary")]);
    const alerts = Array.isArray(alertsData.alerts) ? alertsData.alerts : [];
    const keys = alerts.map(keyOf);

    // Tandai "Baru" hanya setelah pemuatan pertama.
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
    console.error("Gagal memuat dashboard:", error);
    const updated = $("#updated-at");
    updated.classList.add("warn");
    if (state.hasData) {
      updated.textContent = `Gagal memperbarui pukul ${formatTime(new Date())}. Menampilkan data terakhir.`;
    } else {
      updated.textContent = "Belum terhubung";
      setBanner("unknown", "Data belum tersedia", "Server GarudaShield tidak dapat dihubungi. Periksa layanan backend, lalu klik Perbarui sekarang.");
      tableMessage("Tidak ada data untuk ditampilkan.");
    }
  } finally {
    state.loading = false;
    $("#refresh-button").disabled = false;
  }
}

/* ---------- Inisialisasi ---------- */

let timer = null;
function startAutoRefresh() {
  clearInterval(timer);
  if (state.auto) timer = setInterval(() => { if (!document.hidden) loadDashboard(); }, REFRESH_MS);
}

$("#refresh-button").addEventListener("click", loadDashboard);
$("#auto-toggle").addEventListener("click", (event) => {
  state.auto = !state.auto;
  event.currentTarget.setAttribute("aria-pressed", String(state.auto));
  event.currentTarget.textContent = `Otomatis: ${state.auto ? "nyala" : "mati"}`;
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