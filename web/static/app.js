// Phantom Dashboard v3 — Live monitoring with charts, tables, toasts & export

// ---- State ----
let toolTimeline = [];
let findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let findingsList = [];
let toolsUsed = {};
let portsData = [];
let ffufData = [];
let currentTurn = 0;
let missionStartTime = null;
let timerInterval = null;
let activeFilter = "all";

// ---- Charts (lazy-init) ----
let chartSeverity = null;
let chartPorts = null;
let chartTools = null;
let chartFfuf = null;
let summaryChartSev = null;
let summaryChartTools = null;

const COLORS = {
    critical: '#f85149',
    high: '#d29b00',
    medium: '#e3b341',
    low: '#58a6ff',
    info: '#6e7681',
};

// socket is initialized inside DOMContentLoaded after CDN check
let socket = null;


// ---- Toast Notifications ----

function toast(message, type = "info", duration = 4000) {
    const container = document.getElementById("toast-container");
    const el = document.createElement("div");
    el.className = "toast " + type;

    const icons = { success: "✓", error: "✗", warning: "⚠", info: "ℹ" };
    el.innerHTML = '<span class="toast-icon">' + (icons[type] || "ℹ") + '</span>' +
                   '<span>' + escapeHtml(String(message)) + '</span>';
    container.appendChild(el);

    setTimeout(() => {
        el.classList.add("toast-fade-out");
        setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 350);
    }, duration);
}


// ---- Mission Progress Bar ----

function setMissionProgress(active) {
    const bar = document.getElementById("mission-progress");
    if (!bar) return;
    if (active) {
        bar.classList.add("active");
    } else {
        bar.classList.remove("active");
    }
}


// ---- UI Functions ----

function setStatus(text, connected) {
    const el = document.getElementById("connection-status");
    el.textContent = text;
    el.className = "status" + (connected ? " connected" : "");
}

function addTerminalLine(text, type) {
    const body = document.getElementById("terminal-body");
    const line = document.createElement("div");
    line.className = "terminal-line " + (type || "");
    line.textContent = text;
    body.appendChild(line);
    // Keep max 500 lines
    while (body.children.length > 500) body.removeChild(body.firstChild);
    body.scrollTop = body.scrollHeight;
}

function clearTerminal() {
    document.getElementById("terminal-body").innerHTML = "";
    toast("Terminal cleared", "info", 1500);
}

function addTimelineItem(name, id, status) {
    const bar = document.getElementById("timeline-bar");
    const item = document.createElement("span");
    item.className = "timeline-item " + status;
    item.textContent = name;
    item.dataset.toolId = id || "";
    item.setAttribute("role", "listitem");
    bar.appendChild(item);
    toolTimeline.push(item);
    while (bar.children.length > 50) bar.removeChild(bar.firstChild);
    toolTimeline = toolTimeline.slice(-50);
}

function updateTimelineItem(id, status, duration) {
    let target = null;
    for (let i = toolTimeline.length - 1; i >= 0; i--) {
        if (toolTimeline[i].dataset.toolId === id) {
            target = toolTimeline[i];
            break;
        }
    }
    if (!target && toolTimeline.length > 0) {
        target = toolTimeline[toolTimeline.length - 1];
    }
    if (target) {
        target.className = "timeline-item " + status;
        if (duration) {
            const dur = document.createElement("span");
            dur.className = "tl-duration";
            dur.textContent = duration + "s";
            target.appendChild(dur);
        }
    }
}

function updateFindingsBadges() {
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
        const el = document.getElementById("count-" + sev);
        if (el) el.textContent = findings[sev] + " " + sev.charAt(0).toUpperCase() + sev.slice(1);
    }
}

function addFindingEntry(f) {
    const list = document.getElementById("findings-list");
    const entry = document.createElement("div");
    entry.className = "finding-entry";
    const sev = (f.severity || "info").toLowerCase();
    entry.innerHTML =
        '<div class="finding-sev"><span class="sev-badge sev-' + sev + '">' + sev.toUpperCase() + '</span></div>' +
        '<div class="finding-detail">' + escapeHtml(f.template || f.extra || f.url || "Finding") + '</div>';
    list.insertBefore(entry, list.firstChild);
    while (list.children.length > 30) list.removeChild(list.lastChild);
}


// ---- Empty State Management ----

function updateEmptyStates() {
    document.querySelectorAll('tbody').forEach(tbody => {
        const empty = tbody.parentElement.querySelector('.empty-state');
        if (empty) empty.style.display = tbody.children.length === 0 ? 'block' : 'none';
    });
}


// ---- Severity Filter ----

function filterFindings(sev) {
    activeFilter = sev;
    // Update filter button states
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.classList.toggle("active-filter", btn.dataset.sev === sev);
    });
    // Show/hide rows
    const rows = document.querySelectorAll("#table-findings tbody tr");
    rows.forEach(row => {
        const badge = row.querySelector(".sev-badge");
        if (!badge) return;
        const rowSev = badge.textContent.toLowerCase();
        row.style.display = (sev === "all" || rowSev === sev) ? "" : "none";
    });
}


// ---- Table Functions ----

function addFindingRow(f) {
    const tbody = document.querySelector("#table-findings tbody");
    const row = document.createElement("tr");
    const sev = (f.severity || "info").toLowerCase();
    row.setAttribute("data-sev", sev);
    row.innerHTML =
        '<td><span class="sev-badge sev-' + sev + '">' + sev.toUpperCase() + '</span></td>' +
        '<td title="' + escapeHtml(f.template || "") + '">' + escapeHtml(f.template || "") + '</td>' +
        '<td>' + escapeHtml(f.protocol || "") + '</td>' +
        '<td title="' + escapeHtml(f.url || "") + '">' + escapeHtml(f.url || "") + '</td>' +
        '<td title="' + escapeHtml(f.extra || "") + '">' + escapeHtml(f.extra || "") + '</td>';
    tbody.appendChild(row);
    // Apply current filter
    if (activeFilter !== "all" && sev !== activeFilter) {
        row.style.display = "none";
    }
    updateEmptyStates();
}

function addPortRow(p) {
    const tbody = document.querySelector("#table-ports tbody");
    const row = document.createElement("tr");
    const stClass = p.state === "open" ? "status-open" : p.state === "filtered" ? "status-filtered" : "status-closed";
    row.innerHTML =
        '<td>' + p.port + '</td>' +
        '<td>' + escapeHtml(p.protocol || "") + '</td>' +
        '<td><span class="status-badge ' + stClass + '">' + escapeHtml(p.state || "") + '</span></td>' +
        '<td>' + escapeHtml(p.service || "") + '</td>' +
        '<td title="' + escapeHtml(p.version || "") + '">' + escapeHtml(p.version || "") + '</td>';
    tbody.appendChild(row);
    updateEmptyStates();
}

function addFfufRow(r) {
    const tbody = document.querySelector("#table-ffuf tbody");
    const row = document.createElement("tr");
    const st = r.status || 0;
    const httpClass = st >= 500 ? "http-5xx" : st >= 400 ? "http-4xx" : st >= 300 ? "http-3xx" : "http-2xx";
    row.innerHTML =
        '<td title="' + escapeHtml(r.url || "") + '">' + escapeHtml(r.url || "") + '</td>' +
        '<td><span class="http-status ' + httpClass + '">' + st + '</span></td>' +
        '<td>' + (r.size || 0) + '</td>' +
        '<td>' + (r.words || 0) + '</td>';
    tbody.appendChild(row);
    updateEmptyStates();
}


// ---- CSV Export ----

function _tableToCSV(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return "";
    const rows = [];
    const headers = Array.from(table.querySelectorAll("thead th")).map(th => '"' + th.textContent.trim() + '"');
    rows.push(headers.join(","));
    table.querySelectorAll("tbody tr").forEach(tr => {
        if (tr.style.display === "none") return;
        const cells = Array.from(tr.querySelectorAll("td")).map(td => {
            // Get plain text, escape double-quotes
            const text = (td.getAttribute("title") || td.textContent).trim().replace(/"/g, '""');
            return '"' + text + '"';
        });
        rows.push(cells.join(","));
    });
    return rows.join("\n");
}

function _downloadCSV(csv, filename) {
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportFindingsCSV() {
    const csv = _tableToCSV("table-findings");
    if (!csv || csv.split("\n").length <= 1) {
        toast("No findings to export", "info", 2000);
        return;
    }
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    _downloadCSV(csv, "phantom-findings-" + ts + ".csv");
    toast("Findings exported as CSV", "success", 2500);
}

function exportPortsCSV() {
    const csv = _tableToCSV("table-ports");
    if (!csv || csv.split("\n").length <= 1) {
        toast("No port data to export", "info", 2000);
        return;
    }
    const ts = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    _downloadCSV(csv, "phantom-ports-" + ts + ".csv");
    toast("Ports exported as CSV", "success", 2500);
}


// ---- Charts ----

function initCharts() {
    if (typeof Chart === 'undefined') return;

    const defaults = Chart.defaults;
    defaults.color = '#8b949e';
    defaults.borderColor = '#30363d';
    // Use system UI font in charts — monospace is reserved for terminal output only
    defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
    defaults.font.size = 11;

    // Severity donut
    const ctxSev = document.getElementById("chart-severity");
    if (ctxSev) {
        chartSeverity = new Chart(ctxSev, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low", "Info"],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low, COLORS.info],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: "right", labels: { boxWidth: 12 } },
                    tooltip: {
                        callbacks: {
                            label: ctx => ctx.label + ": " + ctx.parsed + " findings",
                        },
                    },
                },
            },
        });
    }

    // Ports bar chart
    const ctxPorts = document.getElementById("chart-ports");
    if (ctxPorts) {
        chartPorts = new Chart(ctxPorts, {
            type: "bar",
            data: { labels: [], datasets: [{ label: "Open Ports", data: [], backgroundColor: "#58a6ff" }] },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: "y",
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { grid: { display: false } },
                },
            },
        });
    }

    // Tools pie chart
    const ctxTools = document.getElementById("chart-tools");
    if (ctxTools) {
        chartTools = new Chart(ctxTools, {
            type: "pie",
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        "#f85149", "#d2a8ff", "#58a6ff", "#7ee787",
                        "#e3b341", "#79c0ff", "#d29b00", "#8b949e",
                        "#a5d6ff", "#ffa657", "#3fb950", "#f0883e",
                    ],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: "right", labels: { boxWidth: 10, font: { size: 10 } } },
                    tooltip: {
                        callbacks: {
                            label: ctx => ctx.label + ": " + ctx.parsed + "x",
                        },
                    },
                },
            },
        });
    }

    // FFuf status chart
    const ctxFfuf = document.getElementById("chart-ffuf");
    if (ctxFfuf) {
        chartFfuf = new Chart(ctxFfuf, {
            type: "bar",
            data: { labels: [], datasets: [{ label: "Count", data: [], backgroundColor: [] }] },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1 } },
                },
            },
        });
    }
}

function updateSeverityChart() {
    if (!chartSeverity) return;
    chartSeverity.data.datasets[0].data = [
        findings.critical, findings.high, findings.medium, findings.low, findings.info,
    ];
    chartSeverity.update();
}

function updatePortsChart() {
    if (!chartPorts) return;
    const openPorts = portsData.filter(p => p.state === "open");
    chartPorts.data.labels = openPorts.map(p => p.port + "/" + p.protocol);
    chartPorts.data.datasets[0].data = openPorts.map(() => 1);
    chartPorts.data.datasets[0].backgroundColor = openPorts.map(p => {
        const port = p.port;
        if ([80, 443, 8080, 8443].includes(port)) return "#58a6ff";
        if ([21, 22, 23, 3389].includes(port)) return "#f85149";
        if ([3306, 5432, 1433, 27017].includes(port)) return "#e3b341";
        return "#7ee787";
    });
    chartPorts.update();
}

function updateToolsChart() {
    if (!chartTools) return;
    chartTools.data.labels = Object.keys(toolsUsed);
    chartTools.data.datasets[0].data = Object.values(toolsUsed);
    chartTools.update();
}

function updateFfufChart() {
    if (!chartFfuf) return;
    const statusCounts = {};
    ffufData.forEach(r => {
        const code = r.status || 0;
        const bucket = Math.floor(code / 100) + "xx";
        statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
    });
    const labels = Object.keys(statusCounts).sort();
    const colors = labels.map(l => {
        if (l === "2xx") return "#7ee787";
        if (l === "3xx") return "#58a6ff";
        if (l === "4xx") return "#d29b00";
        return "#f85149";
    });
    chartFfuf.data.labels = labels;
    chartFfuf.data.datasets[0].data = labels.map(l => statusCounts[l]);
    chartFfuf.data.datasets[0].backgroundColor = colors;
    chartFfuf.update();
}


// ---- Mission Summary ----

function showMissionSummary(data) {
    const panel = document.getElementById("summary-panel");
    const duration = data.duration ? formatDuration(data.duration) : "N/A";
    const totalFindings = findings.critical + findings.high + findings.medium + findings.low + findings.info;
    const totalTools = Object.values(toolsUsed).reduce((a, b) => a + b, 0);

    let html = '<div class="summary-header">' +
        '<h2>MISSION COMPLETE</h2>' +
        '<div class="summary-meta">' + (data.turns || currentTurn) + ' turns &nbsp;|&nbsp; ' +
        duration + ' &nbsp;|&nbsp; ' + totalFindings + ' findings</div>' +
        '</div>';

    html += '<div class="summary-stats">';
    html += statCard(findings.critical, "Critical", "critical");
    html += statCard(findings.high, "High", "high");
    html += statCard(findings.medium, "Medium", "medium");
    html += statCard(totalTools, "Tools Run", "tools");
    html += statCard(data.turns || currentTurn, "Turns", "turns");
    html += statCard(duration, "Duration", "duration");
    html += '</div>';

    html += '<div class="summary-charts">' +
        '<div class="summary-chart-card"><h3>Findings by Severity</h3><canvas id="summary-chart-sev"></canvas></div>' +
        '<div class="summary-chart-card"><h3>Tools Breakdown</h3><canvas id="summary-chart-tools"></canvas></div>' +
        '</div>';

    if (data.summary) {
        html += '<h3 style="color:var(--blue);font-size:12px;margin:12px 0 8px;text-transform:uppercase;letter-spacing:1px;">Agent Summary</h3>';
        html += '<div class="summary-text">' + escapeHtml(data.summary) + '</div>';
    }

    panel.innerHTML = html;

    // Render summary charts (guard for Chart.js availability)
    if (typeof Chart === 'undefined') return;

    setTimeout(() => {
        const ctxSev = document.getElementById("summary-chart-sev");
        if (ctxSev) {
            if (summaryChartSev) summaryChartSev.destroy();
            summaryChartSev = new Chart(ctxSev, {
                type: "doughnut",
                data: {
                    labels: ["Critical", "High", "Medium", "Low", "Info"],
                    datasets: [{
                        data: [findings.critical, findings.high, findings.medium, findings.low, findings.info],
                        backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low, COLORS.info],
                        borderWidth: 0,
                    }],
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: "right", labels: { boxWidth: 12 } } },
                },
            });
        }
        const ctxTools = document.getElementById("summary-chart-tools");
        if (ctxTools && Object.keys(toolsUsed).length > 0) {
            if (summaryChartTools) summaryChartTools.destroy();
            summaryChartTools = new Chart(ctxTools, {
                type: "pie",
                data: {
                    labels: Object.keys(toolsUsed),
                    datasets: [{
                        data: Object.values(toolsUsed),
                        backgroundColor: [
                            "#f85149", "#d2a8ff", "#58a6ff", "#7ee787",
                            "#e3b341", "#79c0ff", "#d29b00", "#8b949e",
                        ],
                        borderWidth: 0,
                    }],
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: "right", labels: { boxWidth: 10, font: { size: 10 } } } },
                },
            });
        }
    }, 100);
}

function statCard(value, label, cls) {
    return '<div class="stat-card ' + cls + '">' +
        '<div class="stat-value">' + value + '</div>' +
        '<div class="stat-label">' + label + '</div>' +
        '</div>';
}


// ---- Tabs ----

function switchTab(el) {
    document.querySelectorAll(".tab").forEach(t => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
    });
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    el.classList.add("active");
    el.setAttribute("aria-selected", "true");
    const target = el.dataset.tab || el.getAttribute("data-tab");
    const panel = document.getElementById(target);
    if (panel) panel.classList.add("active");
}


// ---- Timer ----

function startTimer() {
    if (timerInterval) clearInterval(timerInterval);
    missionStartTime = Date.now();
    timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - missionStartTime) / 1000);
        document.getElementById("mission-timer").textContent = formatDuration(elapsed);
    }, 1000);
}

function stopTimer() {
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = null;
}

function formatDuration(sec) {
    if (typeof sec !== "number") return String(sec);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = Math.floor(sec % 60);
    if (h > 0) return h + "h " + m + "m " + s + "s";
    if (m > 0) return m + "m " + s + "s";
    return s + "s";
}


// ---- Mission Control ----

function _validateScope(scope) {
    if (!scope) return "Enter a target scope before launching.";
    // Reject obvious shell injection characters
    if (/[;&|`$(){}]/.test(scope)) return "Scope contains invalid characters.";
    // Must look like a URL, IP, or CIDR
    const urlRe = /^https?:\/\/[^\s]+$/i;
    const ipRe = /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/;
    const domainRe = /^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}(\/.*)?$/;
    const lines = scope.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
    for (const line of lines) {
        if (!urlRe.test(line) && !ipRe.test(line) && !domainRe.test(line)) {
            return "Invalid scope entry: \"" + line + "\". Use URLs (http://...), IPs, CIDRs, or domains.";
        }
    }
    return null; // valid
}

function startMission() {
    const scope = document.getElementById("scope-input").value.trim();
    const validationError = _validateScope(scope);
    if (validationError) {
        addTerminalLine(validationError, "error");
        toast(validationError, "error", 3000);
        document.getElementById("scope-input").focus();
        return;
    }

    resetState();
    document.getElementById("btn-launch").disabled = true;
    document.getElementById("btn-stop").disabled = false;
    startTimer();
    setMissionProgress(true);

    addTerminalLine("Starting mission against: " + scope, "system");

    fetch("/api/missions/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            scope: scope,
            provider: document.getElementById("provider-select").value,
        }),
    })
    .then(r => {
        if (!r.ok) return r.text().then(t => { throw new Error("Launch failed (" + r.status + "): " + t); });
        return r.json();
    })
    .then(data => {
        if (data.error) {
            addTerminalLine("Error: " + data.error, "error");
            toast(data.error, "error", 5000);
            document.getElementById("btn-launch").disabled = false;
            document.getElementById("btn-stop").disabled = true;
            stopTimer();
            setMissionProgress(false);
        }
    })
    .catch(err => {
        addTerminalLine("Error: " + err, "error");
        toast(String(err), "error", 5000);
        document.getElementById("btn-launch").disabled = false;
        document.getElementById("btn-stop").disabled = true;
        stopTimer();
        setMissionProgress(false);
    });
}

function stopMission() {
    document.getElementById('btn-stop').disabled = true;
    fetch("/api/missions/stop", { method: "POST" })
    .then(r => {
        if (!r.ok) throw new Error("Stop failed (" + r.status + ")");
        return r.json();
    })
    .then(() => {
        toast("Stop signal sent.", "warning");
    })
    .catch(e => {
        toast(e.message, "error");
        document.getElementById('btn-stop').disabled = false;
    });
}

function resetState() {
    findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findingsList = [];
    toolsUsed = {};
    portsData = [];
    ffufData = [];
    toolTimeline = [];
    currentTurn = 0;
    activeFilter = "all";
    updateFindingsBadges();
    document.getElementById("timeline-bar").innerHTML = "";
    document.getElementById("findings-list").innerHTML = "";
    document.getElementById("turn-badge").textContent = "Turn 0";
    document.getElementById("mission-timer").textContent = "";
    document.querySelector("#table-findings tbody").innerHTML = "";
    document.querySelector("#table-ports tbody").innerHTML = "";
    document.querySelector("#table-ffuf tbody").innerHTML = "";
    document.getElementById("summary-panel").innerHTML =
        '<div class="summary-placeholder">Mission in progress...</div>';
    clearTerminal();
    // Reset filter buttons
    document.querySelectorAll(".filter-btn").forEach(b => {
        b.classList.toggle("active-filter", b.dataset.sev === "all");
    });
    // Reset charts
    if (chartSeverity) { chartSeverity.data.datasets[0].data = [0,0,0,0,0]; chartSeverity.update(); }
    if (chartPorts) { chartPorts.data.labels = []; chartPorts.data.datasets[0].data = []; chartPorts.update(); }
    if (chartTools) { chartTools.data.labels = []; chartTools.data.datasets[0].data = []; chartTools.update(); }
    if (chartFfuf) { chartFfuf.data.labels = []; chartFfuf.data.datasets[0].data = []; chartFfuf.update(); }
    updateEmptyStates();
}


// ---- Session Management ----

function loadSessions() {
    const list = document.getElementById("session-list");
    list.innerHTML = '<div class="loading-spinner"></div>';
    fetch("/api/sessions?limit=50")
    .then(r => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
    })
    .then(data => {
        // Support both paginated {sessions: [...]} and legacy flat array
        const sessions = Array.isArray(data) ? data : (data.sessions || []);
        list.innerHTML = "";
        if (!sessions.length) {
            list.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:6px">No sessions yet</div>';
            return;
        }
        sessions.forEach(s => {
            const item = document.createElement("div");
            item.className = "session-item";
            item.setAttribute("role", "listitem");
            item.setAttribute("tabindex", "0");
            const badge = s.has_report ? '<span class="session-badge">Report</span>' : "";
            item.innerHTML =
                '<div class="session-id">' + escapeHtml(s.label || s.id) + badge + '</div>' +
                '<div class="session-meta">' + s.file_count + ' files' + (s.has_state ? ' | Resumable' : '') + '</div>';
            item.onclick = function() { loadSession(s.id, this); };
            item.onkeydown = function(e) { if (e.key === "Enter" || e.key === " ") loadSession(s.id, this); };
            list.appendChild(item);
        });
    })
    .catch(() => {
        list.innerHTML = '<div class="empty-state">Failed to load sessions</div>';
    });
}

function loadSession(sessionId, el) {
    document.querySelectorAll(".session-item").forEach(e => e.classList.remove("active"));
    if (el) el.classList.add("active");

    fetch("/api/sessions/" + encodeURIComponent(sessionId) + "/state")
    .then(r => {
        if (!r.ok) throw new Error("state " + r.status);
        return r.json();
    })
    .then(data => {
        if (data.error) {
            addTerminalLine("No state data for this session.", "system");
            return;
        }

        // Reset state only after successful fetch
        resetState();

        if (data.findings) {
            data.findings.forEach(f => {
                const sev = (f.severity || "info").toLowerCase();
                if (findings[sev] !== undefined) findings[sev]++;
                findingsList.push(f);
                addFindingEntry(f);
                addFindingRow(f);
            });
            updateFindingsBadges();
            updateSeverityChart();
        }

        if (data.nmap) {
            data.nmap.forEach(scan => {
                if (scan.ports) {
                    scan.ports.forEach(p => {
                        portsData.push(p);
                        addPortRow(p);
                    });
                }
            });
            updatePortsChart();
        }

        if (data.ffuf) {
            data.ffuf.forEach(r => {
                ffufData.push(r);
                addFfufRow(r);
            });
            updateFfufChart();
        }

        if (data.tools_used) {
            data.tools_used.forEach(t => {
                toolsUsed[t.name] = (toolsUsed[t.name] || 0) + 1;
            });
            updateToolsChart();
        }

        clearTerminal();
        addTerminalLine(
            "Session: " + sessionId + " | Turn " + data.turn + " | " + data.message_count + " messages",
            "system"
        );
        if (data.texts) {
            data.texts.forEach(t => addTerminalLine(t, "agent"));
        }

        currentTurn = data.turn;
        document.getElementById("turn-badge").textContent = "Turn " + data.turn;

        const totalFindings = findings.critical + findings.high + findings.medium + findings.low + findings.info;
        const totalTools = Object.values(toolsUsed).reduce((a, b) => a + b, 0);
        showMissionSummary({
            turns: data.turn,
            duration: "N/A",
            summary: "Session loaded from history.\n" + totalFindings + " findings, " + totalTools + " tool calls.",
        });

        switchTab(document.querySelector('[data-tab="charts-tab"]'));
        toast("Session " + sessionId + " loaded", "success", 2500);
        updateEmptyStates();
    })
    .catch(() => {
        // Fallback: load log file
        clearTerminal();
        addTerminalLine("Loading session log...", "system");
        fetch("/api/sessions/" + encodeURIComponent(sessionId) + "/logs/agent.log")
        .then(r => r.json())
        .then(log => {
            if (log.content) {
                log.content.split("\n").slice(-100).forEach(line => {
                    addTerminalLine(line, "agent");
                });
            }
        })
        .catch(() => addTerminalLine("Could not load session log.", "error"));
    });
}


// ---- Keyboard Shortcuts ----

document.addEventListener("keydown", (e) => {
    // Don't fire when user is typing in an input
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.tagName === "SELECT") {
        return;
    }

    switch (e.key.toUpperCase()) {
        case "R":
            if (!e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                loadSessions();
                toast("Sessions refreshed", "info", 1500);
            }
            break;
        case "C":
            if (!e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                clearTerminal();
            }
            break;
        case "F":
            if (!e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                document.getElementById("scope-input").focus();
            }
            break;
    }
});


// ---- Helpers ----

function escapeHtml(text) {
    if (text == null) return "";
    const div = document.createElement("div");
    div.textContent = String(text);
    let safe = div.innerHTML;
    safe = safe.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    return safe;
}


// ---- Init ----

document.addEventListener("DOMContentLoaded", () => {
    // CDN fallback check — Socket.IO
    if (typeof io === 'undefined') {
        const mainEl = document.getElementById("main-content") || document.querySelector("main");
        if (mainEl) {
            mainEl.innerHTML =
                '<div class="empty-state" style="padding:40px;font-size:14px;">Socket.IO failed to load. ' +
                'Check your network connection or CDN access.</div>';
        }
        return;
    }

    // CDN fallback check — Chart.js
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js not loaded — charts disabled');
    }

    // Connect Socket.IO with API key from query string
    const apiKey = new URLSearchParams(window.location.search).get('key') || '';
    socket = io({ query: { key: apiKey } });

    // ---- WebSocket Events ----

    socket.on("connect", () => {
        setStatus("Connected", true);
        toast("Connected to dashboard", "success", 2500);
    });

    socket.on("disconnect", () => {
        setStatus("Disconnected", false);
        toast("Dashboard disconnected", "error", 4000);
        setMissionProgress(false);
    });

    socket.on("connected", (data) => {
        setStatus("Connected", true);
        if (data.mission_running) {
            document.getElementById("btn-launch").disabled = true;
            document.getElementById("btn-stop").disabled = false;
            startTimer();
            setMissionProgress(true);
            toast("Mission already in progress", "info");
        }
    });

    socket.on("session_started", (data) => {
        addTerminalLine("Session: " + data.session, "system");
        loadSessions();
    });

    socket.on("turn_start", (data) => {
        currentTurn = data.turn;
        document.getElementById("turn-badge").textContent = "Turn " + data.turn;
        addTerminalLine("--- Turn " + data.turn + " ---", "turn-separator");
    });

    socket.on("agent_output", (data) => {
        addTerminalLine(data.text, data.type || "agent");
    });

    socket.on("tool_start", (data) => {
        const inputStr = JSON.stringify(data.input || {});
        const short = inputStr.length > 80 ? inputStr.slice(0, 80) + "..." : inputStr;
        addTerminalLine("[TOOL] " + data.name + "(" + short + ")", "tool");
        addTimelineItem(data.name, data.id, "running");

        // Track tool usage
        toolsUsed[data.name] = (toolsUsed[data.name] || 0) + 1;
        updateToolsChart();
    });

    socket.on("tool_result", (data) => {
        const content = data.content || '';
        const display = content.length > 200 ? content.slice(0, 200) + "..." : content;
        addTerminalLine("[RESULT:" + (data.name || "?") + "] " + display, "result");
        updateTimelineItem(data.id, "done", data.duration);
    });

    socket.on("tool_data", (data) => {
        if (data.label === "nmap" && data.data && data.data.ports) {
            data.data.ports.forEach(p => {
                portsData.push(p);
                addPortRow(p);
            });
            updatePortsChart();
        }
        if (data.label === "ffuf" && Array.isArray(data.data)) {
            data.data.forEach(r => {
                ffufData.push(r);
                addFfufRow(r);
            });
            updateFfufChart();
        }
    });

    socket.on("finding", (data) => {
        const sev = (data.severity || "info").toLowerCase();
        if (findings[sev] !== undefined) findings[sev]++;
        updateFindingsBadges();

        findingsList.push(data);
        addFindingEntry(data);
        addFindingRow(data);
        updateSeverityChart();

        if (sev === "critical") {
            toast("CRITICAL finding: " + (data.template || data.url || "New finding"), "error", 6000);
        } else if (sev === "high") {
            toast("HIGH finding: " + (data.template || data.url || "New finding"), "warning", 4000);
        }
    });

    socket.on("mission_complete", (data) => {
        addTerminalLine("=== MISSION COMPLETE ===", "system");
        document.getElementById("btn-launch").disabled = false;
        document.getElementById("btn-stop").disabled = true;
        stopTimer();
        setMissionProgress(false);
        loadSessions();
        showMissionSummary(data);
        switchTab(document.querySelector('[data-tab="summary-tab"]'));
        const total = findings.critical + findings.high + findings.medium + findings.low + findings.info;
        toast("Mission complete — " + total + " findings in " + (data.turns || currentTurn) + " turns", "success", 8000);
    });

    socket.on("mission_error", (data) => {
        addTerminalLine("[ERROR] " + data.error, "error");
        if (data.traceback) {
            addTerminalLine(data.traceback, "error");
        }
        document.getElementById("btn-launch").disabled = false;
        document.getElementById("btn-stop").disabled = true;
        stopTimer();
        setMissionProgress(false);
        toast("Mission error: " + data.error, "error", 8000);
    });

    socket.on("mission_status", (data) => {
        if (data.status === "running") {
            addTerminalLine("Mission started.", "system");
            setMissionProgress(true);
        }
    });

    // ---- Reconnection feedback ----

    socket.on("reconnect_attempt", () => {
        document.getElementById("status-badge").textContent = "Reconnecting...";
        document.getElementById("status-badge").className = "status-badge status-warning";
    });

    socket.on("reconnect", () => {
        document.getElementById("status-badge").textContent = "Connected";
        document.getElementById("status-badge").className = "status-badge status-ok";
        toast("Reconnected", "success");
    });

    // ---- Init charts & sessions ----

    if (typeof Chart !== 'undefined') {
        initCharts();
    }
    loadSessions();
    updateEmptyStates();
});
