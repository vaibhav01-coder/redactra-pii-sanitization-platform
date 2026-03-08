(() => {
  const API = "";
  const TOKEN_KEY = "redact_token";
  const ROLE_KEY = "redact_role";
  const EMAIL_KEY = "redact_email";
  const REFRESH_KEY = "redact_refresh_token";
  const THEME_KEY = "redact_theme";

  const LIMITS = {
    ".pdf": [5 * 1024, 50 * 1024 * 1024],
    ".docx": [2 * 1024, 50 * 1024 * 1024],
    ".xlsx": [10, 50 * 1024 * 1024],
    ".sql": [100, 100 * 1024 * 1024],
    ".csv": [10, 100 * 1024 * 1024],
    ".json": [10, 100 * 1024 * 1024],
    ".txt": [1, 10 * 1024 * 1024],
    ".png": [5 * 1024, 20 * 1024 * 1024],
    ".jpg": [5 * 1024, 20 * 1024 * 1024],
    ".jpeg": [5 * 1024, 20 * 1024 * 1024],
    ".zip": [1, 500 * 1024 * 1024],
  };

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function getSizeStatus(file, ext) {
    const limits = LIMITS[ext];
    if (!limits) return { ok: false, msg: "Unknown format" };
    const [minB, maxB] = limits;
    if (file.size < minB) return { ok: false, msg: "Below minimum (" + formatBytes(minB) + "). May be rejected." };
    if (file.size > maxB) return { ok: false, msg: "Exceeds maximum (" + formatBytes(maxB) + ")." };
    return { ok: true, msg: "Within range (" + formatBytes(minB) + " – " + formatBytes(maxB) + ")" };
  }

  const state = {
    token: localStorage.getItem(TOKEN_KEY) || "",
    role: localStorage.getItem(ROLE_KEY) || "",
    email: localStorage.getItem(EMAIL_KEY) || "",
    refresh: localStorage.getItem(REFRESH_KEY) || "",
    theme: localStorage.getItem(THEME_KEY) || "light",
    currentView: "dashboard",
    uploadMode: "single",
    uploadPhase: "select",
    pendingSuspendUserId: null,
    files: [],
    stats: null,
    users: [],
    logs: [],
    currentFileId: "",
    pollId: null,
    countdownId: null,
  };

  const $ = (id) => document.getElementById(id);
  const views = {
    dashboard: $("viewDashboard"),
    upload: $("viewUpload"),
    results: $("viewResults"),
    operations: $("viewOperations"),
  };

  function applyTheme(theme) {
    state.theme = theme;
    document.body.classList.toggle("dark", theme === "dark");
    localStorage.setItem(THEME_KEY, theme);
    const label = theme === "dark" ? "Light" : "Dark";
    $("authThemeToggle").textContent = label;
    $("appThemeToggle").textContent = label;
  }

  function toggleTheme() {
    applyTheme(state.theme === "dark" ? "light" : "dark");
  }

  function decodeJwt(token) {
    try {
      const payload = token.split(".")[1];
      if (!payload) return {};
      return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    } catch {
      return {};
    }
  }

  async function refreshSession() {
    if (!state.refresh) return false;

    try {
      const res = await fetch(API + "/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: state.refresh }),
      });
      if (!res.ok) return false;
      const out = await res.json();
      if (!out.access_token) return false;
      setSession(out.access_token, state.email, out.refresh_token || state.refresh);
      return true;
    } catch {
      return false;
    }
  }

  async function api(path, options = {}, retried = false) {
    const headers = { ...(options.headers || {}) };
    const isPublicAuth = path.startsWith("/auth/login") || path.startsWith("/auth/register") || path.startsWith("/auth/refresh");
    if (!(options.body instanceof FormData) && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
    if (state.token && !isPublicAuth) headers.Authorization = `Bearer ${state.token}`;

    const res = await fetch(API + path, { ...options, headers });
    if (res.status === 401 && !isPublicAuth && !retried) {
      const ok = await refreshSession();
      if (ok) return api(path, options, true);
      logout();
      throw new Error("Session expired. Please login again.");
    }
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please login again.");
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Request failed");
    }

    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res;
  }

  function setSession(token, email, refreshToken) {
    state.token = token;
    state.email = email;
    if (refreshToken) state.refresh = refreshToken;
    const payload = decodeJwt(token);
    state.role = payload.role || "user";
    localStorage.setItem(TOKEN_KEY, state.token);
    localStorage.setItem(ROLE_KEY, state.role);
    localStorage.setItem(EMAIL_KEY, state.email);
    localStorage.setItem(REFRESH_KEY, state.refresh || "");
    $("roleBadge").textContent = state.role.toUpperCase();
  }

  function clearPolling() {
    if (state.pollId) {
      clearInterval(state.pollId);
      state.pollId = null;
    }
  }

  function logout() {
    clearPolling();
    state.token = "";
    state.role = "";
    state.email = "";
    state.refresh = "";
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLE_KEY);
    localStorage.removeItem(EMAIL_KEY);
    localStorage.removeItem(REFRESH_KEY);
    $("appShell").classList.add("hidden");
    $("authShell").classList.remove("hidden");
  }

  function navItems() {
    const items = [
      { id: "dashboard", label: "Dashboard" },
      { id: "upload", label: "Upload File" },
      { id: "results", label: "File Results" },
    ];
    if (state.role === "admin") {
      items.push({ id: "operations", label: "Operations" });
    }
    return items;
  }

  function renderNav() {
    const nav = $("nav");
    nav.innerHTML = navItems().map((i) => `<button data-view="${i.id}">${i.label}</button>`).join("");
    nav.onclick = async (e) => {
      const btn = e.target.closest("button[data-view]");
      if (!btn) return;
      await goTo(btn.dataset.view);
    };
  }

  function setActiveNav() {
    Array.from($("nav").querySelectorAll("button[data-view]")).forEach((b) => {
      b.classList.toggle("active", b.dataset.view === state.currentView);
    });
  }

  function renderFileResultSelect() {
    const sel = $("fileResultSelect");
    const files = state.files || [];
    const opts = '<option value="">— Select a file —</option>' + files
      .map((f) => `<option value="${f.id}">${String(f.id).slice(0, 8)} — ${String(f.file_type || "").toUpperCase()} (${riskBand(f.risk_score)})</option>`)
      .join("");
    sel.innerHTML = opts;
    sel.value = state.currentFileId || "";
  }

  function ensureResultsPlaceholder() {
    renderFileResultSelect();
    if (state.currentFileId) return;
    $("resultMeta").textContent = "Open a file from Dashboard or select one above.";
    $("resultChips").innerHTML = "";
    $("entityBody").innerHTML = `<tr><td colspan="${state.role === "admin" ? 5 : 3}">No file selected</td></tr>`;
  }

  async function goTo(view) {
    if (view === "operations" && state.role !== "admin") {
      view = "dashboard";
    }

    Object.entries(views).forEach(([k, el]) => el.classList.toggle("hidden", k !== view));
    state.currentView = view;
    setActiveNav();

    if (view === "dashboard") await refreshDashboard();
    if (view === "results") {
      if (!state.files || state.files.length === 0) await refreshDashboard();
      ensureResultsPlaceholder();
    }
    if (view === "operations") await refreshUsers();
  }

  function riskBand(score) {
    if ((score ?? 0) >= 81) return "CRITICAL";
    if ((score ?? 0) >= 51) return "HIGH";
    if ((score ?? 0) >= 21) return "MODERATE";
    return "LOW";
  }

  function fmtDate(v) {
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return "-";
    return d.toLocaleString();
  }

  function fmtExpiry(v) {
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return "-";
    const ms = d.getTime() - Date.now();
    if (ms <= 0) return "Expired";
    const h = Math.floor(ms / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    return `${h}h ${m}m ${s}s`;
  }

  function renderStats() {
    const s = state.stats || { total_files: 0, total_entities: 0, expiring_soon: 0, risk_distribution: {}, flagged_count: 0, auto_deleted_today: 0 };
    const summary = [
      ["Total Files", s.total_files || 0],
      ["PII Sanitized", s.total_entities || 0],
      state.role === "admin" ? ["Threats Flagged", s.flagged_count || 0] : ["Expiring in 1hr", s.expiring_soon || 0],
      state.role === "admin" ? ["Auto-Deleted Today", s.auto_deleted_today || 0] : null,
    ].filter(Boolean);

    $("summaryGrid").className = "grid " + (summary.length === 4 ? "four" : "three");
    $("summaryGrid").innerHTML = summary
      .map(([k, v]) => `<article class="card"><div class="stat-title">${k}</div><div class="stat-value">${v}</div></article>`)
      .join("");

    const r = s.risk_distribution || {};
    const items = [["LOW", r.low || 0], ["MODERATE", r.moderate || 0], ["HIGH", r.high || 0], ["CRITICAL", r.critical || 0]];

    $("riskGrid").innerHTML = items
      .map(([k, v]) => `<article class="card"><div class="stat-title">${k}</div><div class="stat-value">${v}</div></article>`)
      .join("");
  }

  function fillStatusFilter() {
    const statuses = [...new Set(state.files.map((f) => String(f.status || "").toUpperCase()).filter(Boolean))].sort();
    const prev = $("statusFilter").value;
    $("statusFilter").innerHTML = `<option value="">All Status</option>` + statuses.map((s) => `<option value="${s}">${s}</option>`).join("");
    if (statuses.includes(prev)) $("statusFilter").value = prev;
  }

  function filteredFiles() {
    const q = $("fileSearch").value.trim().toLowerCase();
    const sf = $("statusFilter").value;
    const rf = $("riskFilter").value;

    return state.files.filter((f) => {
      const id = String(f.id || "").toLowerCase();
      const status = String(f.status || "").toUpperCase();
      const risk = riskBand(f.risk_score);
      return (!q || id.includes(q)) && (!sf || status === sf) && (!rf || risk === rf);
    });
  }

  function renderFiles() {
    const rows = filteredFiles();
    if (!rows.length) {
      $("filesBody").innerHTML = `<tr><td colspan="6">No files found</td></tr>`;
      return;
    }

    $("filesBody").innerHTML = rows
      .map((f) => {
        const risk = riskBand(f.risk_score);
        return `
          <tr>
            <td>${String(f.id).slice(0, 8)}</td>
            <td>${String(f.file_type || "").toUpperCase()}</td>
            <td><span class="risk ${risk}">${risk}</span></td>
            <td>${String(f.status || "").toUpperCase()}</td>
            <td class="expires-cell" data-expires="${f.expires_at || ""}">${fmtExpiry(f.expires_at)}</td>
            <td><button class="link-btn-inline" data-open="${f.id}">Open</button></td>
          </tr>`;
      })
      .join("");
  }

  async function refreshDashboard() {
    try {
      state.stats = await api("/dashboard/stats");
    } catch (e) {
      console.warn("Stats failed", e);
    }

    try {
      const files = await api("/files/");
      state.files = Array.isArray(files) ? files : [];
    } catch (e) {
      console.warn("Files failed", e);
      state.files = [];
    }

    renderStats();
    fillStatusFilter();
    renderFiles();
  }

  function validateUpload(file, mode) {
    const ext = file.name.includes(".") ? `.${file.name.split(".").pop().toLowerCase()}` : "";
    const singleAllowed = [".pdf", ".docx", ".xlsx", ".sql", ".csv", ".json", ".txt", ".png", ".jpg", ".jpeg"];

    if (mode === "single" && !singleAllowed.includes(ext)) throw new Error(`Unsupported file type: ${ext}`);
    if (mode === "batch" && ext !== ".zip") throw new Error("Batch mode accepts ZIP only.");

    const [min, max] = LIMITS[ext] || [1, 200 * 1024 * 1024];
    if (file.size < min || file.size > max) throw new Error(`File size out of range for ${ext}.`);
  }

  function setUploadMode(mode) {
    state.uploadMode = mode;
    state.uploadPhase = "select";
    $("uploadSelectArea").classList.remove("hidden");
    $("uploadPreview").classList.add("hidden");
    $("uploadScanning").classList.add("hidden");
    $("uploadStatus").textContent = "";
    if (mode === "single") {
      $("modeSingle").className = "primary-btn small";
      $("modeBatch").className = "ghost-btn small";
      $("uploadInput").accept = ".pdf,.docx,.xlsx,.sql,.csv,.json,.txt,.png,.jpg,.jpeg";
    } else {
      $("modeSingle").className = "ghost-btn small";
      $("modeBatch").className = "primary-btn small";
      $("uploadInput").accept = ".zip";
      $("uploadStatus").textContent = "Batch mode expects a ZIP file.";
    }
  }

  function showUploadPreview(file) {
    const ext = file.name.includes(".") ? "." + file.name.split(".").pop().toLowerCase() : "";
    const singleAllowed = [".pdf", ".docx", ".xlsx", ".sql", ".csv", ".json", ".txt", ".png", ".jpg", ".jpeg"];
    const formatOk = state.uploadMode === "single" ? singleAllowed.includes(ext) : ext === ".zip";
    const sizeStatus = LIMITS[ext] ? getSizeStatus(file, ext) : { ok: false, msg: "Unknown format" };
    const sizeOk = sizeStatus.ok;
    const canSubmit = formatOk && sizeOk;

    $("uploadFileInfo").innerHTML = `
      <div class="row"><span>Name</span><strong>${escapeHtml(file.name)}</strong></div>
      <div class="row"><span>Format</span><span>${(ext || "—").replace(".", "").toUpperCase()}</span></div>
      <div class="row"><span>Size</span><span>${formatBytes(file.size)}</span></div>
      <div class="row"><span>Status</span><span class="${sizeOk ? "size-ok" : sizeStatus.msg.indexOf("Below") !== -1 ? "size-warn" : "size-err"}">${sizeStatus.msg}</span></div>
    `;
    $("uploadSubmit").disabled = !canSubmit;
    $("uploadSelectArea").classList.add("hidden");
    $("uploadPreview").classList.remove("hidden");
    $("uploadScanning").classList.add("hidden");
    $("uploadStatus").textContent = canSubmit ? "" : "Fix format or size to submit.";
  }

  function setScanPhase(step, pct) {
    const steps = ["Running malware scan...", "Scanning for PII...", "Sanitizing file..."];
    $("uploadScanStep").textContent = steps[step - 1] || "Complete.";
    $("uploadProgressBar").style.width = pct + "%";
  }

  async function startUpload() {
    const input = $("uploadInput");
    if (!input.files || !input.files[0]) return;
    const file = input.files[0];
    try {
      validateUpload(file, state.uploadMode);
    } catch (e) {
      $("uploadStatus").textContent = e.message;
      return;
    }

    $("uploadPreview").classList.add("hidden");
    $("uploadScanning").classList.remove("hidden");
    $("uploadStatus").textContent = "";
    setScanPhase(1, 15);

    const t1 = setTimeout(() => setScanPhase(2, 50), 700);
    const t2 = setTimeout(() => setScanPhase(3, 85), 1500);

    const fd = new FormData();
    fd.append("masking_mode", $("maskMode").value || "redact");
    fd.append("bureau_field", "");

    let endpoint = "/upload/single";
    if (state.uploadMode === "batch") {
      endpoint = "/upload/folder";
      fd.append("archive", file);
    } else {
      fd.append("file", file);
    }

    try {
      const out = await api(endpoint, { method: "POST", body: fd });
      clearTimeout(t1);
      clearTimeout(t2);
      setScanPhase(3, 100);
      $("uploadScanStatus").textContent = "Complete.";

      const id = out.file_id || out.case_id || null;
      const results = out.results;

      if (out.status === "FLAGGED" || out.status === "QUARANTINED") {
        $("uploadStatus").textContent = "THREAT DETECTED — File has been quarantined.";
        $("uploadScanning").classList.add("hidden");
        $("uploadSelectArea").classList.remove("hidden");
        input.value = "";
        await refreshDashboard();
        return;
      }
      if (out.duplicate && id) {
        $("uploadStatus").textContent = "File already exists. File ID: " + String(id).slice(0, 8) + "…";
        if (id) await openResults(id);
      } else if (results && Array.isArray(results) && results.length > 0) {
        const done = results.filter((r) => r.file_id || r.status === "SANITIZED" || r.status === "FLAGGED").length;
        $("uploadStatus").textContent = "Batch complete: " + done + "/" + results.length + " files processed.";
        const first = results.find((r) => r.file_id);
        if (first && first.file_id) await openResults(first.file_id);
      } else {
        $("uploadStatus").textContent = id ? "Processing complete." : "Done.";
        if (id) await openResults(id);
      }
      await refreshDashboard();
      $("uploadScanning").classList.add("hidden");
      $("uploadSelectArea").classList.remove("hidden");
      input.value = "";
    } catch (e) {
      clearTimeout(t1);
      clearTimeout(t2);
      $("uploadStatus").textContent = e.message || "Upload failed.";
      $("uploadScanning").classList.add("hidden");
      $("uploadPreview").classList.remove("hidden");
    }
  }

  async function download(path, fallback) {
    const res = await api(path);
    const blob = await res.blob();
    const cd = res.headers.get("content-disposition") || "";
    const m = cd.match(/filename="?([^";]+)"?/i);
    const name = m ? m[1] : fallback;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function openResults(fileId) {
    const out = await api(`/files/${fileId}/result`);
    const file = out.file || {};
    state.currentFileId = fileId;

    $("resultMeta").textContent = `File ID: ${fileId}   Uploaded: ${fmtDate(file.created_at)}   ${file.pii_count || 0} PII found`;
    $("resultChips").innerHTML = `
      <span class="chip">${String(file.file_type || "").toUpperCase()}</span>
      <span class="risk ${riskBand(file.risk_score)}">${riskBand(file.risk_score)}</span>
      <span class="chip">${String(file.status || "").toUpperCase()}</span>`;

    const isAdmin = state.role === "admin";
    $("thOverride").classList.toggle("hidden", !isAdmin);
    $("thOriginal").classList.toggle("hidden", !isAdmin);
    $("downloadOriginal").classList.toggle("hidden", !isAdmin);

    const entities = out.entities || [];
    const colCount = isAdmin ? 5 : 3;
    if (!entities.length) {
      $("entityBody").innerHTML = `<tr><td colspan="${colCount}">No entities found</td></tr>`;
    } else {
      $("entityBody").innerHTML = entities
        .map((e) => `
          <tr>
            <td>${e.entity_type}</td>
            ${isAdmin ? `<td class="mono">${escapeHtml(e.original_value != null ? e.original_value : "—")}</td>` : ""}
            <td class="mono">${escapeHtml(e.masked_value || "")}</td>
            <td>${Math.round((e.confidence || 0) * 100)}%</td>
            ${isAdmin ? `<td><button class="link-btn-inline" data-override="${e.id}">Mark False Positive</button></td>` : ""}
          </tr>`)
        .join("");
    }

    renderFileResultSelect();
    $("fileResultSelect").value = fileId;
    await goTo("results");
  }

  function escapeHtml(str) {
    if (str == null) return "";
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function filteredUsers() {
    const q = $("userSearch").value.trim().toLowerCase();
    const role = $("userRoleFilter").value;
    const status = $("userStatusFilter").value;
    return state.users.filter((u) => {
      const mq = !q || String(u.email || "").toLowerCase().includes(q);
      const mr = !role || u.role === role;
      const ms = !status || (status === "active" ? !!u.is_active : !u.is_active);
      return mq && mr && ms;
    });
  }

  function updateLiveCountdowns() {
    const cells = document.querySelectorAll("#filesBody .expires-cell");
    cells.forEach((cell) => {
      const expiresAt = cell.getAttribute("data-expires") || "";
      cell.textContent = fmtExpiry(expiresAt);
    });
  }

  function renderUsers() {
    const rows = filteredUsers();
    if (!rows.length) {
      $("usersBody").innerHTML = `<tr><td colspan="5">No users</td></tr>`;
      return;
    }

    $("usersBody").innerHTML = rows
      .map((u) => {
        const isPending = state.pendingSuspendUserId === u.id;
        const actionCell = isPending
          ? `<span class="confirm-inline">Are you sure?</span>
             <button class="ghost-btn small action-btn action-confirm-suspend" data-user-id="${u.id}">Confirm</button>
             <button class="ghost-btn small action-btn action-cancel-suspend">Cancel</button>`
          : `<button class="ghost-btn small action-btn action-toggle" data-toggle-user="${u.id}" data-active="${u.is_active}">${u.is_active ? "Suspend" : "Activate"}</button>`;
        return `
        <tr>
          <td>${u.email}</td>
          <td><span class="role-chip ${u.role}">${String(u.role).toUpperCase()}</span></td>
          <td>${u.file_count ?? 0}</td>
          <td><span class="status-chip ${u.is_active ? "active" : "inactive"}">${u.is_active ? "ACTIVE" : "INACTIVE"}</span></td>
          <td class="actions-cell">${actionCell}</td>
        </tr>`;
      })
      .join("");
  }

  async function refreshUsers() {
    if (state.role !== "admin") return;
    state.users = await api("/users/");
    renderUsers();
  }

  async function refreshAudit() {
    if (state.role !== "admin") return;
    state.logs = await api("/audit/logs?skip=0&limit=100");
    $("auditBody").innerHTML = state.logs.length
      ? state.logs.map((l) => `<tr><td>${l.event_type}</td><td>${String(l.user_id || "").slice(0, 8)}</td><td>${String(l.file_id || "").slice(0, 8)}</td><td>${fmtDate(l.created_at)}</td></tr>`).join("")
      : `<tr><td colspan="4">No logs</td></tr>`;
  }

  function strength(password) {
    if (!password) return "";
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    if (password.length < 8 || !hasNumber) return "Weak";
    if (password.length >= 8 && hasNumber && !hasSpecial) return "Medium";
    return "Strong";
  }

  function bindAuth() {
    $("authThemeToggle").onclick = toggleTheme;

    $("tabLogin").onclick = () => {
      $("tabLogin").classList.add("active");
      $("tabRegister").classList.remove("active");
      $("loginForm").classList.remove("hidden");
      $("registerForm").classList.add("hidden");
    };

    $("tabRegister").onclick = () => {
      $("tabRegister").classList.add("active");
      $("tabLogin").classList.remove("active");
      $("registerForm").classList.remove("hidden");
      $("loginForm").classList.add("hidden");
    };

    $("toggleLoginPassword").onclick = () => {
      const input = $("loginPassword");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("toggleLoginPassword").textContent = show ? "Hide" : "Show";
    };

    $("regPassword").addEventListener("input", () => {
      const s = strength($("regPassword").value);
      $("passStrength").textContent = s ? `Password strength: ${s}` : "";
    });

    $("loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("loginError").textContent = "";
      const email = $("loginEmail").value.trim();
      const password = $("loginPassword").value;
      try {
        const out = await api("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
        setSession(out.access_token, email, out.refresh_token);
        await enterApp();
      } catch (err) {
        $("loginError").textContent = err.message || "Login failed";
      }
    });

    $("registerForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = $("regEmail").value.trim();
      const password = $("regPassword").value;
      const confirm = $("regConfirm").value;
      const honeypot = $("regHoney").value;

      if (!email) return ($("regMsg").textContent = "Email is required");
      if (password.length < 8) return ($("regMsg").textContent = "Password must be at least 8 characters");
      if (password !== confirm) return ($("regMsg").textContent = "Confirm password does not match");

      try {
        await api("/auth/register", { method: "POST", body: JSON.stringify({ email, password, bureau_field: honeypot }) });
        $("regMsg").textContent = "Account created. Please log in.";
        setTimeout(() => $("tabLogin").click(), 1200);
      } catch (err) {
        $("regMsg").textContent = err.message || "Registration failed";
      }
    });
  }

  function bindApp() {
    $("appThemeToggle").onclick = toggleTheme;
    $("logoutBtn").onclick = logout;

    ["fileSearch", "statusFilter", "riskFilter"].forEach((id) => {
      $(id).addEventListener("input", renderFiles);
      $(id).addEventListener("change", renderFiles);
    });

    $("toUpload").onclick = () => goTo("upload");

    $("filesBody").onclick = async (e) => {
      const btn = e.target.closest("button[data-open]");
      if (!btn) return;
      try {
        await openResults(btn.dataset.open);
      } catch (err) {
        alert(err.message || "Failed to open results");
      }
    };

    $("modeSingle").onclick = () => setUploadMode("single");
    $("modeBatch").onclick = () => setUploadMode("batch");
    $("dropZone").onclick = () => $("uploadInput").click();
    $("uploadSubmit").onclick = startUpload;
    $("uploadChangeFile").onclick = () => {
      $("uploadInput").value = "";
      state.uploadPhase = "select";
      $("uploadPreview").classList.add("hidden");
      $("uploadScanning").classList.add("hidden");
      $("uploadSelectArea").classList.remove("hidden");
      $("uploadStatus").textContent = "";
    };
    $("uploadInput").addEventListener("change", () => {
      const f = $("uploadInput").files?.[0];
      if (f) showUploadPreview(f);
      else {
        $("uploadPreview").classList.add("hidden");
        $("uploadSelectArea").classList.remove("hidden");
      }
    });
    $("dropZone").addEventListener("dragover", (e) => { e.preventDefault(); e.stopPropagation(); $("dropZone").classList.add("drop-over"); });
    $("dropZone").addEventListener("dragleave", () => { $("dropZone").classList.remove("drop-over"); });
    $("dropZone").addEventListener("drop", (e) => {
      e.preventDefault();
      $("dropZone").classList.remove("drop-over");
      const f = e.dataTransfer?.files?.[0];
      if (!f) return;
      const dt = new DataTransfer();
      dt.items.add(f);
      $("uploadInput").files = dt.files;
      showUploadPreview(f);
    });

    $("scanAnother").onclick = () => goTo("upload");
    $("fileResultSelect").addEventListener("change", async () => {
      const id = $("fileResultSelect").value;
      if (!id) return;
      try {
        await openResults(id);
      } catch (err) {
        alert(err.message || "Failed to load results");
      }
    });
    $("downloadSanitized").onclick = () => download(`/files/${state.currentFileId}/download`, `sanitized_${state.currentFileId}.txt`);
    $("downloadOriginal").onclick = () => download(`/files/${state.currentFileId}/original`, `original_${state.currentFileId}.bin`);

    $("entityBody").onclick = async (e) => {
      const btn = e.target.closest("button[data-override]");
      if (!btn || state.role !== "admin") return;
      try {
        await api(`/scan/${state.currentFileId}/override`, {
          method: "POST",
          body: JSON.stringify({ entity_id: btn.dataset.override, is_false_positive: true }),
        });
        await openResults(state.currentFileId);
      } catch (err) {
        alert(err.message || "Override failed");
      }
    };

    $("usersTab").onclick = () => {
      $("usersTab").classList.add("active");
      $("auditTab").classList.remove("active");
      $("usersPanel").classList.remove("hidden");
      $("auditPanel").classList.add("hidden");
    };

    $("auditTab").onclick = async () => {
      $("auditTab").classList.add("active");
      $("usersTab").classList.remove("active");
      $("usersPanel").classList.add("hidden");
      $("auditPanel").classList.remove("hidden");
      await refreshAudit();
    };

    ["userSearch", "userRoleFilter", "userStatusFilter"].forEach((id) => {
      $(id).addEventListener("input", renderUsers);
      $(id).addEventListener("change", renderUsers);
    });

    $("showAddUser").onclick = () => $("addUserBox").classList.toggle("hidden");

    $("createUser").onclick = async () => {
      const email = $("newUserEmail").value.trim();
      const password = $("newUserPassword").value;
      const role = $("newUserRole").value;
      try {
        await api("/users/", { method: "POST", body: JSON.stringify({ email, password, role }) });
        $("userMsg").textContent = "User created.";
        $("newUserEmail").value = "";
        $("newUserPassword").value = "";
        await refreshUsers();
      } catch (err) {
        $("userMsg").textContent = err.message || "Create failed";
      }
    };

    $("usersBody").onclick = async (e) => {
      const toggle = e.target.closest("button[data-toggle-user]");
      if (toggle) {
        const id = toggle.dataset.toggleUser;
        const active = toggle.dataset.active === "true";
        if (active) {
          state.pendingSuspendUserId = id;
          renderUsers();
          return;
        }
        await api(`/users/${id}`, { method: "PATCH", body: JSON.stringify({ is_active: true }) });
        $("userMsg").textContent = "User reactivated.";
        await refreshUsers();
        return;
      }

      const confirmBtn = e.target.closest("button[data-user-id].action-confirm-suspend");
      if (confirmBtn) {
        const id = confirmBtn.dataset.userId;
        try {
          await api(`/users/${id}`, { method: "DELETE" });
          $("userMsg").textContent = "User suspended.";
          state.pendingSuspendUserId = null;
          await refreshUsers();
        } catch (err) {
          $("userMsg").textContent = err.message || "Failed to suspend.";
        }
        return;
      }

      if (e.target.closest("button.action-cancel-suspend")) {
        state.pendingSuspendUserId = null;
        renderUsers();
      }
    };

    $("refreshAudit").onclick = refreshAudit;
    $("exportAudit").onclick = () => download("/audit/export", "audit_log.pdf");
  }

  async function enterApp() {
    $("authShell").classList.add("hidden");
    $("appShell").classList.remove("hidden");
    $("roleBadge").textContent = state.role.toUpperCase();

    renderNav();
    setUploadMode("single");
    $("fileSearch").value = "";
    await goTo("dashboard");

    clearPolling();
    state.pollId = setInterval(() => {
      if (state.currentView === "dashboard") refreshDashboard().catch(() => {});
    }, 30000);

    state.countdownId = setInterval(() => {
      if (state.currentView === "dashboard") updateLiveCountdowns();
    }, 1000);
  }

  function boot() {
    applyTheme(state.theme);
    bindAuth();
    bindApp();

    if (state.token) {
      enterApp().catch(() => logout());
    }
  }

  boot();
})();














