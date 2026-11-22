const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const S = {
  topo: "",
  topoName: "",
  inspect: null,
  excel: null,
  selected: new Set(),
  online: {},
  probe: {},
  identity: {},
  applicable: {},
  mismatch: {},
};

const VIEW_META = {
  topo: ["拓扑解析", "上传 .topo 文件，自动识别设备、端口与链路"],
  excel: ["批量导入", "导入 Excel 设备清单与命令，批量下发"],
  inspect: ["设备巡检", "SSH / Telnet 采集设备指标，自动提取 CPU、内存、光衰等数值"],
  aiops: ["智能运维", "健康评分、动态基线、根因推断、趋势预测与配置合规"],
  logs: ["日志审计", "采集 / 导入设备日志，过滤导出后生成审计报告"],
  tools: ["网络工具", "Ping、端口扫描、DNS、子网计算、下载测速与抓包分析"],
  ops: ["配置运维", "批量备份配置、对比差异、验证设备间连通性"],
  brief: ["任务书", "按实验任务书生成地址规划与配置骨架"],
  history: ["执行记录", "命令下发流水与回显归档"],
  env: ["环境体检", "eNSP / VirtualBox 运行环境预检"],
};

/* ---------------- 主题 ---------------- */

// 截图/自动化场景下关掉动画，避免抓到淡入的第一帧
if (new URLSearchParams(location.search).get("noanim") === "1") {
  const style = document.createElement("style");
  style.textContent = "*{animation:none !important;transition:none !important}";
  document.head.appendChild(style);
}

function applyTheme(theme, persist = true) {
  document.documentElement.dataset.theme = theme;
  if (persist) {
    try {
      localStorage.setItem("ensp-theme", theme);
    } catch (e) {
      /* 隐私模式下可能失败 */
    }
  }
  const btn = $("#btnTheme");
  if (btn) btn.textContent = theme === "dark" ? "浅色" : "深色";
}

(function initTheme() {
  let saved = "light";
  try {
    saved = localStorage.getItem("ensp-theme") || "light";
  } catch (e) {
    /* ignore */
  }
  const urlTheme = new URLSearchParams(location.search).get("theme");
  if (urlTheme === "dark" || urlTheme === "light") {
    applyTheme(urlTheme, false); // 链接里带的主题只影响本次，不写偏好
    return;
  }
  applyTheme(saved);
})();

$("#btnTheme").addEventListener("click", () => {
  const now = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(now);
});

/* ---------------- 通用 ---------------- */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function shortPort(name) {
  return String(name || "")
    .replace(/^GigabitEthernet/i, "GE")
    .replace(/^Ethernet/i, "Eth")
    .replace(/^Serial/i, "Ser")
    .replace(/^FastEthernet/i, "FE");
}

let toastTimer = null;
function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.className = "toast" + (isError ? " err" : "");
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 5200 : 2600);
}

async function api(path, options = {}) {
  const { timeout = 0, ...rest } = options;
  let timer = null;
  if (timeout > 0) {
    const controller = new AbortController();
    rest.signal = controller.signal;
    timer = setTimeout(() => controller.abort(), timeout);
  }
  try {
    const res = await fetch(path, rest);
    const type = res.headers.get("content-type") || "";
    if (!type.includes("application/json")) {
      const text = await res.text();
      throw new Error(text?.slice(0, 300) || `HTTP ${res.status}`);
    }
    const data = await res.json();
    if (data && data.detail && data.ok === undefined) {
      throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
    }
    if (data && data.ok === false && data.error) throw new Error(data.error);
    return data;
  } catch (err) {
    if (err && err.name === "AbortError") {
      throw new Error(`请求超过 ${Math.round(timeout / 1000)} 秒未返回，已中断`);
    }
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function setAlert(id, message, kind = "") {
  const el = $(id);
  if (!message) { el.hidden = true; return; }
  el.className = "alert" + (kind ? " " + kind : "");
  el.innerHTML = message;
  el.hidden = false;
}

/* ---------------- 导航 ---------------- */

function switchView(name) {
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  const [title, sub] = VIEW_META[name] || ["", ""];
  $("#pageTitle").textContent = title;
  $("#pageSub").textContent = sub;
  document.title = (title ? title + " · " : "") + "eNSP 拓扑控制台";
  if (name === "history" && typeof loadHistory === "function") loadHistory();
  if (name === "inspect" && !inspDevices.length && S.inspect) inspFromTopo(true);
  if (name === "ops" && typeof opsInit === "function") opsInit();
  if (name === "aiops" && typeof loadAiops === "function") loadAiops();
  if (name === "logs" && typeof logsInit === "function") logsInit();
  if (name === "inspect" && typeof loadScheduler === "function") loadScheduler();
}

$$(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

/* ---------------- 拓扑 ---------------- */

function renderTopo(data, name) {
  const inspect = data.inspect || data;
  if (!inspect || !inspect.devices) return;

  S.inspect = inspect;
  S.topo = data.path || S.topo;
  S.topoName = name || S.topoName;

  const devices = inspect.devices || [];
  const links = inspect.links || [];
  const ports = devices.map((d) => d.consolePort).filter((p) => typeof p === "number");
  const models = inspect.modelCounts || {};

  $("#statDevices").textContent = devices.length;
  $("#statModels").textContent = Object.entries(models).map(([m, n]) => `${m} × ${n}`).join(" · ") || "—";
  $("#statLinks").textContent = links.length;
  $("#statPorts").textContent = ports.length;
  $("#statPortRange").textContent = ports.length
    ? `${Math.min(...ports)} – ${Math.max(...ports)}`
    : "—";
  $("#statOnline").textContent = "—";
  $("#statOnlineHint").textContent = "点“探测在线”检测";

  const tbody = $("#deviceTable tbody");
  tbody.innerHTML = devices.map((d) => {
    const free = (d.portsFree || []).map(shortPort);
    let freeCell;
    if (!free.length) {
      freeCell = '<span class="none">无</span>';
    } else {
      const head = free.slice(0, 3);
      const rest = free.length - head.length;
      freeCell = head.map(esc).join("<br>");
      if (rest > 0) {
        freeCell += `<br><span class="more" title="${esc(free.join("  "))}">+${rest} 个</span>`;
      }
    }
    return `<tr>
      <td><span class="dev-name">${esc(d.name)}</span></td>
      <td><span class="dev-model">${esc(d.model)}</span></td>
      <td>${d.consolePort ? `<span class="port-badge">${d.consolePort}</span>` : '<span class="muted">—</span>'}</td>
      <td class="num">${d.portsUsed ?? 0}/${d.portsTotal ?? 0}</td>
      <td class="free-list">${freeCell}</td>
      <td><span class="state" data-dev="${esc(d.name)}"><i></i>未探测</span></td>
    </tr>`;
  }).join("");

  const lbody = $("#linkTable tbody");
  lbody.innerHTML = links.map((l) => `<tr>
    <td><span class="dev-name">${esc(l.from)}</span></td>
    <td class="mono">${esc(shortPort(l.fromPort))}</td>
    <td class="num muted">↔</td>
    <td><span class="dev-name">${esc(l.to)}</span></td>
    <td class="mono">${esc(shortPort(l.toPort))}</td>
    <td class="muted">${esc(l.lineType || "—")}</td>
  </tr>`).join("");

  $("#linkCount").textContent = `${links.length} 条`;

  $("#topoSummary").hidden = false;
  $("#topoDetail").hidden = false;
  $("#linkCard").hidden = links.length === 0;

  $("#topoChip").hidden = false;
  $("#topoChipName").textContent = S.topoName || "拓扑已载入";

  $("#topoImg").src = `/api/topo/preview?t=${Date.now()}`;
  setAlert("#topoAlert", "");
}

async function uploadTopo(file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".topo")) {
    const msg = `只支持 .topo 文件，你选的是 ${file.name}`;
    toast(msg, true);
    setAlert("#topoAlert", esc(msg), "err");
    return;
  }
  const form = new FormData();
  form.append("file", file);

  const btn = $("#btnPickTopo");
  const label = btn ? btn.textContent : "";
  if (btn) {
    btn.disabled = true;
    btn.textContent = "解析中…";
  }
  toast("正在解析拓扑…");

  try {
    const data = await api("/api/topo/upload", { method: "POST", body: form });
    renderTopo(data, data.name || file.name);
    toast(`已载入 ${data.inspect.devices.length} 台设备 / ${data.inspect.links.length} 条链路`);
  } catch (err) {
    setAlert("#topoAlert", `解析失败：${esc(err.message)}`, "err");
    toast(err.message, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = label || "选择文件";
    }
  }
}

function wireDropzone(zoneSel, inputSel, onFile) {
  const zone = $(zoneSel);
  const input = $(inputSel);

  zone.addEventListener("click", (e) => {
    if (e.target.closest("button") || e.target === input) return;
    input.click();
  });
  input.addEventListener("change", () => {
    if (input.files[0]) onFile(input.files[0]);
    input.value = "";
  });
  ["dragenter", "dragover"].forEach((ev) =>
    zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); })
  );
  ["dragleave", "drop"].forEach((ev) =>
    zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("over"); })
  );
  zone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file) onFile(file);
  });
}

wireDropzone("#topoDrop", "#topoFile", uploadTopo);
$("#btnPickTopo").addEventListener("click", (e) => { e.stopPropagation(); $("#topoFile").click(); });

/* ---------------- 探测在线 ---------------- */

async function probeDevices(names) {
  if (!S.inspect) { toast("先载入拓扑", true); return; }
  let devices = S.inspect.devices || [];
  if (names?.length) devices = devices.filter((d) => names.includes(d.name));

  try {
    const data = await api("/api/device/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devices }),
    });
    data.devices.forEach((r) => {
      S.online[r.name] = r.online;
      S.probe[r.name] = r.detail || "";
      S.identity[r.name] = r.modelMatched;
      S.applicable[r.name] = r.applicable !== false;
      S.mismatch[r.name] = r.identityMismatch === true;
    });

    $$("#deviceTable .state").forEach((el) => {
      const name = el.dataset.dev;
      if (name in S.online) {
        const on = S.online[name];
        let cls = on === true ? "on" : on === false ? "off" : "unknown";
        let text = on === true ? "在线" : on === false ? "离线" : "无法判定";
        if (S.applicable[name] === false) {
          cls = "off";
          text = "不适用";
        } else if (S.mismatch[name]) {
          cls = "mismatch";
          text = "不是本设备";
        }
        el.className = "state " + cls;
        el.title = S.probe[name] || "";
        el.innerHTML = `<i></i>${text}`;
      }
    });

    const unknown = data.unknownCount || 0;
    const mismatch = data.devices.filter((r) => r.identityMismatch === true).length;
    $("#statOnline").textContent = `${data.onlineCount}/${data.total}`;
    $("#statOnlineHint").textContent = mismatch
      ? `${mismatch} 台端口被其他拓扑设备占用`
      : unknown
        ? `另有 ${unknown} 台无法判定`
        : "console 直连 + 系统_MAC 身份核对";
    toast(
      `在线 ${data.onlineCount}/${data.total} 台` +
      (mismatch ? `，${mismatch} 台端口被其他拓扑设备占用` : "") +
      (unknown ? `，${unknown} 台无法判定` : "")
    );
  } catch (err) {
    toast(err.message, true);
  }
}

$("#btnProbe").addEventListener("click", () => probeDevices());

$("#btnValidate").addEventListener("click", async () => {
  if (!S.topo) { toast("先载入拓扑", true); return; }
  try {
    const r = await api("/api/topo/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: S.topo }),
    });
    const errors = r.errors || [];
    const warns = r.warnings || [];
    if (!errors.length && !warns.length) {
      setAlert("#topoAlert", "拓扑校验通过：无错误、无警告。", "ok");
    } else {
      const parts = [];
      if (errors.length) parts.push(`<strong>${errors.length} 个错误</strong><ul>${errors.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`);
      if (warns.length) parts.push(`<strong>${warns.length} 个提醒</strong><ul>${warns.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`);
      setAlert("#topoAlert", parts.join(""), errors.length ? "err" : "");
    }
  } catch (err) {
    setAlert("#topoAlert", `校验失败：${esc(err.message)}`, "err");
  }
});

$("#btnExportTopo").addEventListener("click", () => {
  if (!S.topo) {
    toast("先载入拓扑", true);
    return;
  }
  const a = document.createElement("a");
  a.href = `/api/topo/export?path=${encodeURIComponent(S.topo)}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast("已导出设备与链路清单");
});

$("#topoImg").addEventListener("click", () => {
  const src = $("#topoImg").src;
  if (!src) return;
  $("#lightboxImg").src = src;
  $("#lightbox").hidden = false;
});

$("#lightbox").addEventListener("click", () => {
  $("#lightbox").hidden = true;
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#lightbox").hidden) $("#lightbox").hidden = true;
});

/* ---------------- Excel ---------------- */

async function uploadExcel(file) {
  if (!file) return;
  if (!/\.(xlsx|xlsm)$/i.test(file.name)) {
    toast("只支持 .xlsx / .xlsm 文件", true);
    return;
  }
  const form = new FormData();
  form.append("file", file);
  toast("正在解析 Excel…");
  try {
    const data = await api("/api/excel/parse", { method: "POST", body: form });
    S.excel = data;
    S.selected = new Set(data.devices.filter((d) => d.commands.length).map((d) => d.name));
    renderExcel(data);
    toast(`识别 ${data.deviceCount} 台设备 / ${data.commandCount} 条命令`);
  } catch (err) {
    setAlert("#excelAlert", `解析失败：${esc(err.message)}`, "err");
    toast(err.message, true);
  }
}

function renderExcel(data) {
  const devices = data.devices || [];
  const ready = devices.filter((d) => d.commands.length).length;

  $("#xlsDevices").textContent = data.deviceCount;
  $("#xlsCommands").textContent = data.commandCount;
  $("#xlsSheets").textContent = (data.sheets || []).length;
  $("#xlsSheetNames").textContent = (data.sheets || []).map((s) => s.name).join(" · ") || "—";
  $("#xlsReady").textContent = ready;

  $("#excelSummary").hidden = false;
  $("#excelCard").hidden = false;

  const box = $("#excelDevices");
  box.innerHTML = devices.map((d) => {
    const inTopo = !S.inspect || (S.inspect.devices || []).some((x) => x.name === d.name);
    const checked = S.selected.has(d.name) ? "checked" : "";
    const cmds = d.commands || [];
    return `<div class="dev-row" data-dev="${esc(d.name)}">
      <input type="checkbox" class="pick" ${checked} ${cmds.length ? "" : "disabled"}>
      <div class="dev-row-main">
        <span class="dev-row-name">${esc(d.name)}</span>
        ${d.model ? `<span class="dev-model">${esc(d.model)}</span>` : ""}
        ${inTopo ? "" : '<span class="state off"><i></i>拓扑未找到</span>'}
      </div>
      <span class="cmd-count ${cmds.length ? "" : "zero"}">${cmds.length} 条</span>
      <button class="btn-toggle" data-toggle="${esc(d.name)}">${cmds.length ? "查看" : "空"}</button>
    </div>
    <div class="cmd-panel" data-panel="${esc(d.name)}">
      <textarea class="cmd-edit" data-cmd="${esc(d.name)}" spellcheck="false" placeholder="每行一条命令">${esc(cmds.join("\n"))}</textarea>
    </div>`;
  }).join("");

  $$("#excelDevices .pick").forEach((cb) => {
    cb.addEventListener("change", () => {
      const row = cb.closest(".dev-row");
      const name = row.dataset.dev;
      if (cb.checked) S.selected.add(name); else S.selected.delete(name);
    });
  });

  $$("#excelDevices .btn-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const panel = $(`[data-panel="${CSS.escape(btn.dataset.toggle)}"]`);
      panel.classList.toggle("open");
      btn.textContent = panel.classList.contains("open") ? "收起" : "查看";
    });
  });

  $$("#excelDevices [data-cmd]").forEach((ta) => {
    ta.addEventListener("input", () => {
      const dev = (S.excel?.devices || []).find((d) => d.name === ta.dataset.cmd);
      if (!dev) return;
      dev.commands = ta.value
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

      const panel = ta.closest(".cmd-panel");
      const row = panel ? panel.previousElementSibling : null;
      const countEl = row ? row.querySelector(".cmd-count") : null;
      if (countEl) {
        countEl.textContent = `${dev.commands.length} 条`;
        countEl.classList.toggle("zero", dev.commands.length === 0);
      }
      const cb = row ? row.querySelector(".pick") : null;
      if (cb && dev.commands.length && cb.disabled) {
        cb.disabled = false;
        cb.checked = true;
        S.selected.add(dev.name);
      }
    });
  });

  const missing = devices.filter((d) => S.inspect && !(S.inspect.devices || []).some((x) => x.name === d.name));
  const skipped = data.skippedSheets || [];
  const notes = [];
  if (missing.length) {
    notes.push(`有 ${missing.length} 台设备不在当前拓扑中：${missing.map((m) => esc(m.name)).join("、")}。下发前请核对设备名。`);
  }
  if (skipped.length) {
    notes.push(`已跳过非配置工作表：${skipped.map((s) => esc(s)).join("、")}（名称不含「设备 / 命令 / 配置」关键词）`);
  }
  setAlert("#excelAlert", notes.join("<br>"), missing.length ? "err" : "");
}

wireDropzone("#excelDrop", "#excelFile", uploadExcel);
$("#btnPickExcel").addEventListener("click", (e) => { e.stopPropagation(); $("#excelFile").click(); });

async function loadSampleExcel(silent = false) {
  try {
    const data = await api("/api/demo/excel");
    S.excel = data;
    S.selected = new Set(data.devices.filter((d) => d.commands.length).map((d) => d.name));
    renderExcel(data);
    if (!silent) toast(`已载入示例：${data.deviceCount} 台设备 / ${data.commandCount} 条命令`);
  } catch (err) {
    toast(err.message, true);
  }
}

$("#btnSampleExcel").addEventListener("click", (e) => {
  e.stopPropagation();
  loadSampleExcel(false);
});

$("#chkAll").addEventListener("change", (e) => {
  const on = e.target.checked;
  $$("#excelDevices .pick").forEach((cb) => {
    if (cb.disabled) return;
    cb.checked = on;
    const name = cb.closest(".dev-row").dataset.dev;
    if (on) S.selected.add(name); else S.selected.delete(name);
  });
});

$("#btnProbeExcel").addEventListener("click", () => {
  if (!S.excel) { toast("先导入 Excel", true); return; }
  probeDevices(S.excel.devices.map((d) => d.name));
});

$("#btnDeploy").addEventListener("click", async () => {
  if (!S.excel) return;
  if (!S.topo) { toast("先载入拓扑文件", true); return; }

  const configs = {};
  S.excel.devices.forEach((d) => {
    if (S.selected.has(d.name) && d.commands.length) configs[d.name] = d.commands.join("\n");
  });
  const names = Object.keys(configs);
  if (!names.length) { toast("没有可下发的设备", true); return; }

  const totalCmds = Object.values(configs).reduce(
    (n, text) => n + text.split("\n").filter(Boolean).length,
    0
  );
  const ok = window.confirm(
    `即将向 ${names.length} 台设备下发 ${totalCmds} 条命令：\n\n${names.join("、")}\n\n确认继续？`
  );
  if (!ok) return;

  const btn = $("#btnDeploy");
  btn.disabled = true;
  toast(`正在向 ${names.length} 台设备下发…`);
  try {
    const r = await api("/api/device/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ topo: S.topo, configs, concurrency: 4, includeResults: true }),
    });
    renderDeploy(r);
    toast(`完成：成功 ${r.succeeded} / ${r.deviceCount}`);
  } catch (err) {
    $("#deployCard").hidden = false;
    $("#deployMeta").textContent = "";
    $("#deployResult").innerHTML = `<div class="result-row"><span class="result-badge fail">失败</span><div class="result-body">${esc(err.message)}</div></div>`;
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

function renderDeploy(r) {
  $("#deployCard").hidden = false;
  $("#deployMeta").textContent = `${r.succeeded} 成功 / ${r.failed} 失败 · ${r.elapsedSeconds ?? "—"}s`;
  const rows = (r.devices || []).map((d) => {
    const ok = d.ok;
    const cmds = d.sent ?? d.commandCount ?? "";
    const err = d.error ? `<div class="result-err">${esc(d.error)}</div>` : "";
    const fails = (d.failures || []).slice(0, 4)
      .map((f) => `<div class="result-err">${esc(typeof f === "string" ? f : f.command || JSON.stringify(f))}</div>`)
      .join("");
    return `<div class="result-row">
      <span class="result-badge ${ok ? "" : "fail"}">${ok ? "成功" : "失败"}</span>
      <div class="result-body">
        <strong>${esc(d.device || d.name || "?")}</strong>
        ${cmds !== "" ? ` <code>${cmds} 条命令</code>` : ""}
        ${err}${fails}
      </div>
    </div>`;
  }).join("");
  $("#deployResult").innerHTML = rows || '<div class="result-row"><div class="result-body muted">没有返回结果</div></div>';
}

/* ---------------- 设备巡检 ---------------- */

const INSP_DEFAULT_COMMANDS = [
  "display version",
  "display cpu-usage",
  "display memory-usage",
  "display interface brief",
  "display transceiver diagnosis interface",
  "display temperature all",
];

let inspDevices = [];
let inspResult = null;

function inspRenderDevices() {
  const body = $("#inspDeviceBody");
  if (!inspDevices.length) {
    body.innerHTML =
      '<tr><td colspan="8" class="insp-empty">还没有设备。点「从拓扑载入」自动带出，或手动添加。</td></tr>';
    return;
  }

  body.innerHTML = inspDevices
    .map(
      (d, i) => `<tr data-idx="${i}">
      <td class="c-on"><input type="checkbox" class="i-on" ${d.enabled ? "checked" : ""}></td>
      <td><input class="i-name" value="${esc(d.name)}" placeholder="R1"></td>
      <td><input class="i-host mono-input" value="${esc(d.host)}" placeholder="127.0.0.1"></td>
      <td class="c-port"><input class="i-port mono-input" type="number" value="${d.port}" placeholder="2000"></td>
      <td class="c-proto"><select class="i-proto">
        <option value="telnet" ${d.protocol === "telnet" ? "selected" : ""}>Telnet</option>
        <option value="ssh" ${d.protocol === "ssh" ? "selected" : ""}>SSH</option>
      </select></td>
      <td><input class="i-user" value="${esc(d.username || "")}" placeholder="可选"></td>
      <td><input class="i-pass" type="password" value="${esc(d.password || "")}" placeholder="可选"></td>
      <td class="c-del"><button class="btn-row-del" title="删除">×</button></td>
    </tr>`
    )
    .join("");

  $$("#inspDeviceBody tr").forEach((tr) => {
    const idx = Number(tr.dataset.idx);
    const item = inspDevices[idx];

    $(".i-on", tr).addEventListener("change", (e) => {
      item.enabled = e.target.checked;
    });
    $(".i-name", tr).addEventListener("input", (e) => {
      item.name = e.target.value;
    });
    $(".i-host", tr).addEventListener("input", (e) => {
      item.host = e.target.value;
    });
    $(".i-port", tr).addEventListener("input", (e) => {
      item.port = Number(e.target.value) || 0;
    });
    $(".i-proto", tr).addEventListener("change", (e) => {
      item.protocol = e.target.value;
      const portEl = $(".i-port", tr);
      if (e.target.value === "ssh" && Number(portEl.value) >= 2000) {
        portEl.value = "22";
        item.port = 22;
      }
    });
    $(".i-user", tr).addEventListener("input", (e) => {
      item.username = e.target.value;
    });
    $(".i-pass", tr).addEventListener("input", (e) => {
      item.password = e.target.value;
    });
    $(".btn-row-del", tr).addEventListener("click", () => {
      inspDevices.splice(idx, 1);
      inspRenderDevices();
    });
  });
}

function inspFromTopo(silent = false) {
  const devices = S.inspect?.devices || [];
  if (!devices.length) {
    if (!silent) toast("先载入拓扑文件", true);
    return;
  }
  inspDevices = devices.map((d) => ({
    enabled: !!d.consolePort,
    name: d.name,
    host: "127.0.0.1",
    port: d.consolePort || 22,
    protocol: d.consolePort ? "telnet" : "ssh",
    username: "",
    password: "",
  }));
  inspRenderDevices();
  if (!silent) {
    toast(`已载入 ${inspDevices.length} 台设备，${inspDevices.filter((d) => d.enabled).length} 台可巡检`);
  }
}

$("#btnInspFromTopo").addEventListener("click", () => inspFromTopo(false));

$("#btnInspAddRow").addEventListener("click", () => {
  inspDevices.push({
    enabled: true,
    name: "",
    host: "127.0.0.1",
    port: 22,
    protocol: "ssh",
    username: "",
    password: "",
  });
  inspRenderDevices();
});

$("#btnInspResetCmd").addEventListener("click", () => {
  $("#inspCommands").value = INSP_DEFAULT_COMMANDS.join("\n");
  toast("已恢复默认命令");
});

function metricCell(item, key, fallbackUnit = "") {
  const metric = (item.metrics || []).find((m) => m.key === key);
  if (!metric || metric.value === null || metric.value === undefined || metric.value === "") {
    return '<span class="metric na">—</span>';
  }
  const unit = metric.unit || fallbackUnit;
  return `<span class="metric ${metric.level}">${esc(metric.value)}${unit ? `<span class="unit">${esc(unit)}</span>` : ""}</span>`;
}

function renderInspResult(result) {
  inspResult = result;
  $("#inspResultCard").hidden = false;

  const summary = result.summary || {};
  const time = String(result.finishedAt || "").replace("T", " ").slice(0, 19);
  $("#inspMeta").textContent =
    `${summary.succeeded}/${summary.total} 成功` +
    (summary.failed ? ` · ${summary.failed} 失败` : "") +
    (summary.warnCount ? ` · ${summary.warnCount} 项警告` : "") +
    (summary.critCount ? ` · ${summary.critCount} 项异常` : "") +
    ` · ${time}`;

  const body = $("#inspResultBody");
  body.innerHTML = (result.devices || [])
    .map((item, idx) => {
      const status = item.ok
        ? '<span class="state on"><i></i>成功</span>'
        : `<span class="state off" title="${esc(item.error || "")}"><i></i>失败</span>`;

      const up = (item.metrics || []).find((m) => m.key === "if_up")?.value;
      const down = (item.metrics || []).find((m) => m.key === "if_down")?.value;
      let ifCell = '<span class="metric na">—</span>';
      if (up !== null && up !== undefined) {
        ifCell = `<span class="metric">${up}<span class="unit">UP</span>${down > 0 ? ` / ${down}<span class="unit">DOWN</span>` : ""}</span>`;
      }

      const error = !item.ok && item.error
        ? `<div class="result-err" style="margin-top:2px">${esc(item.error)}</div>`
        : "";

      return `<tr>
        <td><span class="dev-name">${esc(item.device)}</span>${error}</td>
        <td>${status}</td>
        <td class="num">${metricCell(item, "cpu")}</td>
        <td class="num">${metricCell(item, "memory")}</td>
        <td class="num">${metricCell(item, "temperature")}</td>
        <td class="num">${metricCell(item, "rx_power")}</td>
        <td class="num">${metricCell(item, "tx_power")}</td>
        <td>${ifCell}</td>
        <td class="num muted">${item.elapsedMs ?? "—"}</td>
        <td><button class="btn-toggle" data-raw="${idx}">原始</button></td>
      </tr>`;
    })
    .join("");

  $$("#inspResultBody [data-raw]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.raw);
      const item = (inspResult.devices || [])[idx];
      if (!item) return;
      renderInspRaw(item);
      btn.textContent = "已展开";
    });
  });

  setAlert("#inspAlert", "");
}

function renderInspRaw(item) {
  const box = $("#inspRaw");
  box.hidden = false;
  const raws = item.raw || [];
  box.innerHTML =
    `<h4>${esc(item.device)} <span class="muted">${esc(item.host)}:${esc(item.port)} · ${esc(item.protocol)}</span></h4>` +
    (raws.length
      ? raws
          .map(
            (r) => `<div><pre><span class="raw-cmd">${esc(r.command)}</span>
${esc(r.output || "（无输出）")}${r.error ? `\n<span class="raw-err">${esc(r.error)}</span>` : ""}</pre></div>`
          )
          .join("")
      : '<div class="muted">没有采集到输出</div>');
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

$("#btnInspRun").addEventListener("click", async () => {
  const selected = inspDevices.filter((d) => d.enabled && d.name.trim() && d.host.trim());
  if (!selected.length) {
    toast("没有启用的设备，先载入或勾选", true);
    return;
  }
  const commands = $("#inspCommands").value
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!commands.length) {
    toast("巡检命令为空", true);
    return;
  }

  const btn = $("#btnInspRun");
  btn.disabled = true;
  const startedAt = Date.now();
  btn.textContent = "巡检中… 0s";
  const timer = setInterval(() => {
    btn.textContent = `巡检中… ${Math.round((Date.now() - startedAt) / 1000)}s`;
  }, 500);
  toast(`正在巡检 ${selected.length} 台设备…`);
  try {
    const result = await api("/api/inspect/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devices: selected.map((d) => ({
          name: d.name,
          host: d.host,
          port: Number(d.port),
          protocol: d.protocol,
          username: d.username,
          password: d.password,
        })),
        commands,
        concurrency: Number($("#inspConcurrency").value) || 4,
        timeout: Number($("#inspTimeout").value) || 20,
      }),
      timeout: 600000,
    });
    renderInspResult(result);
    const s = result.summary || {};
    toast(`巡检完成：${s.succeeded}/${s.total} 成功`);
    if (s.failed) {
      setAlert("#inspAlert", `有 ${s.failed} 台设备巡检失败，展开「原始」查看原因。`, "");
    }
  } catch (err) {
    setAlert("#inspAlert", `巡检失败：${esc(err.message)}`, "err");
    toast(err.message, true);
  } finally {
    clearInterval(timer);
    btn.disabled = false;
    btn.textContent = "开始巡检";
  }
});

function inspDownload(format, detail = 0) {
  if (!inspResult?.runId) {
    toast("先执行一次巡检", true);
    return;
  }
  const url = `/api/inspect/export?runId=${encodeURIComponent(inspResult.runId)}&format=${format}&detail=${detail}`;
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

$("#btnInspCsv").addEventListener("click", () => inspDownload("csv", 0));
$("#btnInspCsvDetail").addEventListener("click", () => inspDownload("csv", 1));
$("#btnInspJson").addEventListener("click", () => inspDownload("json", 0));

/* ---------------- 网络工具 ---------------- */

function errorBox(message) {
  return `<div class="alert err">${esc(message || "执行失败")}</div>`;
}

function metricCard(label, value, unit = "", cls = "") {
  const shown = value === null || value === undefined || value === "" ? "—" : value;
  return `<div class="tool-metric ${cls}">
    <div class="k">${esc(label)}</div>
    <div class="v">${esc(shown)}${unit ? `<small>${esc(unit)}</small>` : ""}</div>
  </div>`;
}

function renderSpeedResult(r) {
  if (!r.ok) return errorBox(r.error);
  return `<div class="tool-metrics">
      ${metricCard("下载带宽", r.mbps, "Mbps", "good")}
      ${metricCard("吞吐", r.mbPerSec, "MB/s")}
      ${metricCard("测试时长", r.durationSec, "s")}
      ${metricCard("首字节", r.firstByteMs ?? "—", "ms")}
    </div>
    <div class="muted" style="font-size:12px;line-height:1.7">
      目标：<span class="mono">${esc(r.url)}</span><br>
      共接收 ${(r.bytes / 1024 / 1024).toFixed(2)} MB / ${r.chunks} 个数据块
      ${r.partial ? "（连接提前结束，按已收数据统计）" : ""}
    </div>`;
}

function renderPingResult(r) {
  if (!r.ok) return errorBox(r.error);
  const cls = r.lossPercent === 0 ? "good" : r.received > 0 ? "warn" : "bad";
  const rows = (r.replies || [])
    .map(
      (x) => `<tr><td class="mono">${esc(x.from)}</td><td class="num">${x.bytes}</td>
        <td class="num">${x.timeMs}</td><td class="num">${x.ttl}</td></tr>`
    )
    .join("");
  return `<div class="tool-metrics">
      ${metricCard("丢包率", r.lossPercent, "%", cls)}
      ${metricCard("接收 / 发送", `${r.received} / ${r.sent}`)}
      ${metricCard("平均延迟", r.rtt ? r.rtt.avg : "—", "ms")}
      ${metricCard("最小 / 最大", r.rtt ? `${r.rtt.min} / ${r.rtt.max}` : "—", "ms")}
    </div>
    ${rows
      ? `<div class="table-wrap"><table class="tbl"><thead><tr>
          <th>来自</th><th class="num">字节</th><th class="num">时间(ms)</th><th class="num">TTL</th>
        </tr></thead><tbody>${rows}</tbody></table></div>`
      : '<div class="muted">没有任何回包，目标可能不可达或被防火墙拦截。</div>'}
    <details class="tool-raw"><summary>原始输出</summary><pre>${esc(r.raw || "")}</pre></details>`;
}

function renderTraceResult(r) {
  if (!r.ok) return errorBox(r.error);
  const rows = (r.hops || [])
    .map(
      (h) => `<tr>
        <td class="num">${h.hop}</td>
        <td class="mono">${h.ip ? esc(h.ip) : '<span class="muted">* * *</span>'}</td>
        <td class="num">${h.timesMs && h.timesMs.length ? h.timesMs.join(" / ") + " ms" : "—"}</td>
      </tr>`
    )
    .join("");
  return `<div class="tool-metrics">
      ${metricCard("总跳数", r.hopCount)}
      ${metricCard("是否到达", r.reached ? "是" : "否", "", r.reached ? "good" : "warn")}
      ${metricCard("耗时", r.elapsedMs, "ms")}
    </div>
    <div class="table-wrap"><table class="tbl"><thead><tr>
      <th class="num">跳</th><th>地址</th><th class="num">时延</th>
    </tr></thead><tbody>${rows}</tbody></table></div>
    <details class="tool-raw"><summary>原始输出</summary><pre>${esc(r.raw || "")}</pre></details>`;
}

function renderPortResult(r) {
  if (!r.ok) return errorBox(r.error);
  const rows = (r.open || [])
    .map(
      (p) => `<tr><td><span class="port-chip">${p.port}</span></td>
        <td>${esc(p.service || "—")}</td></tr>`
    )
    .join("");
  return `<div class="tool-metrics">
      ${metricCard("扫描端口", r.scanned)}
      ${metricCard("开放", r.openCount, "个", r.openCount ? "warn" : "good")}
      ${metricCard("耗时", r.elapsedMs, "ms")}
    </div>
    ${r.openCount
      ? `<div class="table-wrap"><table class="tbl"><thead><tr><th>端口</th><th>常见服务</th></tr></thead>
         <tbody>${rows}</tbody></table></div>`
      : '<div class="alert">扫描完成，没有发现开放的 TCP 端口。</div>'}`;
}

function renderDnsResult(r) {
  if (!r.answers || !r.answers.length) {
    return `<div class="alert ${r.status === "NXDOMAIN" ? "" : "err"}">
      ${esc(r.error || `查询返回 ${r.status}，没有记录`)}</div>`;
  }
  const rows = r.answers
    .map(
      (a) => `<tr><td class="mono">${esc(a.name)}</td><td>${esc(a.type)}</td>
        <td class="mono">${esc(a.value)}</td><td class="num">${a.ttl}</td></tr>`
    )
    .join("");
  return `<div class="tool-metrics">
      ${metricCard("状态", r.status, "", r.status === "NOERROR" ? "good" : "warn")}
      ${metricCard("记录数", r.answerCount)}
      ${metricCard("DNS 服务器", r.server)}
      ${metricCard("耗时", r.elapsedMs, "ms")}
    </div>
    <div class="table-wrap"><table class="tbl"><thead><tr>
      <th>名称</th><th>类型</th><th>值</th><th class="num">TTL</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderSubnetResult(r, mode) {
  if (!r.ok) return errorBox(r.error);

  if (mode === "split") {
    const rows = r.subnets
      .map(
        (s) => `<tr><td class="mono">${esc(s.cidr)}</td><td class="mono">${esc(s.network)}</td>
          <td class="mono">${esc(s.broadcast)}</td>
          <td class="mono">${s.firstHost ? `${esc(s.firstHost)} - ${esc(s.lastHost)}` : "—"}</td>
          <td class="num">${s.hostCount}</td></tr>`
      )
      .join("");
    return `<div class="tool-metrics">
        ${metricCard("父网段", r.parent)}
        ${metricCard("新掩码", "/" + r.newPrefix)}
        ${metricCard("子网总数", r.totalSubnets, "个", "good")}
        ${metricCard("已列出", r.returned)}
      </div>
      <div class="table-wrap"><table class="tbl"><thead><tr>
        <th>子网</th><th>网络地址</th><th>广播地址</th><th>可用范围</th><th class="num">主机数</th>
      </tr></thead><tbody>${rows}</tbody></table></div>
      ${r.truncated ? `<div class="alert" style="margin-top:12px">子网数量超过 ${r.returned} 个，仅列出前 ${r.returned} 个。</div>` : ""}`;
  }

  const rows = [
    ["网络地址", r.network],
    ["广播地址", r.broadcast || "—"],
    ["子网掩码", `${r.netmask}  (/${r.prefix})`],
    ["通配符掩码", r.wildcard],
    ["可用地址范围", r.firstHost ? `${r.firstHost} - ${r.lastHost}` : "—"],
    ["可用主机数", r.hostCount],
    ["地址总数", r.totalAddresses],
    ["私有地址", r.isPrivate ? "是" : "否"],
  ]
    .map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(v)}</span></div>`)
    .join("");

  return `<div class="tool-metrics">
      ${metricCard("网络地址", r.cidr)}
      ${metricCard("可用主机", r.hostCount, "个", "good")}
      ${metricCard("掩码", "/" + r.prefix)}
    </div>
    <div class="env-group">${rows}</div>
    ${r.binary && r.binary.ip
      ? `<div class="mono" style="margin-top:12px;font-size:11.5px;color:#6b7684;line-height:1.8">
          IP&nbsp;&nbsp;: ${esc(r.binary.ip)}<br>掩码: ${esc(r.binary.mask)}</div>`
      : ""}`;
}

function renderPcapResult(r) {
  if (!r.ok) return errorBox(r.error);
  const protoRows = Object.entries(r.protocols || {})
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td class="num">${v}</td>
      <td class="num">${r.packetCount ? ((v / r.packetCount) * 100).toFixed(1) : 0}%</td></tr>`)
    .join("");
  const convRows = (r.topConversations || [])
    .map(
      (c) => `<tr><td class="mono">${esc(c.session)}</td><td>${esc(c.protocol)}</td>
        <td class="num">${c.packets}</td><td class="num">${(c.bytes / 1024).toFixed(1)} KB</td></tr>`
    )
    .join("");
  const srcTop = (r.topSources || [])
    .slice(0, 5)
    .map((x) => `${esc(x.ip)} (${x.packets})`)
    .join(" · ");

  return `<div class="tool-metrics">
      ${metricCard("数据包", r.packetCount)}
      ${metricCard("总流量", (r.byteCount / 1024 / 1024).toFixed(2), "MB")}
      ${metricCard("持续时间", r.durationSec, "s")}
      ${metricCard("会话数", (r.topConversations || []).length + "+")}
    </div>
    ${r.startTime ? `<div class="muted" style="font-size:12px;margin-bottom:12px">抓包时间：${esc(r.startTime)} → ${esc(r.endTime)}</div>` : ""}
    <div class="table-wrap" style="margin-bottom:14px"><table class="tbl"><thead><tr>
      <th>协议</th><th class="num">包数</th><th class="num">占比</th>
    </tr></thead><tbody>${protoRows}</tbody></table></div>
    <h4 style="margin:0 0 8px;font-size:12.5px">Top 会话</h4>
    <div class="table-wrap"><table class="tbl"><thead><tr>
      <th>会话</th><th>协议</th><th class="num">包数</th><th class="num">流量</th>
    </tr></thead><tbody>${convRows}</tbody></table></div>
    ${srcTop ? `<div class="muted" style="font-size:12px;margin-top:12px">Top 源 IP：${srcTop}</div>` : ""}`;
}

const TOOL_DEFS = {
  speed: {
    title: "下载测速",
    action: "开始测速",
    endpoint: "/api/tools/speedtest",
    hint: "默认用 Cloudflare 测速点，可换成内网文件地址",
    fields: [
      {
        key: "url",
        label: "测速地址（http/https）",
        wide: true,
        value: "https://speed.cloudflare.com/__down?bytes=25000000",
      },
      { key: "duration", label: "测试时长（秒）", type: "number", value: 6, min: 2, max: 30 },
    ],
    render: (r) => renderSpeedResult(r),
  },

  portscan: {
    title: "端口扫描",
    action: "启动扫描",
    endpoint: "/api/tools/portscan",
    hint: "最多 2048 个端口，超出自动截断",
    fields: [
      { key: "host", label: "目标地址", value: "127.0.0.1", placeholder: "192.168.1.1" },
      {
        key: "preset",
        label: "端口预设",
        type: "select",
        value: "common",
        options: [
          { value: "common", label: "常用端口（22 个）" },
          { value: "web", label: "Web 服务" },
          { value: "网络设备", label: "网络设备" },
          { value: "数据库", label: "数据库" },
          { value: "全部常用", label: "1-1024" },
          { value: "", label: "自定义（用下面的输入）" },
        ],
      },
      { key: "ports", label: "自定义端口", value: "22,80,443", placeholder: "22,80,8000-8100" },
      { key: "timeout", label: "单端口超时（秒）", type: "number", value: 1, min: 0.2, max: 10 },
      { key: "concurrency", label: "并发数", type: "number", value: 200, min: 1, max: 512 },
    ],
    render: (r) => renderPortResult(r),
  },

  ping: {
    title: "Ping 测试",
    action: "启动测试",
    endpoint: "/api/tools/ping",
    hint: "调用系统 ping，ICMP 可能被防火墙拦截",
    fields: [
      { key: "host", label: "目标地址", value: "127.0.0.1" },
      { key: "count", label: "次数", type: "number", value: 4, min: 1, max: 20 },
      { key: "timeoutMs", label: "单次超时（毫秒）", type: "number", value: 1000, min: 100, max: 10000 },
      { key: "size", label: "包大小（字节）", type: "number", value: 32, min: 1, max: 65500 },
    ],
    render: (r) => renderPingResult(r),
  },

  subnet: {
    title: "IPv4 子网划分",
    action: "计算",
    endpoint: "/api/tools/subnet",
    secondary: { action: "按新掩码划分", endpoint: "/api/tools/subnet-split" },
    hint: "输入可以是 192.168.1.0/24 或 192.168.1.10/24",
    fields: [
      { key: "cidr", label: "IP / 网段", wide: true, value: "192.168.10.0/24", placeholder: "192.168.1.0/24" },
      { key: "newPrefix", label: "划分后的掩码长度", type: "number", value: 26, min: 1, max: 32 },
    ],
    render: (r, mode) => renderSubnetResult(r, mode),
  },

  traceroute: {
    title: "路由追踪",
    action: "启动追踪",
    endpoint: "/api/tools/traceroute",
    hint: "使用 tracert -d，不解析域名",
    fields: [
      { key: "host", label: "目标地址", value: "127.0.0.1" },
      { key: "maxHops", label: "最大跳数", type: "number", value: 16, min: 1, max: 64 },
      { key: "timeoutMs", label: "单跳超时（毫秒）", type: "number", value: 1000, min: 100, max: 5000 },
    ],
    render: (r) => renderTraceResult(r),
  },

  dns: {
    title: "DNS 查询",
    action: "启动查询",
    endpoint: "/api/tools/dns",
    hint: "默认走阿里 DNS 223.5.5.5",
    fields: [
      { key: "name", label: "域名", wide: true, value: "www.baidu.com", placeholder: "example.com" },
      {
        key: "type",
        label: "记录类型",
        type: "select",
        value: "A",
        options: ["A", "AAAA", "CNAME", "MX", "TXT", "NS"].map((t) => ({ value: t, label: t })),
      },
      { key: "server", label: "DNS 服务器", value: "223.5.5.5" },
    ],
    render: (r) => renderDnsResult(r),
  },

  pcap: {
    title: "抓包分析",
    action: "上传并分析",
    endpoint: "/api/tools/pcap",
    multipart: true,
    hint: "支持经典 pcap（eNSP / Wireshark 导出），最大 80MB",
    fields: [
      { key: "file", label: "选择 pcap 文件", type: "file", wide: true, accept: ".pcap,.cap" },
    ],
    render: (r) => renderPcapResult(r),
  },
};

let currentTool = null;

function toolFieldHtml(field) {
  const wide = field.wide ? " wide" : "";
  if (field.type === "select") {
    const opts = (field.options || [])
      .map(
        (o) =>
          `<option value="${esc(o.value)}" ${o.value === field.value ? "selected" : ""}>${esc(o.label)}</option>`
      )
      .join("");
    return `<div class="tool-field${wide}"><label>${esc(field.label)}</label>
      <select data-key="${field.key}">${opts}</select></div>`;
  }
  if (field.type === "file") {
    return `<div class="tool-field${wide}"><label>${esc(field.label)}</label>
      <input type="file" data-key="${field.key}" accept="${field.accept || ""}"></div>`;
  }
  const attrs = [
    field.min !== undefined ? `min="${field.min}"` : "",
    field.max !== undefined ? `max="${field.max}"` : "",
    field.placeholder ? `placeholder="${esc(field.placeholder)}"` : "",
  ]
    .filter(Boolean)
    .join(" ");
  return `<div class="tool-field${wide}"><label>${esc(field.label)}</label>
    <input data-key="${field.key}" type="${field.type || "text"}" value="${esc(field.value ?? "")}" ${attrs}></div>`;
}

function openTool(key) {
  const def = TOOL_DEFS[key];
  if (!def) return;
  currentTool = key;
  $("#toolTitle").textContent = def.title;
  $("#toolBody").innerHTML = `
    <div class="tool-form" id="toolForm">
      ${def.fields.map(toolFieldHtml).join("")}
      <div class="tool-actions">
        <button class="btn primary" id="toolRun">${esc(def.action)}</button>
        ${def.secondary ? `<button class="btn" id="toolRun2">${esc(def.secondary.action)}</button>` : ""}
        <span class="tool-hint">${esc(def.hint || "")}</span>
      </div>
    </div>
    <div class="tool-result" id="toolResult"></div>`;

  $("#toolRun").addEventListener("click", () => runTool(def.endpoint, "primary"));
  if (def.secondary) {
    $("#toolRun2").addEventListener("click", () => runTool(def.secondary.endpoint, "split"));
  }
  $("#toolModal").hidden = false;
}

function closeTool() {
  $("#toolModal").hidden = true;
  currentTool = null;
}

function collectToolValues() {
  const values = {};
  $$("#toolBody [data-key]").forEach((el) => {
    const key = el.dataset.key;
    if (el.type === "file") {
      if (el.files && el.files[0]) values[key] = el.files[0];
    } else if (el.type === "number") {
      const n = Number(el.value);
      values[key] = Number.isFinite(n) ? n : 0;
    } else {
      values[key] = el.value;
    }
  });
  return values;
}

async function runTool(endpoint, mode) {
  const def = TOOL_DEFS[currentTool];
  if (!def) return;

  const box = $("#toolResult");
  const btn = $("#toolRun");
  if (btn) btn.disabled = true;
  box.innerHTML = '<div class="tool-loading"><span class="spinner"></span>执行中，请稍候…</div>';

  try {
    const values = collectToolValues();
    let data;
    if (def.multipart) {
      if (!values.file) throw new Error("请先选择文件");
      const form = new FormData();
      form.append("file", values.file);
      data = await api(endpoint, { method: "POST", body: form });
    } else {
      data = await api(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
    }
    box.innerHTML = def.render(data, mode);
  } catch (err) {
    box.innerHTML = errorBox(err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

$$("#toolGrid .tool-card").forEach((card) => {
  card.addEventListener("click", () => openTool(card.dataset.tool));
});

$("#toolClose").addEventListener("click", closeTool);
$$("#toolModal [data-close]").forEach((el) => el.addEventListener("click", closeTool));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#toolModal").hidden) closeTool();
});

/* ---------------- 配置运维 ---------------- */

let opsTab = "backup";
let backupDevices = [];
let matrixDevices = [];
let backupFiles = [];

function switchOpsTab(name) {
  opsTab = name;
  $$("#opsTabs .ops-tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".ops-panel").forEach((p) => p.classList.toggle("active", p.id === "ops-" + name));
  if (name === "backup" || name === "diff") loadBackups();
}

$$("#opsTabs .ops-tab").forEach((btn) => {
  btn.addEventListener("click", () => switchOpsTab(btn.dataset.tab));
});

function opsDevicesFromTopo(kind, silent = false) {
  const devices = S.inspect?.devices || [];
  if (!devices.length) {
    if (!silent) toast("先载入拓扑文件", true);
    return;
  }
  const list = devices
    .filter((d) => d.consolePort)
    .map((d) => ({
      enabled: true,
      name: d.name,
      host: "127.0.0.1",
      port: d.consolePort,
      username: "",
      password: "",
    }));

  if (kind === "backup") backupDevices = list;
  else matrixDevices = list;
  renderOpsDevices(kind);
  if (!silent) toast(`已载入 ${list.length} 台设备`);
}

function renderOpsDevices(kind) {
  const list = kind === "backup" ? backupDevices : matrixDevices;
  const body = kind === "backup" ? $("#backupDeviceBody") : $("#matrixDeviceBody");
  if (!body) return;

  if (!list.length) {
    body.innerHTML = '<tr><td colspan="6" class="insp-empty">点上方按钮从拓扑载入设备</td></tr>';
    return;
  }

  body.innerHTML = list
    .map(
      (d, i) => `<tr data-idx="${i}">
      <td class="c-on"><input type="checkbox" class="o-on" ${d.enabled ? "checked" : ""}></td>
      <td><input class="o-name" value="${esc(d.name)}"></td>
      <td><input class="o-host mono-input" value="${esc(d.host)}"></td>
      <td class="c-port"><input class="o-port mono-input" type="number" value="${d.port}"></td>
      <td><input class="o-user" value="${esc(d.username || "")}" placeholder="可选"></td>
      <td><input class="o-pass" type="password" value="${esc(d.password || "")}" placeholder="可选"></td>
    </tr>`
    )
    .join("");

  $$("tr", body).forEach((tr) => {
    const idx = Number(tr.dataset.idx);
    const item = list[idx];
    if (!item) return;
    $(".o-on", tr).addEventListener("change", (e) => {
      item.enabled = e.target.checked;
    });
    $(".o-name", tr).addEventListener("input", (e) => {
      item.name = e.target.value;
    });
    $(".o-host", tr).addEventListener("input", (e) => {
      item.host = e.target.value;
    });
    $(".o-port", tr).addEventListener("input", (e) => {
      item.port = Number(e.target.value) || 0;
    });
    $(".o-user", tr).addEventListener("input", (e) => {
      item.username = e.target.value;
    });
    $(".o-pass", tr).addEventListener("input", (e) => {
      item.password = e.target.value;
    });
  });
}

function collectOpsDevices(kind) {
  const list = kind === "backup" ? backupDevices : matrixDevices;
  return list
    .filter((d) => d.enabled && d.name.trim() && d.host.trim())
    .map((d) => ({
      name: d.name,
      host: d.host,
      port: Number(d.port),
      username: d.username,
      password: d.password,
    }));
}

$("#btnBackupFromTopo").addEventListener("click", () => opsDevicesFromTopo("backup"));
$("#btnMatrixFromTopo").addEventListener("click", () => opsDevicesFromTopo("matrix"));

$("#btnBackupRun").addEventListener("click", async () => {
  const devices = collectOpsDevices("backup");
  if (!devices.length) {
    toast("没有启用的设备", true);
    return;
  }

  const btn = $("#btnBackupRun");
  btn.disabled = true;
  const startedAt = Date.now();
  const timer = setInterval(() => {
    btn.textContent = `备份中… ${Math.round((Date.now() - startedAt) / 1000)}s`;
  }, 500);
  $("#backupMeta").textContent = "";

  try {
    const r = await api("/api/backup/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devices,
        concurrency: Number($("#backupConcurrency").value) || 4,
      }),
      timeout: 300000,
    });
    $("#backupMeta").textContent = `成功 ${r.succeeded}/${r.deviceCount} · ${r.stamp}`;
    const failed = (r.devices || []).filter((d) => !d.ok);
    if (failed.length) {
      setAlert(
        "#opsAlert",
        `${failed.length} 台失败：${failed.map((d) => `${esc(d.device)}（${esc(d.error || "未知")}）`).join("；")}`,
        "err"
      );
    } else {
      setAlert("#opsAlert", "");
    }
    await loadBackups();
    toast(`已保存 ${r.succeeded} 份配置`);
  } catch (err) {
    setAlert("#opsAlert", `备份失败：${esc(err.message)}`, "err");
    toast(err.message, true);
  } finally {
    clearInterval(timer);
    btn.disabled = false;
    btn.textContent = "开始备份";
  }
});

async function loadBackups() {
  try {
    const r = await api("/api/backup/list");
    backupFiles = [];
    (r.folders || []).forEach((folder) => {
      (folder.files || []).forEach((file) => {
        backupFiles.push({ ...file, stamp: folder.stamp });
      });
    });
    renderBackups(r.folders || []);
    fillDiffSelects();
  } catch (err) {
    /* 没有备份是正常的 */
  }
}

function renderBackups(folders) {
  const box = $("#backupList");
  if (!box) return;
  if (!folders.length) {
    box.innerHTML = '<div class="empty-state">还没有备份</div>';
    return;
  }

  box.innerHTML = folders
    .map((folder, i) => {
      const label = folder.stamp.replace(
        /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/,
        "$1-$2-$3 $4:$5:$6"
      );
      const files = folder.files
        .map(
          (f) => `<div class="backup-file">
            <button class="lnk" data-path="${esc(f.path)}" data-name="${esc(f.name)}">${esc(f.name)}</button>
            <span class="sz">${(f.bytes / 1024).toFixed(1)} KB</span>
          </div>`
        )
        .join("");
      return `<div class="backup-folder">
        <div class="backup-head ${i === 0 ? "open" : ""}" data-folder="${i}">
          <span class="backup-caret">▶</span>
          <span class="backup-time">${esc(label)}</span>
          <span class="backup-count">${folder.files.length} 台</span>
        </div>
        <div class="backup-files ${i === 0 ? "open" : ""}" data-files="${i}">${files}</div>
      </div>`;
    })
    .join("");

  $$("#backupList .backup-head").forEach((head) => {
    head.addEventListener("click", () => {
      head.classList.toggle("open");
      $(`[data-files="${head.dataset.folder}"]`)?.classList.toggle("open");
    });
  });

  $$("#backupList .lnk").forEach((btn) => {
    btn.addEventListener("click", () => previewBackup(btn.dataset.path, btn.dataset.name));
  });
}

async function previewBackup(path, name) {
  try {
    const data = await api(`/api/backup/file?path=${encodeURIComponent(path)}`);
    $("#toolTitle").textContent = `${name} · ${data.lines} 行`;
    $("#toolBody").innerHTML = `<pre style="max-height:62vh;overflow:auto;background:#1d2430;color:#dbe4f0;padding:14px;border-radius:8px;font-family:var(--mono);font-size:11.5px;line-height:1.75;margin:0">${esc(data.text)}</pre>`;
    $("#toolModal").hidden = false;
  } catch (err) {
    toast(err.message, true);
  }
}

function fillDiffSelects() {
  const selA = $("#diffA");
  const selB = $("#diffB");
  if (!selA || !selB) return;

  if (!backupFiles.length) {
    selA.innerHTML = '<option value="">（暂无备份）</option>';
    selB.innerHTML = '<option value="">（暂无备份）</option>';
    return;
  }

  const options = backupFiles
    .map(
      (f) =>
        `<option value="${esc(f.path)}">${esc(f.device)} · ${esc(f.stamp)}</option>`
    )
    .join("");
  selA.innerHTML = options;
  selB.innerHTML = options;
  selA.selectedIndex = 0;
  selB.selectedIndex = Math.max(0, backupFiles.length - 1);
}

$("#btnBackupRefresh").addEventListener("click", loadBackups);
$("#btnDiffRefresh").addEventListener("click", loadBackups);

$("#btnDiffRun").addEventListener("click", async () => {
  const a = $("#diffA").value;
  const b = $("#diffB").value;
  if (!a || !b) {
    toast("先选择两个版本", true);
    return;
  }
  if (a === b) {
    toast("两次选的是同一个文件", true);
    return;
  }

  const btn = $("#btnDiffRun");
  btn.disabled = true;
  try {
    const r = await api(
      `/api/backup/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`,
      { timeout: 60000 }
    );
    renderDiff(r);
  } catch (err) {
    setAlert("#opsAlert", `对比失败：${esc(err.message)}`, "err");
  } finally {
    btn.disabled = false;
  }
});

function renderDiff(r) {
  $("#diffResultCard").hidden = false;
  $("#diffMeta").textContent = r.same
    ? "两份配置完全一致"
    : `+${r.added} 行 / -${r.removed} 行`;

  if (r.same) {
    $("#diffView").innerHTML = '<div class="empty-state">没有差异</div>';
    return;
  }

  const marks = {
    add: ["+", "add"],
    del: ["-", "del"],
    hunk: ["", "hunk"],
    ctx: [" ", ""],
    meta: ["", "meta"],
  };
  $("#diffView").innerHTML = r.rows
    .map((row) => {
      const [mark, cls] = marks[row.type] || [" ", ""];
      return `<div class="diff-row ${cls}"><span class="mark">${mark}</span><span>${esc(row.text)}</span></div>`;
    })
    .join("");
}

function parseTargets(text) {
  return String(text || "")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split("=");
      if (parts.length === 2) return { label: parts[0].trim(), ip: parts[1].trim() };
      return { label: line, ip: line };
    });
}

$("#btnMatrixRun").addEventListener("click", async () => {
  const devices = collectOpsDevices("matrix");
  if (!devices.length) {
    toast("没有启用的设备", true);
    return;
  }
  const targets = parseTargets($("#matrixTargets").value);
  if (!targets.length) {
    toast("请填写目标地址", true);
    return;
  }
  if (devices.length * targets.length > 64) {
    toast(`设备 ${devices.length} × 目标 ${targets.length} = ${devices.length * targets.length}，超过 64 次上限`, true);
    return;
  }

  const btn = $("#btnMatrixRun");
  btn.disabled = true;
  const startedAt = Date.now();
  const timer = setInterval(() => {
    btn.textContent = `测试中… ${Math.round((Date.now() - startedAt) / 1000)}s`;
  }, 500);

  try {
    const r = await api("/api/matrix/ping", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devices, targets, concurrency: 4 }),
      timeout: 300000,
    });
    renderMatrix(r);
  } catch (err) {
    setAlert("#opsAlert", `测试失败：${esc(err.message)}`, "err");
  } finally {
    clearInterval(timer);
    btn.disabled = false;
    btn.textContent = "开始测试";
  }
});

function renderMatrix(r) {
  $("#matrixResultCard").hidden = false;
  $("#matrixMeta").textContent = `可达 ${r.reachable}/${r.total} · ${r.deviceCount} 台 × ${r.targetCount} 个目标`;

  const head = `<thead><tr><th>源 \\ 目标</th>${r.targets
    .map((t) => `<th>${esc(t.label)}<span class="sub">${esc(t.ip)}</span></th>`)
    .join("")}</tr></thead>`;

  const body = r.rows
    .map(
      (row) => `<tr><td>${esc(row.device)}</td>${row.cells
        .map((c) => {
          if (c.ok === true) return '<td><span class="matrix-cell ok">✓</span></td>';
          if (c.ok === false)
            return `<td><span class="matrix-cell bad" title="${esc(c.error || "")}">✕</span></td>`;
          return `<td><span class="matrix-cell na" title="${esc(c.error || "")}">?</span></td>`;
        })
        .join("")}</tr>`
    )
    .join("");

  $("#matrixTable").innerHTML = head + `<tbody>${body}</tbody>`;
}

function opsInit() {
  if (!backupDevices.length && S.inspect) opsDevicesFromTopo("backup", true);
  if (!matrixDevices.length && S.inspect) opsDevicesFromTopo("matrix", true);
  loadBackups();
}

/* ---------------- 智能运维 ---------------- */

const AIO_GRADE = { A: "健康", B: "良好", C: "一般", D: "危险" };
let aioLastData = null;

async function loadAiops() {
  try {
    const data = await api("/api/aiops/overview");
    renderAiops(data);
  } catch (err) {
    toast(err.message, true);
  }
}

function aioSpark(samples) {
  if (!samples || samples.length < 2) return "—";
  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const span = max - min || 1;
  return `<span class="spark">${samples.slice(-8).map((v) => {
    const h = 3 + Math.round(((v - min) / span) * 15);
    return `<i style="height:${h}px" title="${esc(String(v))}"></i>`;
  }).join("")}</span>`;
}

function renderAiops(d) {
  aioLastData = d;
  const hasRun = d.dataSource === "inspection" && (d.assets || []).some((a) => a.score !== null);
  $("#aioStats").hidden = !hasRun;
  $("#aioEmpty").hidden = hasRun;
  $("#aioScoreCard").hidden = !hasRun;
  $("#aioEventCard").hidden = !hasRun;
  $("#aioTrendCard").hidden = !hasRun;
  $("#aioComplianceCard").hidden = !hasRun;

  if (!hasRun) {
    $("#aioSummary").hidden = true;
    $("#aioDataWarn").hidden = true;
    return;
  }

  const c = d.counts || {};
  $("#aioScore").textContent = d.overallScore ?? "—";
  $("#aioGradeHint").textContent = d.overallGrade
    ? `${d.overallGrade} 级 · ${AIO_GRADE[d.overallGrade] || ""}`
    : "—";
  $("#aioP1").textContent = c.p1 ?? 0;
  $("#aioP2").textContent = c.p2 ?? 0;
  $("#aioOnline").textContent = `${c.online ?? 0}/${c.reachableChecked ?? 0}`;
  $("#aioRunMeta").textContent = d.runFinishedAt
    ? `巡检 ${String(d.runFinishedAt).replace("T", " ").slice(5, 16)}`
    : "—";

  const sum = $("#aioSummary");
  sum.hidden = false;
  sum.textContent = d.summary || "";

  if ((d.mismatches || []).length) {
    const list = d.mismatches.slice(0, 4).map((m) =>
      `${esc(m.device)}（拓扑 ${esc(m.topology)} / 实检 ${esc(m.inspected)}）`).join("、");
    setAlert("#aioDataWarn",
      `<b>数据一致性提示</b><br>${d.mismatches.length} 台设备的巡检型号与当前拓扑不符：${list}。` +
      `通常是 eNSP 里运行的仍是上一个拓扑。已跳过拓扑关联与根因传播，评分仍基于实检数据。`);
  } else {
    setAlert("#aioDataWarn", "");
  }

  const tbody = $("#aioDeviceTable tbody");
  tbody.innerHTML = (d.assets || []).map((a) => {
    const grade = a.grade || "—";
    const issues = (a.issues || []).slice(0, 3).map((i) => esc(i.label + "：" + i.message)).join("<br>") || '<span class="muted">无异常</span>';
    const trend = a.trends && a.trends.length
      ? aioSpark(a.trends[0].samples)
      : '<span class="muted">—</span>';
    return `<tr>
      <td><span class="dev-name">${esc(a.name)}</span></td>
      <td><span class="dev-model">${esc(a.model || "—")}</span></td>
      <td class="num"><span class="score-pill ${String(grade).toLowerCase()}">${a.score ?? "—"}</span></td>
      <td>${grade === "—" ? "—" : `${grade} · ${AIO_GRADE[grade] || ""}`}</td>
      <td class="aio-issues">${issues}</td>
      <td>${trend}</td>
    </tr>`;
  }).join("");

  $("#aioEventMeta").textContent = `${(d.events || []).length} 项 · P1 ${c.p1 || 0} / P2 ${c.p2 || 0} / P3 ${c.p3 || 0} / P4 ${c.p4 || 0}`;
  $("#aioEvents").innerHTML = (d.events || []).map((e) => {
    const sev = String(e.severity || "P4").toLowerCase();
    const affected = (e.affected || []).length ? ` · 影响 ${esc(e.affected.join("、"))}` : "";
    const evidence = (e.evidence || []).map((x) => `<li>${esc(x)}</li>`).join("");
    const status = e.status === "ack"
      ? '<span class="evt-status ack">已确认</span>'
      : e.status === "ignored"
        ? '<span class="evt-status ignored">已忽略</span>'
        : "";
    return `<div class="evt ${sev}" data-evt="${esc(e.id)}">
      <div class="evt-head">
        <span class="sev ${sev}">${esc(e.severity)}</span>
        <span class="evt-title" data-dev="${esc(e.root)}" title="点击定位设备">${esc(e.title)}</span>
        <span class="evt-meta">${esc(e.kind)} · 根因 ${esc(e.root)}${affected}</span>
        <span class="evt-actions">
          ${status}
          <button class="btn ghost sm" data-ack="${esc(e.id)}" data-status="ack">确认</button>
          <button class="btn ghost sm" data-ack="${esc(e.id)}" data-status="ignored">忽略</button>
        </span>
      </div>
      <ul class="evt-evidence">${evidence}</ul>
      <div class="evt-fix">建议：${esc(e.suggestion)}</div>
    </div>`;
  }).join("") || '<p class="muted">没有需要处理的事件。</p>';

  $$("#aioEvents [data-ack]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await api("/api/aiops/events/ack", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: btn.dataset.ack, status: btn.dataset.status }),
        });
        await loadAiops();
      } catch (err) {
        toast(err.message, true);
        btn.disabled = false;
      }
    });
  });
  $$("#aioEvents .evt-title").forEach((el) => {
    el.addEventListener("click", () => aioFocusDevice(el.dataset.dev));
  });

  const compare = d.comparison || [];
  $("#aioCompareCard").hidden = !hasRun || !compare.length;
  $("#aioCompareTable tbody").innerHTML = compare.map((c) => {
    const worse = c.metric === "rx_power" ? c.delta < 0 : c.delta > 0;
    return `<tr>
      <td>${esc(c.device)}</td><td>${esc(c.label)}</td>
      <td class="num">${c.prev}</td><td class="num">${c.now}</td>
      <td class="num" style="color:${worse ? "var(--warn)" : "var(--ok)"}">${c.delta > 0 ? "+" : ""}${c.delta}</td>
    </tr>`;
  }).join("");

  const rows = [];
  let maxWindow = 0;
  (d.assets || []).forEach((a) => {
    (a.trends || []).forEach((t) => {
      maxWindow = Math.max(maxWindow, t.windowDays || 0);
      if (t.reliable === false || t.slope == null) return;   // 窗口太短，画出来也是噪声
      const eta = t.etaDays == null ? "—" : `${t.etaDays} 天`;
      rows.push(`<tr>
        <td>${esc(a.name)}</td>
        <td>${esc(t.label)}</td>
        <td class="num">${t.current}${esc(t.unit)}</td>
        <td class="num">${t.slope > 0 ? "+" : ""}${t.slope}/天</td>
        <td>${eta}</td>
        <td>${aioSpark(t.samples)}</td>
      </tr>`);
    });
  });
  $("#aioTrendTable tbody").innerHTML = rows.join("") ||
    `<tr><td colspan="6" class="muted">历史样本不足：需要同一型号至少 3 次巡检、且时间跨度 ≥ 6 小时${
      maxWindow ? `（当前跨度约 ${(maxWindow * 24).toFixed(1)} 小时）` : ""
    }。</td></tr>`;

  $("#aioComplianceMeta").textContent = d.complianceStamp
    ? `备份批次 ${d.complianceStamp} · ${(d.compliance || []).length} 项`
    : "还没有配置备份";
  $("#aioCompliance").innerHTML = (d.compliance || []).map((x) => `
    <div class="cmp">
      <span class="sev ${String(x.severity).toLowerCase()}">${esc(x.severity)}</span>
      <div>
        <b>${esc(x.device)}</b> · ${esc(x.message)}
        ${x.line ? `<div><code>${esc(x.line)}</code></div>` : ""}
        <div class="cmp-fix">建议：${esc(x.suggestion)}</div>
      </div>
    </div>`).join("") || '<p class="muted">没有发现风险配置项。</p>';
}

$("#btnAioRefresh").addEventListener("click", async () => {
  const btn = $("#btnAioRefresh");
  btn.disabled = true;
  btn.textContent = "分析中…";
  await loadAiops();
  btn.disabled = false;
  btn.textContent = "重新分析";
});

$("#btnAioReport").addEventListener("click", () => {
  window.location.href = "/api/aiops/report";
});

$("#btnAioGoInspect").addEventListener("click", () => switchView("inspect"));

function aioFocusDevice(name) {
  const row = $$("#aioDeviceTable tbody tr").find(
    (r) => r.querySelector(".dev-name")?.textContent === name
  );
  if (!row) return;
  row.scrollIntoView({ block: "center", behavior: "smooth" });
  row.classList.remove("flash");
  void row.offsetWidth;
  row.classList.add("flash");
}

$("#btnAioRules").addEventListener("click", () => {
  const editor = $("#aioRulesEditor");
  if (!editor.hidden) {
    editor.hidden = true;
    return;
  }
  const rules = (aioLastData && aioLastData.rules) || [];
  $("#aioRulesText").value = rules
    .map((r) => `${r.severity} :: ${r.pattern} :: ${r.message} :: ${r.suggestion}`)
    .join("\n");
  editor.hidden = false;
});

$("#btnAioRulesCancel").addEventListener("click", () => {
  $("#aioRulesEditor").hidden = true;
});

$("#btnAioRulesSave").addEventListener("click", async () => {
  const lines = $("#aioRulesText").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const rules = lines
    .map((line) => {
      const parts = line.split("::").map((s) => s.trim());
      return {
        severity: parts[0] || "P3",
        pattern: parts[1] || "",
        message: parts[2] || "命中自定义规则",
        suggestion: parts[3] || "按基线要求整改",
      };
    })
    .filter((r) => r.pattern);
  try {
    await api("/api/aiops/rules", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules }),
    });
    $("#aioRulesEditor").hidden = true;
    toast(`已保存 ${rules.length} 条合规规则`);
    await loadAiops();
  } catch (err) {
    toast(err.message, true);
  }
});

/* ---------------- 定时巡检 ---------------- */

async function loadScheduler() {
  try {
    const d = await api("/api/scheduler");
    $("#schedEnabled").checked = !!d.config.enabled;
    $("#schedInterval").value = d.config.intervalMinutes || 60;
    renderScheduler(d);
  } catch (err) {
    /* 服务刚启动时可能还没就绪 */
  }
}

function renderScheduler(d) {
  const el = $("#schedStatus");
  if (!el) return;
  if (d.running) {
    el.textContent = "正在执行…";
    return;
  }
  const cfg = d.config || {};
  if (!cfg.enabled) {
    el.textContent = cfg.lastError ? `未启用（上次错误：${cfg.lastError}）` : "未启用";
    return;
  }
  let text = d.nextInSeconds != null
    ? `已启用，约 ${Math.max(1, Math.ceil(d.nextInSeconds / 60))} 分钟后执行`
    : "已启用";
  if (cfg.lastRunAt) text += ` · 上次 ${String(cfg.lastRunAt).replace("T", " ").slice(5, 16)}`;
  if (cfg.lastError) text += ` · 上次错误：${cfg.lastError}`;
  el.textContent = text;
}

function schedPayload() {
  const devices = inspDevices
    .filter((d) => d.enabled && d.name.trim() && d.host.trim())
    .map((d) => ({
      name: d.name.trim(),
      host: d.host.trim(),
      port: Number(d.port),
      protocol: d.protocol,
      username: d.username,
      password: d.password,
    }));
  const commands = $("#inspCommands").value.split("\n").map((s) => s.trim()).filter(Boolean);
  return {
    enabled: $("#schedEnabled").checked,
    intervalMinutes: Number($("#schedInterval").value) || 60,
    devices,
    commands,
  };
}

$("#btnSchedSave").addEventListener("click", async () => {
  const payload = schedPayload();
  if (payload.enabled && !payload.devices.length) {
    toast("先勾选要巡检的设备", true);
    return;
  }
  try {
    const d = await api("/api/scheduler", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderScheduler(d);
    toast(payload.enabled ? `已启用，每 ${payload.intervalMinutes} 分钟巡检 ${payload.devices.length} 台` : "已停用定时巡检");
  } catch (err) {
    toast(err.message, true);
  }
});

$("#btnSchedRun").addEventListener("click", async () => {
  const btn = $("#btnSchedRun");
  btn.disabled = true;
  btn.textContent = "执行中…";
  try {
    const r = await api("/api/scheduler/run", { method: "POST" });
    toast(`巡检完成：${r.summary?.succeeded ?? 0}/${r.summary?.total ?? 0} 台成功`);
    await loadScheduler();
    if (typeof restoreInspection === "function") await restoreInspection();
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "立即执行";
  }
});

/* ---------------- 日志审计 ---------------- */

let logsState = { entries: [], audit: null };

function logsSevClass(sev) {
  if (["紧急", "告警", "严重"].includes(sev)) return "p1";
  if (sev === "错误") return "p2";
  if (sev === "警告") return "p3";
  return "p4";
}

function logsInit() {
  const sel = $("#logDevice");
  if (sel && sel.options.length <= 1 && S.inspect) {
    (S.inspect.devices || [])
      .filter((d) => d.consolePort)
      .forEach((d) => {
        const opt = document.createElement("option");
        opt.value = d.name;
        opt.textContent = d.name;
        sel.appendChild(opt);
      });
  }
  (async () => {
    try {
      const d = await api("/api/logs/state");
      if (!d.count) return;
      logsState.entries = d.entries || [];
      logsRenderTable(logsState.entries);
      logsRenderStats(d.summary);
      $("#logMeta").textContent = `上次采集 ${(d.meta && d.meta.collectedAt) || ""} · ${d.count} 条`;
      if (d.audit) logsRenderAudit(d.audit);
    } catch (err) {
      /* 恢复失败不影响新采集 */
    }
  })();
}

function logsRenderStats(summary) {
  const box = $("#logStats");
  if (!summary || !summary.total) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  $("#logTotal").textContent = summary.total;
  const critical = ["紧急", "告警", "严重", "错误"].reduce((a, k) => a + (summary.bySeverity[k] || 0), 0);
  $("#logCritical").textContent = critical;
  $("#logDevices").textContent = Object.keys(summary.byDevice || {}).length;
  $("#logErrorRate").textContent = `${summary.errorRate}%`;
  if (summary.start && summary.end) {
    $("#logRange").textContent =
      `${new Date(summary.start * 1000).toLocaleString()} ~ ${new Date(summary.end * 1000).toLocaleTimeString()}`;
  }
}

function logsRenderTable(entries) {
  const body = $("#logTable tbody");
  if (!entries || !entries.length) {
    body.innerHTML = '<tr><td colspan="5" class="muted">没有匹配的日志。</td></tr>';
    return;
  }
  body.innerHTML = entries
    .slice(-600)
    .reverse()
    .map((e) => `<tr>
      <td class="mono">${esc(e.time || "—")}</td>
      <td>${esc(e.device || "")}</td>
      <td><span class="sev ${logsSevClass(e.severity)}">${esc(e.severity || "")}</span></td>
      <td class="mono">${esc(e.module || "")}</td>
      <td class="log-msg">${esc(e.message || e.raw || "")}</td>
    </tr>`)
    .join("");
}

function logsRenderAudit(a) {
  logsState.audit = a;
  $("#logAuditEmpty").hidden = true;
  $("#logAuditBody").hidden = false;
  $("#logP1").textContent = a.counts?.p1 ?? 0;
  $("#logP2").textContent = a.counts?.p2 ?? 0;
  $("#logP3").textContent = a.counts?.p3 ?? 0;
  $("#logAuditRate").textContent = `${a.summary?.errorRate ?? 0}%`;

  $("#logFindings").innerHTML = (a.findings || []).map((f) => {
    const sev = String(f.severity || "P3").toLowerCase();
    const evidence = (f.evidence || []).map((x) => `<li>${esc(x)}</li>`).join("");
    return `<div class="evt ${sev}">
      <div class="evt-head">
        <span class="sev ${sev}">${esc(f.severity)}</span>
        <span class="evt-title">${esc(f.title)}</span>
        <span class="evt-meta">${esc(f.category)} · ${esc(f.detail || "")}</span>
      </div>
      ${evidence ? `<ul class="evt-evidence">${evidence}</ul>` : ""}
      <div class="evt-fix">建议：${esc(f.suggestion)}</div>
    </div>`;
  }).join("") || '<p class="muted">没有发现需要处理的问题。</p>';

  $("#logTemplates").innerHTML = (a.topTemplates || []).map((t) =>
    `<div class="tpl"><code>${esc(t.text)}</code><span>${t.count}</span></div>`
  ).join("") || '<p class="muted">—</p>';

  const tl = a.timeline || [];
  const max = Math.max(1, ...tl.map((x) => x.count));
  $("#logTimeline").innerHTML = tl.slice(-36).map((x) =>
    `<div class="bar" style="height:${Math.max(4, Math.round((x.count / max) * 82))}px" title="${esc(x.hour)} · ${x.count} 条"></div>`
  ).join("") || '<p class="muted">没有可用的时间信息。</p>';
}

$("#btnLogCollect").addEventListener("click", async () => {
  const btn = $("#btnLogCollect");
  btn.disabled = true;
  btn.textContent = "采集中…";
  try {
    const d = await api("/api/logs/collect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    logsState.entries = d.entries || [];
    logsRenderTable(logsState.entries);
    logsRenderStats(d.summary);
    $("#logMeta").textContent = `采集于 ${new Date().toLocaleTimeString()} · ${d.count} 条`;
    const failed = (d.devices || []).filter((x) => !x.ok);
    if (failed.length) toast(`采集到 ${d.count} 条，${failed.length} 台失败`, true);
    else toast(`采集到 ${d.count} 条日志`);
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "采集日志";
  }
});

$("#btnLogFilter").addEventListener("click", async () => {
  try {
    const d = await api("/api/logs/filter", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device: $("#logDevice").value,
        severity: $("#logSeverity").value,
        keyword: $("#logKeyword").value.trim(),
      }),
    });
    logsState.entries = d.entries || [];
    logsRenderTable(logsState.entries);
    logsRenderStats(d.summary);
    $("#logMeta").textContent = `筛选结果 ${d.count} 条`;
  } catch (err) {
    toast(err.message, true);
  }
});

$("#btnLogExportCsv").addEventListener("click", () => {
  window.location.href = "/api/logs/export?format=csv&scope=filtered";
});
$("#btnLogExportTxt").addEventListener("click", () => {
  window.location.href = "/api/logs/export?format=txt&scope=filtered";
});

$("#btnLogAudit").addEventListener("click", async () => {
  const btn = $("#btnLogAudit");
  btn.disabled = true;
  btn.textContent = "审计中…";
  try {
    const d = await api("/api/logs/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: "filtered" }),
    });
    logsRenderAudit(d);
    toast(`审计完成：P1 ${d.counts?.p1 ?? 0} / P2 ${d.counts?.p2 ?? 0}`);
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "审计当前日志";
  }
});

$("#btnLogReport").addEventListener("click", () => {
  window.location.href = "/api/logs/report";
});

$("#btnLogUpload").addEventListener("click", () => $("#logFile").click());
$("#logFile").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  try {
    toast("正在解析并审计…");
    const audit = await api("/api/logs/audit/upload", { method: "POST", body: form });
    const filtered = await api("/api/logs/filter", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    logsState.entries = filtered.entries || [];
    logsRenderTable(logsState.entries);
    logsRenderStats(filtered.summary);
    logsRenderAudit(audit);
    $("#logMeta").textContent = `已导入 ${file.name} · ${filtered.count} 条`;
    toast(`导入 ${filtered.count} 条日志并完成审计`);
  } catch (err) {
    toast(err.message, true);
  } finally {
    e.target.value = "";
  }
});

/* ---------------- 任务书 ---------------- */

let briefData = null;

function chipList(list, cls = "") {
  if (!list || !list.length) return '<span class="chip empty">未识别</span>';
  return list.map((v) => `<span class="chip ${cls}">${esc(v)}</span>`).join("");
}

let skeletonState = {};

function renderSkeleton(skeleton) {
  const names = Object.keys(skeleton || {});
  $("#briefSkeletonCard").hidden = names.length === 0;
  skeletonState = {};
  if (!names.length) return;

  $("#briefSkeleton").innerHTML = names.map((name) => {
    const cmds = skeleton[name] || [];
    skeletonState[name] = cmds;
    return `<div class="skeleton-row" data-dev="${esc(name)}">
      <div class="skeleton-head">
        <span class="dev-name">${esc(name)}</span>
        <span class="cmd-count">${cmds.length} 行</span>
        <span class="muted">可直接编辑</span>
      </div>
      <textarea class="cmd-edit" data-edit="${esc(name)}" spellcheck="false">${esc(cmds.join("\n"))}</textarea>
    </div>`;
  }).join("");

  $$("#briefSkeleton .cmd-edit").forEach((ta) => {
    ta.addEventListener("input", () => {
      skeletonState[ta.dataset.edit] = ta.value.split("\n");
    });
  });
}

function renderBrief(data) {
  const a = data.analysis || {};
  const devices = a.devices || [];
  const nets = (a.networks || []).concat(a.ips || []);
  const protos = a.protocols || [];

  $("#briefDevices").textContent = devices.length;
  $("#briefDevList").textContent = devices.join(" · ") || "未识别到设备名";
  $("#briefNets").textContent = nets.length;
  $("#briefNetList").textContent = nets.slice(0, 4).join(" · ") || "未识别到地址";
  $("#briefProtos").textContent = protos.length;
  $("#briefProtoList").textContent = protos.join(" · ") || "未命中协议关键词";
  $("#briefSize").textContent = `${a.lineCount || 0} 行`;
  $("#briefKind").textContent = `${(data.kind || "").toUpperCase()} · ${(a.charCount || 0).toLocaleString()} 字符`;

  $("#briefSummary").hidden = false;
  $("#briefDetail").hidden = false;
  $("#briefText").textContent = data.text || "";

  const groups = [];
  groups.push(`<div class="fact-group"><h4>设备</h4><div class="chips">${chipList(devices, "accent")}</div></div>`);
  groups.push(`<div class="fact-group"><h4>网段</h4><div class="chips">${chipList(a.networks || [])}</div></div>`);
  groups.push(`<div class="fact-group"><h4>主机地址</h4><div class="chips">${chipList(a.ips || [])}</div></div>`);
  groups.push(`<div class="fact-group"><h4>协议 / 技术</h4><div class="chips">${chipList(protos)}</div></div>`);
  if ((a.vlans || []).length) {
    groups.push(`<div class="fact-group"><h4>VLAN</h4><div class="chips">${chipList(a.vlans.map(String))}</div></div>`);
  }
  if ((a.areas || []).length) {
    groups.push(`<div class="fact-group"><h4>OSPF 区域</h4><div class="chips">${chipList(a.areas)}</div></div>`);
  }
  if ((a.asNumbers || []).length) {
    groups.push(`<div class="fact-group"><h4>AS 号</h4><div class="chips">${chipList(a.asNumbers)}</div></div>`);
  }
  if ((a.sections || []).length) {
    groups.push(`<div class="fact-group"><h4>结构大纲</h4><div class="chips">${chipList(a.sections.slice(0, 12))}</div></div>`);
  }
  $("#briefFacts").innerHTML = groups.join("");

  renderSkeleton(data.skeleton);
  setAlert("#briefAlert", "");
}

async function uploadBrief(file) {
  if (!file) return;
  if (!/\.(docx|pdf|txt|md)$/i.test(file.name)) {
    toast("只支持 .docx / .pdf / .txt / .md", true);
    return;
  }
  const form = new FormData();
  form.append("file", file);
  toast("正在解析任务书…");
  try {
    const data = await api("/api/brief/upload", { method: "POST", body: form });
    briefData = data;
    renderBrief(data);
    toast(`已解析：${data.analysis.devices.length} 台设备 / ${data.analysis.protocols.length} 个协议关键词`);
  } catch (err) {
    setAlert("#briefAlert", `解析失败：${esc(err.message)}`, "err");
    toast(err.message, true);
  }
}

wireDropzone("#briefDrop", "#briefFile", uploadBrief);
$("#btnPickBrief").addEventListener("click", (e) => { e.stopPropagation(); $("#briefFile").click(); });

$("#btnBriefToDeploy").addEventListener("click", () => {
  const devices = Object.entries(skeletonState)
    .map(([name, cmds]) => ({
      name,
      model: "",
      role: "来自任务书",
      commands: (cmds || []).map((c) => String(c).trim()).filter((c) => c && !c.startsWith("#")),
      sheets: ["任务书"],
    }))
    .filter((d) => d.commands.length);

  if (!devices.length) {
    toast("骨架里没有可下发的命令", true);
    return;
  }

  S.excel = {
    ok: true,
    devices,
    deviceCount: devices.length,
    commandCount: devices.reduce((n, d) => n + d.commands.length, 0),
    sheets: [{ name: "任务书", rowCount: devices.length, headerDetected: false, header: [], columns: {}, devices: devices.length }],
  };
  S.selected = new Set(devices.map((d) => d.name));
  renderExcel(S.excel);
  switchView("excel");
  toast(`已送入 ${devices.length} 台设备的配置`);
});

$("#btnBriefCopy").addEventListener("click", async () => {
  const text = briefData?.text || $("#briefText").textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast("已复制全文");
  } catch {
    toast("复制失败，请手动选中", true);
  }
});

/* ---------------- 执行记录 ---------------- */

async function loadHistory() {
  const box = $("#histList");
  box.innerHTML = '<div class="empty-state">正在读取命令日志…</div>';
  try {
    const data = await api("/api/history?limit=600");
    renderHistory(data);
  } catch (err) {
    box.innerHTML = `<div class="empty-state">读取失败：${esc(err.message)}</div>`;
  }
}

function renderHistory(data) {
  const list = data.batches || [];
  $("#histMeta").textContent = list.length
    ? `${data.total} 条命令 · ${list.length} 个批次`
    : "暂无记录";

  if (!list.length) {
    $("#histList").innerHTML =
      '<div class="empty-state">还没有下发记录。执行一次配置下发后，这里会按批次归档命令与回显。</div>';
    return;
  }

  $("#histList").innerHTML = list.map((b, i) => {
    const tool = String(b.tool || "exec")
      .replace("device_batch_config", "config")
      .replace("device_batch_exec", "exec")
      .replace("device_", "");
    const ts = String(b.ts || "").replace("T", " ").slice(0, 19);
    const body = (b.deviceList || []).map((d) => `
      <div class="hist-dev">
        <div class="hist-dev-name">${esc(d.device)} <span>console ${d.port ?? "—"}</span></div>
        ${(d.commands || []).slice(0, 80).map((c) => `
          <div class="hist-cmd ${c.ok ? "" : "fail"}">
            <span class="mark">${c.ok ? "✓" : "✕"}</span>
            <span class="text">${esc(c.command)}${c.error ? ` <span class="err">— ${esc(c.error)}</span>` : ""}</span>
          </div>`).join("")}
      </div>`).join("");

    return `<div class="hist-batch">
      <div class="hist-head ${i === 0 ? "open" : ""}" data-batch="${i}">
        <span class="hist-caret">▶</span>
        <span class="hist-time">${esc(ts)}</span>
        <span class="hist-tool">${esc(tool)}</span>
        <span class="muted">${b.deviceCount} 台</span>
        <span class="hist-count"><b>${b.okCount}</b> 成功${b.failCount ? ` · <i>${b.failCount}</i> 失败` : ""}</span>
      </div>
      <div class="hist-body ${i === 0 ? "open" : ""}" data-body="${i}">${body}</div>
    </div>`;
  }).join("");

  $$("#histList .hist-head").forEach((head) => {
    head.addEventListener("click", () => {
      head.classList.toggle("open");
      $(`[data-body="${head.dataset.batch}"]`)?.classList.toggle("open");
    });
  });
}

$("#btnHistRefresh").addEventListener("click", loadHistory);

/* ---------------- 环境 ---------------- */

function renderEnv(r) {
  const rt = r.runtime || {};
  const ensp = rt.ensp || {};
  const vbox = rt.virtualBox || {};
  const hv = vbox.host || {};
  const models = rt.modelChecks || [];

  const good = (v) => `<span class="${v ? "good" : "bad"}">${v ? "是" : "否"}</span>`;

  const groups = [];

  groups.push(`<div class="env-group">
    <h4>eNSP</h4>
    <div class="kv"><span>安装路径</span><span>${esc(ensp.path || "未找到")}</span></div>
    <div class="kv"><span>版本</span><span>${esc(ensp.version || "—")}</span></div>
    <div class="kv"><span>来源</span><span>${esc(ensp.source || "—")}</span></div>
  </div>`);

  groups.push(`<div class="env-group">
    <h4>VirtualBox</h4>
    <div class="kv"><span>版本</span><span>${esc(vbox.version || "未找到")}</span></div>
    <div class="kv"><span>版本匹配</span><span>${good(!!vbox.versionRecommended)}</span></div>
    <div class="kv"><span>硬件虚拟化</span><span>${good(!!hv.hardwareVirtualization)}</span></div>
    <div class="kv"><span>嵌套分页</span><span>${good(!!hv.nestedPaging)}</span></div>
  </div>`);

  const adapters = vbox.hostOnlyAdapters || [];
  groups.push(`<div class="env-group">
    <h4>Host-Only 网卡</h4>
    ${adapters.length
      ? adapters.map((a) => `<div class="kv"><span>${esc(a.name)}</span><span>${esc(a.ipAddress || "")}</span></div>`).join("")
      : '<div class="kv"><span>未检测到</span><span class="bad">缺少</span></div>'}
  </div>`);

  if (models.length) {
    groups.push(`<div class="env-group">
      <h4>设备型号就绪</h4>
      ${models.map((m) => `<div class="kv"><span>${esc(m.model)}</span><span class="${m.ready ? "good" : "bad"}">${m.ready ? "就绪" : "不可用"}</span></div>`).join("")}
    </div>`);
  }

  const issues = (r.issues || []).filter((i) => i.severity === "error");
  const warnList = (r.issues || []).filter((i) => i.severity === "warning");

  let banner = "";
  if (r.ok && r.readyForTopology) {
    banner = `<div class="alert ok">环境就绪：readyForTopology = true</div>`;
  } else if (!r.ok) {
    banner = `<div class="alert err">预检失败：${esc(r.error || "未知错误")}</div>`;
  } else {
    banner = `<div class="alert">环境未完全就绪，${issues.length} 个错误 / ${warnList.length} 个提醒</div>`;
  }

  const issueHtml = (r.issues || []).map((i) =>
    `<li><strong>${esc(i.code || "")}</strong> ${esc(i.message || "")}${i.remediation ? " — " + esc(i.remediation) : ""}</li>`
  ).join("");

  $("#envBody").innerHTML = `
    ${banner}
    <div class="env-groups">${groups.join("")}</div>
    ${issueHtml ? `<div class="alert" style="margin-top:14px"><strong>检查项</strong><ul>${issueHtml}</ul></div>` : ""}
  `;

  const pill = $("#envPill");
  const txt = $("#envText");
  pill.className = "env-pill " + (r.ok && r.readyForTopology ? "ok" : "warn");
  txt.textContent = r.ok && r.readyForTopology ? "环境就绪" : "环境异常";
}

async function loadEnv(force = false) {
  try {
    const r = await api(`/api/env${force ? "?refresh=1" : ""}`);
    renderEnv(r);
    return r;
  } catch (err) {
    $("#envBody").innerHTML = `<div class="alert err">检测失败：${esc(err.message)}</div>`;
    const pill = $("#envPill");
    pill.className = "env-pill warn";
    $("#envText").textContent = "检测失败";
  }
}

$("#btnEnvRefresh").addEventListener("click", () => loadEnv(true));
$("#btnRefreshState").addEventListener("click", async () => {
  await restoreState(true);
  toast("状态已刷新");
});

/* ---------------- 初始化 ---------------- */

async function restoreState(silent = false) {
  try {
    const st = await api("/api/state");
    if (st.inspect) {
      renderTopo({ inspect: st.inspect, path: st.topo }, st.topoName);
      if (!silent) toast(`已恢复拓扑 ${st.topoName}`);
    }
    if (st.excel && st.excel.devices && st.excel.devices.length) {
      S.excel = st.excel;
      S.selected = new Set(
        st.excel.devices.filter((d) => d.commands.length).map((d) => d.name)
      );
      renderExcel(st.excel);
    }
    if (st.topo && !st.inspect) {
      S.topo = st.topo;
      $("#topoChip").hidden = false;
      $("#topoChipName").textContent = st.topoName || "拓扑";
    }
  } catch (err) {
    /* 首次启动没有状态是正常的 */
  }
}

async function restoreBrief() {
  try {
    const st = await api("/api/brief/state");
    if (st.brief && st.brief.analysis) {
      briefData = st.brief;
      renderBrief(st.brief);
    }
  } catch {
    /* 没有任务书是正常的 */
  }
}

async function restoreInspection() {
  try {
    const data = await api("/api/inspect/last");
    if (data.result) renderInspResult(data.result);
  } catch {
    /* 没有历史结果是正常的 */
  }
}

(async function init() {
  try {
    const inspCmdBox = $("#inspCommands");
    if (inspCmdBox) inspCmdBox.value = INSP_DEFAULT_COMMANDS.join("\n");

    await restoreState(true);
    await restoreBrief();
    await restoreInspection();
    loadEnv();

    const params = new URLSearchParams(location.search);
    const view = params.get("view");
    switchView(view && VIEW_META[view] ? view : "topo");

    if (params.get("demo") === "excel") {
      await loadSampleExcel(true);
      switchView("excel");
    }

    const excelPath = params.get("excel");
    if (excelPath) {
      const data = await api(`/api/excel/load?path=${encodeURIComponent(excelPath)}`);
      S.excel = data;
      S.selected = new Set(data.devices.filter((d) => d.commands.length).map((d) => d.name));
      renderExcel(data);
      switchView("excel");
    }

    if (params.get("probe") === "1" && S.inspect) {
      switchView("topo");
      await probeDevices();
    }
  } catch (err) {
    console.error("[init]", err);
    toast(`页面初始化异常：${err.message}，请按 Ctrl+F5 强制刷新`, true);
  }
})();
