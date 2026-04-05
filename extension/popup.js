function formatFeeds(statusMap) {
  if (!statusMap) return "--";
  const entries = Object.entries(statusMap);
  return entries.map(([key, value]) => `${key}: ${value}`).join(" | ");
}

function updatePopup(result) {
  const statusText =
    result.scan_status === "pending"
      ? "Scanning threat feeds..."
      : result.scan_status === "offline"
      ? "Local protection mode"
      : "Scan complete";

  document.getElementById("status").textContent = statusText;
  const riskEl = document.getElementById("risk-level");
  riskEl.textContent = result.risk_level.toUpperCase();
  riskEl.style.color =
    result.risk_level === "High" ? "#f87171" : result.risk_level === "Medium" ? "#f59e0b" : "#22c55e";

  document.getElementById("probability").textContent = `${result.scam_probability}%`;
  document.getElementById("feeds").textContent = formatFeeds(result.threat_intel_status);
  document.getElementById("confidence").textContent = `${Math.round((result.confidence?.confidence ?? 0) * 100)}%`;
  document.getElementById("casefile").textContent = result.threat_casefile?.archetype || "Unknown casefile";
  document.getElementById("next-move").textContent = result.threat_casefile?.next_move_prediction || "--";
  document.getElementById("intervention").textContent = result.impact_forecast?.intervention_message || "--";

  const meter = document.getElementById("meter-fill");
  const pct = Math.min(100, Math.max(0, result.scam_probability));
  meter.style.width = `${pct}%`;

  const reasons = document.getElementById("reasons");
  reasons.innerHTML = "";
  result.reasons.slice(0, 4).forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = `- ${reason}`;
    reasons.appendChild(li);
  });

  const summary = {
    url: result.url || "",
    risk_level: result.risk_level,
    scam_probability: result.scam_probability,
    reasons: result.reasons,
    casefile: result.threat_casefile?.archetype,
    next_move: result.threat_casefile?.next_move_prediction,
    safe_alternative: result.impact_forecast?.safe_alternative,
  };
  window.__latestReport = JSON.stringify(summary, null, 2);
  window.__latestUrl = result.url || "";
}

let currentTabId = null;

function loadCurrentTabScan() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0]?.id;
    currentTabId = tabId ?? null;
    if (tabId) {
      chrome.runtime.sendMessage({ type: "REQUEST_SCAN", tabId });
    }
    chrome.storage.local.get(["latestScanByTab"], (data) => {
      const latest = data.latestScanByTab || {};
      if (tabId && latest[tabId]) {
        updatePopup(latest[tabId]);
      } else {
        document.getElementById("status").textContent = "Scanning current tab...";
      }
    });
  });
}

loadCurrentTabScan();

document.getElementById("scan-now").addEventListener("click", () => {
  if (!currentTabId) return;
  document.getElementById("status").textContent = "Scanning current tab...";
  chrome.runtime.sendMessage({ type: "FORCE_SCAN", tabId: currentTabId });
});

document.getElementById("copy-report").addEventListener("click", async () => {
  if (window.__latestReport) {
    await navigator.clipboard.writeText(window.__latestReport);
    document.getElementById("status").textContent = "Report copied to clipboard";
  }
});

document.getElementById("report-admin").addEventListener("click", async () => {
  if (!window.__latestReport) return;
  await navigator.clipboard.writeText(window.__latestReport);
  if (window.__latestUrl) {
    fetch("https://frostbyte-two.vercel.app/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: window.__latestUrl, source: "extension" }),
    }).catch(() => {});
  }
  document.getElementById("status").textContent = "Report sent to admin";
});

document.getElementById("scan-history").addEventListener("click", () => {
  document.getElementById("history-summary").textContent = "Scanning browser history...";
  chrome.runtime.sendMessage({ type: "SCAN_HISTORY" });
});

chrome.storage.sync.get(["autoBlock", "theme"], (data) => {
  const autoBlock = Boolean(data.autoBlock);
  document.getElementById("auto-block").checked = autoBlock;
  const isDark = data.theme !== "light";
  document.getElementById("theme-toggle").checked = isDark;
  document.body.classList.toggle("light", !isDark);
});

document.getElementById("auto-block").addEventListener("change", (event) => {
  chrome.storage.sync.set({ autoBlock: event.target.checked });
});


document.getElementById("theme-toggle").addEventListener("change", (event) => {
  const isDark = event.target.checked;
  chrome.storage.sync.set({ theme: isDark ? "dark" : "light" });
  document.body.classList.toggle("light", !isDark);
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SCAN_UPDATED") {
    if (message.tabId && message.tabId === currentTabId) {
      updatePopup(message.result);
    }
  }
  if (message.type === "SCAN_ERROR") {
    document.getElementById("status").textContent = `Scan error: ${message.error}`;
  }
  if (message.type === "HISTORY_SCAN_DONE") {
    const summary = message.summary;
    if (!summary) return;
    document.getElementById("history-summary").textContent = `Scanned ${summary.scanned} sites, High risk: ${summary.highRisk}`;
  }
});

chrome.storage.local.get(["feedStatus", "historyScanSummary"], (data) => {
  if (data.feedStatus && data.feedStatus.openphish_last_updated) {
    const ts = data.feedStatus.openphish_last_updated * 1000;
    const agoMinutes = Math.max(0, Math.floor((Date.now() - ts) / 60000));
    document.getElementById("feed-updated").textContent = `${agoMinutes}m ago`;
    const now = Date.now() / 1000;
    if ((data.feedStatus.openphish_backoff_until || 0) > now || (data.feedStatus.phishtank_backoff_until || 0) > now) {
      document.getElementById("status").textContent = "Feed rate-limited. Retrying soon.";
    }
  } else if (data.feedStatus && data.feedStatus.feeds_disabled) {
    document.getElementById("feed-updated").textContent = "--";
    document.getElementById("status").textContent = "Community feeds disabled.";
  }
  if (data.historyScanSummary) {
    document.getElementById("history-summary").textContent = `Scanned ${data.historyScanSummary.scanned} sites, High risk: ${data.historyScanSummary.highRisk}`;
  }
});
