const API_BASE = "http://localhost:8000";
const FEED_REFRESH_MINUTES = 5;
const HISTORY_SCAN_LIMIT = 20;
const lastScanAt = {};
const MIN_SCAN_INTERVAL_MS = 12000;

async function scanPage(payload) {
  const response = await fetch(`${API_BASE}/scan-page`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error("Scan failed");
  }
  return response.json();
}

async function pollScan(scanId) {
  try {
    const response = await fetch(`${API_BASE}/scan/${scanId}`);
    if (!response.ok) return null;
    return response.json();
  } catch (error) {
    return null;
  }
}

async function scanUrl(payload) {
  const response = await fetch(`${API_BASE}/scan-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error("Scan failed");
  }
  return response.json();
}

function safeRuntimeMessage(payload) {
  try {
    chrome.runtime.sendMessage(payload, () => {
      const err = chrome.runtime.lastError;
      if (err) {
        // Ignore missing receiver (popup closed)
      }
    });
  } catch (error) {
    // Ignore
  }
}

async function refreshFeeds() {
  try {
    await fetch(`${API_BASE}/feeds/refresh`, { method: "POST" });
    const response = await fetch(`${API_BASE}/feeds/status`);
    if (response.ok) {
      const status = await response.json();
      chrome.storage.local.set({ feedStatus: status });
    }
  } catch (error) {
    // ignore refresh failures
  }
}

async function scanHistory() {
  return new Promise((resolve) => {
    chrome.history.search({ text: "", maxResults: 100, startTime: Date.now() - 7 * 24 * 60 * 60 * 1000 }, async (items) => {
      const urls = Array.from(new Set(items.map((item) => item.url).filter((url) => url && url.startsWith("http")))).slice(0, HISTORY_SCAN_LIMIT);
      let highRisk = 0;
      const risky = [];
      for (const url of urls) {
        try {
          const result = await scanUrl({ url });
          if (result.risk_level === "High") {
            highRisk += 1;
            risky.push({ url, score: result.scam_probability });
          }
        } catch (error) {
          // ignore failed history scans
        }
      }
      const summary = { scanned: urls.length, highRisk, risky: risky.slice(0, 5) };
      chrome.storage.local.set({ historyScanSummary: summary });
      resolve(summary);
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("feedRefresh", { periodInMinutes: FEED_REFRESH_MINUTES });
  refreshFeeds();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "feedRefresh") {
    refreshFeeds();
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "LOCAL_SCAN_RESULT") {
    const tabId = sender.tab ? sender.tab.id : "global";
    chrome.storage.local.get(["latestScanByTab"], (data) => {
      const latestScanByTab = data.latestScanByTab || {};
      latestScanByTab[tabId] = message.result;
      chrome.storage.local.set({ latestScanByTab });
    });
    safeRuntimeMessage({ type: "SCAN_UPDATED", result: message.result, tabId });
    return;
  }
  if (message.type === "SCAN_HISTORY") {
    scanHistory().then((summary) => {
      safeRuntimeMessage({ type: "HISTORY_SCAN_DONE", summary });
    });
    return;
  }
  if (message.type === "REQUEST_SCAN" || message.type === "FORCE_SCAN") {
    chrome.tabs.get(message.tabId, (tab) => {
      if (!tab || !tab.url) return;
      if (!tab.url.startsWith("http://") && !tab.url.startsWith("https://")) {
        safeRuntimeMessage({
          type: "SCAN_ERROR",
          error: "Unsupported page scheme",
          tabId: message.tabId,
        });
        return;
      }
      const now = Date.now();
      if (
        message.type !== "FORCE_SCAN" &&
        lastScanAt[message.tabId] &&
        now - lastScanAt[message.tabId] < MIN_SCAN_INTERVAL_MS
      ) {
        return;
      }
      lastScanAt[message.tabId] = now;
      scanUrl({ url: tab.url })
        .then((result) => {
          chrome.storage.local.get(["latestScanByTab"], (data) => {
            const latestScanByTab = data.latestScanByTab || {};
            latestScanByTab[message.tabId] = result;
            chrome.storage.local.set({ latestScanByTab });
          });
          safeRuntimeMessage({ type: "SCAN_UPDATED", result, tabId: message.tabId });
          if (result.scan_status === "pending") {
            const interval = setInterval(async () => {
              const updated = await pollScan(result.id);
              if (updated) {
                chrome.storage.local.get(["latestScanByTab"], (data) => {
                  const latestScanByTab = data.latestScanByTab || {};
                  latestScanByTab[message.tabId] = updated;
                  chrome.storage.local.set({ latestScanByTab });
                });
                safeRuntimeMessage({ type: "SCAN_UPDATED", result: updated, tabId: message.tabId });
                if (updated.scan_status !== "pending") {
                  clearInterval(interval);
                }
              }
            }, 3500);
          }
        })
        .catch((error) => {
          safeRuntimeMessage({ type: "SCAN_ERROR", error: error.message, tabId: message.tabId });
        });
    });
    return;
  }
  if (message.type === "SCAN_PAGE") {
    scanPage(message.payload)
      .then(async (result) => {
        const tabId = sender.tab ? sender.tab.id : "global";
        chrome.storage.local.get(["latestScanByTab"], (data) => {
          const latestScanByTab = data.latestScanByTab || {};
          latestScanByTab[tabId] = result;
          chrome.storage.local.set({ latestScanByTab });
        });
        sendResponse({ ok: true, result });
        if (result.scan_status === "pending") {
          const interval = setInterval(async () => {
            const updated = await pollScan(result.id);
            if (updated) {
              chrome.storage.local.get(["latestScanByTab"], (data) => {
                const latestScanByTab = data.latestScanByTab || {};
                latestScanByTab[tabId] = updated;
                chrome.storage.local.set({ latestScanByTab });
              });
              safeRuntimeMessage({ type: "SCAN_UPDATED", result: updated, tabId });
              if (updated.scan_status !== "pending") {
                clearInterval(interval);
              }
            }
          }, 3500);
        }
      })
      .catch((error) => {
        sendResponse({ ok: false, error: error.message });
      });
    return true;
  }
});
