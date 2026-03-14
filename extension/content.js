const MAX_CONTENT_CHARS = 2000;
const MAX_HIGHLIGHTS = 30;
const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".live", ".icu"];
const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "claim"];

const URGENCY = ["act now", "urgent", "immediately", "verify immediately", "account suspended", "limited time"];
const REWARD = ["you won", "free money", "lottery", "reward", "claim your prize"];
const AUTHORITY = ["your bank", "government notice", "irs", "security team", "support desk"];
const FINANCIAL = ["send payment", "transfer funds", "wire", "gift card", "bank transfer"];
const CRYPTO = ["crypto wallet", "seed phrase", "airdrop", "wallet", "bitcoin", "eth"];

function collectBehaviorSignals() {
  const forms = Array.from(document.querySelectorAll("form"));
  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  const emailInputs = Array.from(document.querySelectorAll('input[type="email"], input[name*="email" i]'));
  const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]'));
  const walletPatterns = /(0x[a-fA-F0-9]{40})|([13][a-km-zA-HJ-NP-Z1-9]{25,34})|(bc1[ac-hj-np-z02-9]{25,60})/g;
  const hasWallet = walletPatterns.test(document.body ? document.body.innerText : "");
  const popups = Array.from(document.querySelectorAll('[role="dialog"], .modal, .popup, .overlay'));
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');

  let behaviorScore = 0;
  const reasons = [];
  if (passwordInputs.length > 0) {
    behaviorScore += 10;
    reasons.push("Login form detected on page");
  }
  if (hiddenInputs.length > 5) {
    behaviorScore += 8;
    reasons.push("Hidden inputs detected (possible credential harvesting)");
  }
  if (emailInputs.length > 0 && passwordInputs.length === 0) {
    behaviorScore += 6;
    reasons.push("Email collection form detected");
  }
  if (popups.length > 0) {
    behaviorScore += 6;
    reasons.push("Popup or overlay UI detected");
  }
  if (metaRefresh) {
    behaviorScore += 10;
    reasons.push("Meta refresh redirect detected");
  }
  if (hasWallet) {
    behaviorScore += 12;
    reasons.push("Crypto wallet address detected on page");
  }

  return {
    form_count: forms.length,
    password_fields: passwordInputs.length,
    hidden_inputs: hiddenInputs.length,
    popup_count: popups.length,
    meta_refresh: Boolean(metaRefresh),
    wallet_detected: hasWallet,
    behavior_score: Math.min(25, behaviorScore),
    behavior_reasons: reasons,
  };
}

function extractPageText() {
  const bodyText = document.body ? document.body.innerText : "";
  return bodyText.replace(/\s+/g, " ").trim().slice(0, MAX_CONTENT_CHARS);
}

function localHeuristicScan(text, url) {
  const normalized = text.toLowerCase();
  const highlights = [];
  let score = 10;
  const addHits = (phrases, weight, reason) => {
    const hits = phrases.filter((p) => normalized.includes(p));
    if (hits.length) {
      score += weight;
      hits.forEach((hit) => {
        if (!highlights.includes(hit)) highlights.push(hit);
      });
      return reason;
    }
    return null;
  };

  const reasons = [];
  const reasonList = [
    addHits(URGENCY, 18, "Urgent language detected"),
    addHits(REWARD, 16, "Reward bait language"),
    addHits(AUTHORITY, 14, "Authority impersonation cues"),
    addHits(FINANCIAL, 20, "Financial request detected"),
    addHits(CRYPTO, 20, "Crypto scam indicators"),
  ];
  reasonList.forEach((r) => r && reasons.push(r));

  const riskLevel = score >= 60 ? "High" : score >= 35 ? "Medium" : "Low";
  return {
    id: `local-${Date.now()}`,
    url,
    scam_probability: Math.min(95, score),
    risk_score: Math.min(100, score),
    risk_level: riskLevel,
    reasons: reasons.length ? reasons : ["Offline heuristic scan"],
    highlights: highlights.slice(0, 10),
    scan_status: "offline",
    threat_intel_status: { offline: "used" },
    confidence: { low: 0.2, mid: 0.4, high: 0.6, confidence: 0.55 },
  };
}

function ensureHighlightStyles() {
  if (document.getElementById("cybershield-styles")) return;
  const style = document.createElement("style");
  style.id = "cybershield-styles";
  style.textContent = `
    .cyber-highlight { background: rgba(248,113,113,0.35); color: #fff; padding: 0 2px; border-radius: 3px; }
    .cyber-link { outline: 2px solid rgba(248,113,113,0.5); border-radius: 4px; }
  `;
  document.head.appendChild(style);
}

function highlightPage(phrases) {
  if (!phrases || phrases.length === 0) return;
  ensureHighlightStyles();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.parentElement) return NodeFilter.FILTER_REJECT;
      const tag = node.parentElement.tagName;
      if (["SCRIPT", "STYLE", "NOSCRIPT"].includes(tag)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  let count = 0;
  const phraseRegex = new RegExp(`\\b(${phrases.map(escapeRegExp).join("|")})\\b`, "gi");

  const nodes = [];
  while (walker.nextNode() && count < MAX_HIGHLIGHTS) {
    nodes.push(walker.currentNode);
    count += 1;
  }

  nodes.forEach((node) => {
    const text = node.nodeValue;
    if (!text) return;
    if (!phraseRegex.test(text)) return;
    const span = document.createElement("span");
    span.innerHTML = text.replace(phraseRegex, `<mark class="cyber-highlight">$1</mark>`);
    node.parentNode.replaceChild(span, node);
  });

  const links = Array.from(document.querySelectorAll("a[href]"));
  links.forEach((link) => {
    const href = link.getAttribute("href") || "";
    if (
      SUSPICIOUS_KEYWORDS.some((k) => href.toLowerCase().includes(k)) ||
      SUSPICIOUS_TLDS.some((tld) => href.toLowerCase().endsWith(tld))
    ) {
      link.classList.add("cyber-link");
    }
  });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function quarantinePage() {
  const overlayId = "cybershield-quarantine";
  if (document.getElementById(overlayId)) return;
  const overlay = document.createElement("div");
  overlay.id = overlayId;
  overlay.style.position = "fixed";
  overlay.style.inset = "0";
  overlay.style.background = "rgba(15,23,42,0.92)";
  overlay.style.zIndex = "999998";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.color = "#fff";
  overlay.style.fontFamily = "system-ui, sans-serif";
  overlay.innerHTML = `
    <div style="background:#111827;padding:24px;border-radius:16px;border:1px solid #334155;max-width:420px;text-align:center;">
      <h2 style="margin:0;font-size:18px;">Quarantine Enabled</h2>
      <p style="margin:8px 0 16px;font-size:13px;color:#cbd5f5;">Suspicious page detected. Links are temporarily blocked.</p>
      <div style="display:flex;gap:10px;">
        <button id="cyber-unlock" style="flex:1;padding:8px;border:none;border-radius:8px;background:#22c55e;color:#0b1120;cursor:pointer;">Allow Access</button>
        <button id="cyber-leave2" style="flex:1;padding:8px;border:none;border-radius:8px;background:#f97316;color:white;cursor:pointer;">Leave Page</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  document.querySelectorAll("a").forEach((link) => {
    link.dataset.cyberBlocked = "true";
    link.style.pointerEvents = "none";
    link.style.opacity = "0.5";
  });
  document.getElementById("cyber-unlock").onclick = () => {
    document.querySelectorAll("a[data-cyber-blocked='true']").forEach((link) => {
      link.style.pointerEvents = "auto";
      link.style.opacity = "1";
      link.removeAttribute("data-cyber-blocked");
    });
    overlay.remove();
  };
  document.getElementById("cyber-leave2").onclick = () => window.location.replace("about:blank");
}

function showBanner(result) {
  const existing = document.getElementById("cybershield-banner");
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = "cybershield-banner";
  banner.style.position = "fixed";
  banner.style.top = "16px";
  banner.style.right = "16px";
  banner.style.zIndex = "999999";
  banner.style.background = result.risk_level === "High" ? "#7f1d1d" : "#1e293b";
  banner.style.color = "white";
  banner.style.padding = "16px";
  banner.style.borderRadius = "12px";
  banner.style.boxShadow = "0 10px 30px rgba(0,0,0,0.35)";
  banner.style.fontFamily = "system-ui, sans-serif";
  banner.style.maxWidth = "320px";

  banner.innerHTML = `
    <div style="font-weight:700; font-size:14px;">AI CyberShield Alert</div>
    <div style="margin-top:6px; font-size:12px;">Risk Level: <strong>${result.risk_level.toUpperCase()}</strong></div>
    <div style="margin-top:4px; font-size:12px;">Scam Probability: ${result.scam_probability}%</div>
    <div style="margin-top:8px; font-size:12px;">${result.reasons.slice(0, 3).join(" • ")}</div>
    <div style="margin-top:10px; display:flex; gap:8px;">
      <button id="cyber-leave" style="flex:1; padding:6px; border:none; border-radius:8px; background:#f97316; color:white; cursor:pointer;">Leave</button>
      <button id="cyber-close" style="flex:1; padding:6px; border:none; border-radius:8px; background:#0f172a; color:white; cursor:pointer;">Dismiss</button>
    </div>
  `;

  document.body.appendChild(banner);
  document.getElementById("cyber-close").onclick = () => banner.remove();
  document.getElementById("cyber-leave").onclick = () => window.location.replace("about:blank");
}

function scanCurrentPage() {
  const payload = {
    url: window.location.href,
    content: extractPageText(),
    signals: collectBehaviorSignals(),
  };
  chrome.runtime.sendMessage({ type: "SCAN_PAGE", payload }, (response) => {
    if (response && response.ok && response.result) {
      highlightPage(response.result.highlights || []);
      if (response.result.risk_level === "High") {
        showBanner(response.result);
        chrome.storage.sync.get(["autoBlock"], (data) => {
          if (data.autoBlock) {
            quarantinePage();
          }
        });
      }
    } else {
      const localResult = localHeuristicScan(payload.content, payload.url);
      highlightPage(localResult.highlights || []);
      if (localResult.risk_level === "High") {
        showBanner(localResult);
        chrome.storage.sync.get(["autoBlock"], (data) => {
          if (data.autoBlock) {
            quarantinePage();
          }
        });
      }
      chrome.runtime.sendMessage({ type: "LOCAL_SCAN_RESULT", result: localResult });
    }
  });
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SCAN_UPDATED" && message.result && message.result.risk_level === "High") {
    showBanner(message.result);
  }
  if (message.type === "REQUEST_SCAN") {
    scanCurrentPage();
  }
});

scanCurrentPage();
