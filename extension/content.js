const MAX_CONTENT_CHARS = 2200;
const MAX_HIGHLIGHTS = 36;
const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".live", ".icu"];
const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "claim", "wallet", "seed"];

const URGENCY = ["act now", "urgent", "immediately", "verify immediately", "account suspended", "limited time"];
const REWARD = ["you won", "free money", "lottery", "reward", "claim your prize"];
const AUTHORITY = ["your bank", "government notice", "irs", "security team", "support desk"];
const FINANCIAL = ["send payment", "transfer funds", "wire", "gift card", "bank transfer"];
const CRYPTO = ["crypto wallet", "seed phrase", "airdrop", "wallet", "bitcoin", "eth"];

let currentRiskLevel = "Low";

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
  [addHits(URGENCY, 18, "Urgent language detected"), addHits(REWARD, 16, "Reward bait language"), addHits(AUTHORITY, 14, "Authority impersonation cues"), addHits(FINANCIAL, 20, "Financial request detected"), addHits(CRYPTO, 20, "Crypto scam indicators")]
    .forEach((reason) => reason && reasons.push(reason));

  const riskLevel = score >= 60 ? "High" : score >= 35 ? "Medium" : "Low";
  const manipulation = {
    fear: normalized.includes("account suspended") ? 35 : 10,
    urgency: URGENCY.some((item) => normalized.includes(item)) ? 70 : 15,
    authority: AUTHORITY.some((item) => normalized.includes(item)) ? 65 : 10,
    greed: REWARD.some((item) => normalized.includes(item)) ? 75 : 10,
    trust: SUSPICIOUS_KEYWORDS.some((item) => normalized.includes(item)) ? 55 : 10,
    confusion: normalized.includes("update") || normalized.includes("support") ? 35 : 10,
    pressure_points: highlights.slice(0, 3).map((hit) => ({
      label: "Signal",
      trigger: hit,
      meaning: "Suspicious language detected during local heuristic analysis.",
    })),
    summary: "Local heuristic manipulation map generated because the backend was unavailable.",
  };

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
    threat_casefile: {
      archetype: "Offline Suspicion Pattern",
      victim_persona: "General-purpose target",
      operator_tactic: "Rapid persuasion with low-trust indicators",
      attack_stage: "Initial lure",
      next_move_prediction: "The page will likely request a sensitive action or redirect to a spoof surface.",
      possible_outcome: "Credential theft, payment fraud, or wallet compromise.",
      narrative: "A local heuristic scan found suspicious scam-like signals on this page.",
      immediate_actions: ["Do not submit credentials.", "Leave the page and verify independently.", "Avoid clicking any additional links."],
      campaign_signature: highlights.slice(0, 4),
      mutation_risk: Math.min(100, score),
    },
    manipulation_map: manipulation,
    impact_forecast: {
      primary_target: "Credentials or money",
      likely_damage: "Potential account or payment compromise",
      loss_window: "Immediate after interaction",
      intervention_message: "Pause. This page is showing scam-like persuasion patterns.",
      safe_alternative: "Use the official website or verified contact channel instead.",
      escalation_path: ["Lure", "Prompt for action", "Sensitive submission", "Potential compromise"],
    },
  };
}

function ensureCyberStyles() {
  if (document.getElementById("cybershield-styles")) return;
  const style = document.createElement("style");
  style.id = "cybershield-styles";
  style.textContent = `
    .cyber-highlight { background: rgba(248,113,113,0.35); color: #fff; padding: 0 2px; border-radius: 3px; }
    .cyber-link { outline: 2px solid rgba(248,113,113,0.5); border-radius: 4px; }
    .cyber-blocked { pointer-events: none !important; opacity: 0.35 !important; filter: grayscale(0.2); }
    .cyber-submit-guard { box-shadow: 0 0 0 2px rgba(248,113,113,0.4) !important; }
  `;
  document.head.appendChild(style);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function highlightPage(phrases) {
  if (!phrases || phrases.length === 0 || !document.body) return;
  ensureCyberStyles();

  const nodes = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.parentElement) return NodeFilter.FILTER_REJECT;
      const tag = node.parentElement.tagName;
      if (["SCRIPT", "STYLE", "NOSCRIPT"].includes(tag)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  while (walker.nextNode() && nodes.length < MAX_HIGHLIGHTS) {
    nodes.push(walker.currentNode);
  }

  const regex = new RegExp(`\\b(${phrases.map(escapeRegExp).join("|")})\\b`, "gi");
  nodes.forEach((node) => {
    const text = node.nodeValue;
    if (!text || !regex.test(text)) return;
    const span = document.createElement("span");
    span.innerHTML = text.replace(regex, `<mark class="cyber-highlight">$1</mark>`);
    node.parentNode.replaceChild(span, node);
  });

  Array.from(document.querySelectorAll("a[href]")).forEach((link) => {
    const href = (link.getAttribute("href") || "").toLowerCase();
    if (SUSPICIOUS_KEYWORDS.some((k) => href.includes(k)) || SUSPICIOUS_TLDS.some((tld) => href.endsWith(tld))) {
      link.classList.add("cyber-link");
    }
  });
}

function setInteractiveState(blocked) {
  ensureCyberStyles();
  Array.from(document.querySelectorAll("a[href], button, [role='button'], input[type='submit'], input[type='button']")).forEach((el) => {
    if (blocked) {
      el.classList.add("cyber-blocked");
      el.dataset.cyberBlocked = "true";
    } else if (el.dataset.cyberBlocked === "true") {
      el.classList.remove("cyber-blocked");
      el.removeAttribute("data-cyber-blocked");
    }
  });
}

function attachSubmitGuard(result) {
  const forms = Array.from(document.querySelectorAll("form"));
  forms.forEach((form) => {
    if (form.dataset.cyberGuarded === "true") return;
    form.dataset.cyberGuarded = "true";
    form.classList.add("cyber-submit-guard");
    form.addEventListener(
      "submit",
      (event) => {
        if (currentRiskLevel !== "High") return;
        event.preventDefault();
        event.stopPropagation();
        showInterventionPanel(result, { force: true, source: "form_submit" });
      },
      true,
    );
  });
}

function showInterventionPanel(result, options = {}) {
  const overlayId = "cybershield-intervention";
  const existing = document.getElementById(overlayId);
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = overlayId;
  overlay.style.position = "fixed";
  overlay.style.inset = "0";
  overlay.style.zIndex = "999999";
  overlay.style.background = "rgba(2, 6, 23, 0.84)";
  overlay.style.backdropFilter = "blur(8px)";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.padding = "20px";

  const points = (result.manipulation_map?.pressure_points || []).slice(0, 3)
    .map((point) => `<div style="padding:10px 12px;border:1px solid rgba(51,65,85,1);border-radius:14px;background:#0f172a;margin-top:8px;"><div style="font-size:10px;text-transform:uppercase;letter-spacing:0.18em;color:#fda4af;">${point.label}</div><div style="margin-top:6px;font-size:13px;color:white;">${point.trigger}</div><div style="margin-top:6px;font-size:12px;color:#94a3b8;">${point.meaning}</div></div>`)
    .join("");

  const path = (result.impact_forecast?.escalation_path || []).slice(0, 4)
    .map((step, index) => `<div style="display:flex;gap:10px;align-items:flex-start;margin-top:10px;"><div style="min-width:24px;height:24px;border-radius:999px;background:rgba(244,63,94,0.18);color:#fecdd3;display:flex;align-items:center;justify-content:center;font-size:12px;">${index + 1}</div><div style="font-size:13px;color:#e2e8f0;">${step}</div></div>`)
    .join("");

  overlay.innerHTML = `
    <div style="width:min(760px,100%);border-radius:28px;border:1px solid rgba(51,65,85,1);background:linear-gradient(180deg,#0f172a 0%,#020617 100%);color:white;box-shadow:0 20px 60px rgba(0,0,0,0.45);overflow:hidden;">
      <div style="padding:20px 22px;border-bottom:1px solid rgba(51,65,85,1);background:radial-gradient(circle at top right, rgba(34,211,238,0.15), transparent 35%), radial-gradient(circle at top left, rgba(244,63,94,0.18), transparent 30%);">
        <div style="font-size:11px;letter-spacing:0.26em;text-transform:uppercase;color:#22d3ee;">CyberShield Intervention</div>
        <div style="margin-top:10px;font-size:28px;font-weight:700;">${result.threat_casefile?.archetype || "Suspicious Scam Pattern"}</div>
        <div style="margin-top:8px;font-size:14px;color:#cbd5e1;">${result.impact_forecast?.intervention_message || "Pause before proceeding. This page shows scam indicators."}</div>
      </div>
      <div style="padding:22px;display:grid;grid-template-columns:1.1fr 0.9fr;gap:18px;">
        <div>
          <div style="padding:16px;border-radius:20px;border:1px solid rgba(51,65,85,1);background:#0b1120;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.18em;color:#94a3b8;">Why this is dangerous</div>
            <div style="margin-top:10px;font-size:14px;color:#e2e8f0;">${result.threat_casefile?.next_move_prediction || "The flow is likely steering toward a sensitive action."}</div>
            <div style="margin-top:14px;font-size:12px;color:#94a3b8;">Likely damage: ${result.impact_forecast?.likely_damage || "Unknown"}</div>
            <div style="margin-top:6px;font-size:12px;color:#94a3b8;">Loss window: ${result.impact_forecast?.loss_window || "Unknown"}</div>
          </div>
          <div style="margin-top:16px;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.18em;color:#94a3b8;">Manipulation signals</div>
            ${points || '<div style="margin-top:10px;font-size:13px;color:#cbd5e1;">No detailed pressure points available.</div>'}
          </div>
        </div>
        <div>
          <div style="padding:16px;border-radius:20px;border:1px solid rgba(51,65,85,1);background:#0b1120;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.18em;color:#94a3b8;">Projected attack path</div>
            ${path || '<div style="margin-top:10px;font-size:13px;color:#cbd5e1;">No escalation path available.</div>'}
          </div>
          <div style="margin-top:16px;padding:16px;border-radius:20px;border:1px solid rgba(34,211,238,0.25);background:rgba(34,211,238,0.08);">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.18em;color:#67e8f9;">Safe alternative</div>
            <div style="margin-top:8px;font-size:13px;color:#ecfeff;">${result.impact_forecast?.safe_alternative || "Use an official and trusted channel."}</div>
          </div>
          <div style="margin-top:18px;display:flex;gap:10px;">
            <button id="cyber-leave" style="flex:1;padding:10px;border:none;border-radius:12px;background:#f97316;color:white;cursor:pointer;font-weight:700;">Leave Page</button>
            <button id="cyber-review" style="flex:1;padding:10px;border:none;border-radius:12px;background:#22d3ee;color:#082f49;cursor:pointer;font-weight:700;">Review Safely</button>
            <button id="cyber-proceed" style="flex:1;padding:10px;border:1px solid rgba(71,85,105,1);border-radius:12px;background:transparent;color:white;cursor:pointer;">Proceed Anyway</button>
          </div>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
  setInteractiveState(true);

  document.getElementById("cyber-leave").onclick = () => window.location.replace("about:blank");
  document.getElementById("cyber-review").onclick = () => {
    overlay.remove();
    setInteractiveState(false);
  };
  document.getElementById("cyber-proceed").onclick = () => {
    if (options.force) {
      currentRiskLevel = "Medium";
    }
    overlay.remove();
    setInteractiveState(false);
  };
}

function showBanner(result) {
  const existing = document.getElementById("cybershield-banner");
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = "cybershield-banner";
  banner.style.position = "fixed";
  banner.style.top = "16px";
  banner.style.right = "16px";
  banner.style.zIndex = "999998";
  banner.style.background = result.risk_level === "High" ? "#7f1d1d" : "#1e293b";
  banner.style.color = "white";
  banner.style.padding = "16px";
  banner.style.borderRadius = "14px";
  banner.style.boxShadow = "0 10px 30px rgba(0,0,0,0.35)";
  banner.style.fontFamily = "system-ui, sans-serif";
  banner.style.maxWidth = "360px";
  banner.innerHTML = `
    <div style="font-weight:700;font-size:14px;">AI CyberShield Alert</div>
    <div style="margin-top:6px;font-size:12px;">${result.threat_casefile?.archetype || "Suspicious Pattern"}</div>
    <div style="margin-top:4px;font-size:12px;">Risk: <strong>${result.risk_level.toUpperCase()}</strong> | ${result.scam_probability}%</div>
    <div style="margin-top:8px;font-size:12px;color:#e2e8f0;">${result.impact_forecast?.intervention_message || result.reasons.slice(0, 2).join(" • ")}</div>
    <div style="margin-top:10px;display:flex;gap:8px;">
      <button id="cyber-investigate" style="flex:1;padding:7px;border:none;border-radius:8px;background:#22d3ee;color:#082f49;cursor:pointer;font-weight:700;">Investigate</button>
      <button id="cyber-close" style="flex:1;padding:7px;border:none;border-radius:8px;background:#0f172a;color:white;cursor:pointer;">Dismiss</button>
    </div>
  `;

  document.body.appendChild(banner);
  document.getElementById("cyber-close").onclick = () => banner.remove();
  document.getElementById("cyber-investigate").onclick = () => showInterventionPanel(result);
}

function applyResult(result) {
  currentRiskLevel = result.risk_level;
  highlightPage(result.highlights || []);
  attachSubmitGuard(result);

  if (result.risk_level === "High") {
    showBanner(result);
    chrome.storage.sync.get(["autoBlock"], (data) => {
      if (data.autoBlock) {
        showInterventionPanel(result);
      }
    });
  }
}

function scanCurrentPage() {
  const payload = {
    url: window.location.href,
    content: extractPageText(),
    signals: collectBehaviorSignals(),
  };

  chrome.runtime.sendMessage({ type: "SCAN_PAGE", payload }, (response) => {
    if (response && response.ok && response.result) {
      applyResult(response.result);
      return;
    }

    const localResult = localHeuristicScan(payload.content, payload.url);
    applyResult(localResult);
    chrome.runtime.sendMessage({ type: "LOCAL_SCAN_RESULT", result: localResult });
  });
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "SCAN_UPDATED" && message.result) {
    applyResult(message.result);
  }
  if (message.type === "REQUEST_SCAN") {
    scanCurrentPage();
  }
});

scanCurrentPage();
