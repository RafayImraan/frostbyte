from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import httpx
import logging
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybershield")

app = FastAPI(title="AI CyberShield API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_origin_regex=r"^chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path(__file__).resolve().parent / "data"
DATABASE_PATH = DATA_DIR / "scan_history.db"

URL_REGEX = re.compile(r"(https?://[^\s]+)")

URGENCY = ["act now", "urgent", "immediately", "verify immediately", "account suspended", "limited time"]
REWARD = ["you won", "free money", "lottery", "reward", "claim your prize"]
AUTHORITY = ["your bank", "government notice", "irs", "security team", "support desk"]
FINANCIAL = ["send payment", "transfer funds", "wire", "gift card", "bank transfer"]
CRYPTO = ["crypto wallet", "seed phrase", "airdrop", "wallet", "bitcoin", "eth"]

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "buff.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".live", ".icu"}
BRANDS = ["paypal", "amazon", "netflix", "apple", "microsoft", "coinbase", "binance"]
KNOWN_BAD_DOMAINS = {"paypal-secure-login.xyz", "secure-paypal-login.xyz"}

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
HTTP_TIMEOUT = float(os.getenv("THREAT_HTTP_TIMEOUT", "6"))

MODEL_API_URL = os.getenv("MODEL_API_URL")
MODEL_API_KEY = os.getenv("MODEL_API_KEY")
MODEL_PROVIDER = os.getenv("MODEL_PROVIDER", "huggingface")
MODEL_NAME = os.getenv("MODEL_NAME", "distilbert-or-roberta")
MODEL_TIMEOUT = float(os.getenv("MODEL_TIMEOUT", "8"))
MODEL_DEBUG_LOG_ONCE = True

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

URLHAUS_TTL = int(os.getenv("URLHAUS_TTL", "3600"))
VT_TTL = int(os.getenv("VT_TTL", "3600"))

URLHAUS_RPS = float(os.getenv("URLHAUS_RPS", "1"))
VT_RPS = float(os.getenv("VT_RPS", "0.5"))


class AnalyzeRequest(BaseModel):
    text: str
    consent: bool | None = None


class ScanUrlRequest(BaseModel):
    url: str
    consent: bool | None = None


class ScanPageRequest(BaseModel):
    url: str
    content: str
    signals: Dict[str, object] | None = None
    consent: bool | None = None


class ReportRequest(BaseModel):
    url: str
    source: str | None = None
    notes: str | None = None


class ExplainRequest(BaseModel):
    text: str
    reasons: List[str]
    risk_level: str
    scam_probability: int


class ExplainResponse(BaseModel):
    explanation: str


class UrlFinding(BaseModel):
    url: str
    reputation: str
    domain_age_days: int | None
    phishing_similarity: str
    notes: List[str]


class AnalyzeResponse(BaseModel):
    id: str
    input: str
    scam_probability: int
    risk_score: int
    risk_level: str
    categories: Dict[str, float]
    reasons: List[str]
    patterns: List[str]
    url_findings: List[UrlFinding]
    threat_intel_status: Dict[str, str]
    scan_status: str
    ai_provider: str
    ai_model: str
    highlights: List[str]
    confidence: Dict[str, float]
    behavior_signals: Dict[str, object]
    created_at: str


class ScanResponse(BaseModel):
    id: str
    url: str
    scam_probability: int
    risk_score: int
    risk_level: str
    reasons: List[str]
    url_findings: List[UrlFinding]
    threat_intel_status: Dict[str, str]
    scan_status: str
    ai_provider: str
    ai_model: str
    highlights: List[str]
    confidence: Dict[str, float]
    behavior_signals: Dict[str, object]
    created_at: str


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            input TEXT,
            scam_probability INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            categories TEXT,
            reasons TEXT,
            patterns TEXT,
            url_findings TEXT,
            threat_intel_status TEXT,
            scan_status TEXT,
            ai_provider TEXT,
            ai_model TEXT,
            created_at TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            url TEXT,
            source TEXT,
            notes TEXT,
            created_at TEXT
        )
        """
    )
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(scans)").fetchall()}
    for column, col_type in [
        ("threat_intel_status", "TEXT"),
        ("scan_status", "TEXT"),
        ("ai_provider", "TEXT"),
        ("ai_model", "TEXT"),
    ]:
        if column not in existing:
            cursor.execute(f"ALTER TABLE scans ADD COLUMN {column} {col_type}")
    conn.commit()
    conn.close()


def store_scan(payload: AnalyzeResponse) -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (id, input, scam_probability, risk_score, risk_level, categories, reasons, patterns, url_findings, threat_intel_status, scan_status, ai_provider, ai_model, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.id,
            payload.input,
            payload.scam_probability,
            payload.risk_score,
            payload.risk_level,
            json.dumps(payload.categories),
            json.dumps(payload.reasons),
            json.dumps(payload.patterns),
            json.dumps([finding.model_dump() for finding in payload.url_findings]),
            json.dumps(payload.threat_intel_status),
            payload.scan_status,
            payload.ai_provider,
            payload.ai_model,
            payload.created_at,
        ),
    )
    conn.commit()
    conn.close()


def redact_response(response: AnalyzeResponse) -> AnalyzeResponse:
    redacted = response.model_copy()
    redacted.input = "[redacted]"
    return redacted


def update_scan(scan_id: str, payload: AnalyzeResponse) -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE scans
        SET scam_probability = ?, risk_score = ?, risk_level = ?, categories = ?, reasons = ?, patterns = ?, url_findings = ?, threat_intel_status = ?, scan_status = ?, ai_provider = ?, ai_model = ?, created_at = ?
        WHERE id = ?
        """,
        (
            payload.scam_probability,
            payload.risk_score,
            payload.risk_level,
            json.dumps(payload.categories),
            json.dumps(payload.reasons),
            json.dumps(payload.patterns),
            json.dumps([finding.model_dump() for finding in payload.url_findings]),
            json.dumps(payload.threat_intel_status),
            payload.scan_status,
            payload.ai_provider,
            payload.ai_model,
            payload.created_at,
            scan_id,
        ),
    )
    conn.commit()
    conn.close()


def store_report(payload: ReportRequest) -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO reports (id, url, source, notes, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            payload.url,
            payload.source or "web",
            payload.notes or "",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def extract_urls(text: str) -> List[str]:
    return URL_REGEX.findall(text)


def normalize_text(text: str) -> str:
    return text.lower()


def match_patterns(text: str) -> Tuple[List[str], int]:
    patterns = []
    score = 0
    for label, phrases, weight in [
        ("Urgency", URGENCY, 18),
        ("Reward bait", REWARD, 16),
        ("Authority impersonation", AUTHORITY, 14),
        ("Financial request", FINANCIAL, 20),
        ("Crypto scam", CRYPTO, 20),
    ]:
        hits = [phrase for phrase in phrases if phrase in text]
        if hits:
            patterns.append(f"{label}: {', '.join(hits)}")
            score += weight
    return patterns, min(score, 100)


def extract_highlights(text: str) -> List[str]:
    hits = []
    for phrase in URGENCY + REWARD + AUTHORITY + FINANCIAL + CRYPTO:
        if phrase in text and phrase not in hits:
            hits.append(phrase)
    return hits[:12]


def confidence_band(score: float) -> Dict[str, float]:
    confidence = min(0.98, max(0.5, score + 0.15))
    return {
        "low": max(0.0, score - 0.15),
        "mid": score,
        "high": min(1.0, score + 0.15),
        "confidence": confidence,
    }


def fallback_explanation(payload: ExplainRequest) -> str:
    reasons = ", ".join(payload.reasons[:4]) if payload.reasons else "pattern-based signals"
    return (
        f"The system flagged this as {payload.risk_level} risk with a {payload.scam_probability}% scam probability "
        f"because it detected {reasons}. Consider avoiding the link, verifying the sender, and not sharing sensitive data."
    )


async def openai_explain(payload: ExplainRequest) -> str:
    if not OPENAI_API_KEY:
        return fallback_explanation(payload)
    prompt = (
        "Explain to a non-technical user why the following content was flagged as a scam risk. "
        "Use short bullet points and plain language. "
        f"Risk level: {payload.risk_level}. Scam probability: {payload.scam_probability}%.\n"
        f"Reasons: {', '.join(payload.reasons)}\n"
        f"Content:\n{payload.text}\n"
    )
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                "https://api.openai.com/v1/responses",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
                json={"model": OPENAI_MODEL, "input": prompt},
            )
            response.raise_for_status()
            data = response.json()
        output_text = None
        for item in data.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    output_text = content.get("text")
                    break
        return output_text or fallback_explanation(payload)
    except Exception:
        return fallback_explanation(payload)


def score_text_ai(text: str) -> Dict[str, float]:
    score = 0.1
    if any(phrase in text for phrase in URGENCY + REWARD):
        score += 0.35
    if any(phrase in text for phrase in FINANCIAL):
        score += 0.25
    if any(phrase in text for phrase in CRYPTO):
        score += 0.25
    if any(phrase in text for phrase in AUTHORITY):
        score += 0.2
    score = min(score, 0.95)

    categories = {
        "safe": max(0.05, 1 - score),
        "spam": min(0.2, score * 0.25),
        "phishing": min(0.9, score * 0.6),
        "financial_scam": min(0.9, score * 0.45),
        "crypto_scam": min(0.9, score * 0.4),
    }

    total = sum(categories.values())
    normalized = {k: v / total for k, v in categories.items()}
    return normalized


async def score_text_model_api(text: str) -> Dict[str, float] | None:
    if not MODEL_API_URL or not MODEL_API_KEY:
        return None
    headers = {"Authorization": f"Bearer {MODEL_API_KEY}"}
    payload = {"inputs": text}
    try:
        async with httpx.AsyncClient(timeout=MODEL_TIMEOUT) as client:
            response = await client.post(MODEL_API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
    except Exception:
        return None

    global MODEL_DEBUG_LOG_ONCE
    if MODEL_DEBUG_LOG_ONCE:
        logger.info("Model response sample: %s", data)
        MODEL_DEBUG_LOG_ONCE = False

    # Expected HF format: list of {label, score} or list of lists
    predictions = []
    if isinstance(data, list) and data and isinstance(data[0], dict):
        predictions = data
    elif isinstance(data, list) and data and isinstance(data[0], list):
        predictions = data[0]
    else:
        return None

    buckets = {
        "safe": 0.0,
        "spam": 0.0,
        "phishing": 0.0,
        "financial_scam": 0.0,
        "crypto_scam": 0.0,
    }

    for item in predictions:
        label = str(item.get("label", "")).lower().strip()
        score = float(item.get("score", 0))

        if label in {"legit", "benign", "safe", "ham", "not_phishing", "non-phishing", "legitimate"}:
            buckets["safe"] += score
            continue

        if "phish" in label or label in {"phishing", "malicious"}:
            buckets["phishing"] += score
            continue

        if "spam" in label:
            buckets["spam"] += score
            continue

        if "fraud" in label or "financial" in label:
            buckets["financial_scam"] += score
            continue

        if "crypto" in label or "wallet" in label:
            buckets["crypto_scam"] += score
            continue

        # Fallback: treat unknown labels as phishing signal
        buckets["phishing"] += score

    total = sum(buckets.values())
    if total == 0:
        return None
    return {k: v / total for k, v in buckets.items()}


def inspect_domain(url: str) -> UrlFinding:
    notes = []
    reputation = "Unknown"
    phishing_similarity = "Low"
    domain_age_days = None

    domain_match = re.search(r"https?://([^/]+)", url)
    domain = domain_match.group(1) if domain_match else url
    domain_lower = domain.lower()

    if any(domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS):
        notes.append("Suspicious TLD detected")

    if any(shortener == domain_lower for shortener in SHORTENERS):
        notes.append("Shortened URL")

    if "login" in domain_lower or "verify" in domain_lower or "secure" in domain_lower:
        notes.append("Credential harvesting keyword")

    for brand in BRANDS:
        if brand in domain_lower and not domain_lower.startswith(brand):
            phishing_similarity = "High"
            notes.append(f"Brand impersonation detected: {brand}")
            break

    if domain_lower in KNOWN_BAD_DOMAINS:
        reputation = "Known scam domain"
        domain_age_days = 2
        notes.append("Listed in local scam database")
    elif notes:
        reputation = "Suspicious"
        domain_age_days = 7 if any(tld for tld in SUSPICIOUS_TLDS if domain_lower.endswith(tld)) else 30

    return UrlFinding(
        url=url,
        reputation=reputation,
        domain_age_days=domain_age_days,
        phishing_similarity=phishing_similarity,
        notes=notes,
    )




def openphish_check(url: str) -> Tuple[bool, List[str], str]:
    return False, [], "disabled"


def phishtank_feed_check(url: str) -> Tuple[bool, List[str], str]:
    return False, [], "disabled"








class RateLimiter:
    def __init__(self, rate_per_sec: float, capacity: float = 1.0) -> None:
        self.rate_per_sec = max(rate_per_sec, 0.0)
        self.capacity = max(capacity, 1.0)
        self.tokens = self.capacity
        self.last_check = time.monotonic()

    def allow(self) -> bool:
        if self.rate_per_sec <= 0:
            return False
        now = time.monotonic()
        elapsed = now - self.last_check
        self.last_check = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class ThreatCache:
    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str], Tuple[float, bool, List[str]]] = {}

    def get(self, provider: str, url: str) -> Tuple[bool | None, List[str], bool]:
        key = (provider, url)
        entry = self._store.get(key)
        if not entry:
            return None, [], False
        expires_at, hit, reasons = entry
        if time.time() > expires_at:
            self._store.pop(key, None)
            return None, [], False
        return hit, reasons, True

    def set(self, provider: str, url: str, hit: bool, reasons: List[str], ttl: int) -> None:
        self._store[(provider, url)] = (time.time() + ttl, hit, reasons)


THREAT_CACHE = ThreatCache()
RL_URLHAUS = RateLimiter(URLHAUS_RPS, capacity=2)
RL_VT = RateLimiter(VT_RPS, capacity=2)


def urlhaus_check(urls: List[str]) -> Tuple[bool, List[str], str]:
    if not urls:
        return False, [], "not_applicable"

    cached_hits = []
    uncached_urls = []
    for url in urls:
        cached_hit, cached_reasons, cached = THREAT_CACHE.get("urlhaus", url)
        if cached:
            if cached_hit:
                cached_hits.append((url, cached_reasons))
        else:
            uncached_urls.append(url)

    if not uncached_urls:
        return bool(cached_hits), ["URLhaus match"] if cached_hits else [], "cached"

    if not RL_URLHAUS.allow():
        return bool(cached_hits), ["URLhaus match"] if cached_hits else [], "rate_limited"

    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            for url in uncached_urls:
                try:
                    response = client.post(
                        "https://urlhaus-api.abuse.ch/v1/url/",
                        data={"url": url, "token": URLHAUS_API_KEY} if URLHAUS_API_KEY else {"url": url},
                    )
                    if response.status_code >= 400:
                        logger.warning("URLhaus HTTP %s for %s: %s", response.status_code, url, response.text)
                    response.raise_for_status()
                    data = response.json()
                    if data.get("query_status") == "ok" and data.get("url_status") in {"online", "offline"}:
                        THREAT_CACHE.set("urlhaus", url, True, ["URLhaus malicious URL"], URLHAUS_TTL)
                    else:
                        THREAT_CACHE.set("urlhaus", url, False, [], URLHAUS_TTL)
                except Exception as inner_exc:
                    logger.exception("URLhaus request failed for %s: %s", url, inner_exc)
    except Exception:
        logger.exception("URLhaus batch failure")
        return bool(cached_hits), ["URLhaus match"] if cached_hits else [], "error"

    return bool(cached_hits), ["URLhaus match"] if cached_hits else [], "ok"


def virustotal_check(url: str) -> Tuple[bool, List[str], str]:
    if not VIRUSTOTAL_API_KEY:
        return False, [], "no_key"

    cached_hit, cached_reasons, cached = THREAT_CACHE.get("virustotal", url)
    if cached:
        return bool(cached_hit), cached_reasons, "cached"

    if not RL_VT.allow():
        return False, [], "rate_limited"
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            response = client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                data={"url": url},
            )
            response.raise_for_status()
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if not analysis_id:
                return False, []

            analysis = client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
            analysis.raise_for_status()
            stats = analysis.json().get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                reasons = [f"VirusTotal detections: malicious={malicious}, suspicious={suspicious}"]
                THREAT_CACHE.set("virustotal", url, True, reasons, VT_TTL)
                return True, reasons, "hit"
            THREAT_CACHE.set("virustotal", url, False, [], VT_TTL)
    except Exception:
        return False, [], "error"
    return False, [], "ok"


def score_urls(findings: List[UrlFinding]) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    for finding in findings:
        if finding.reputation == "Known scam domain":
            score += 35
            reasons.append("Known scam domain detected")
        elif finding.reputation == "Suspicious":
            score += 20
            reasons.append("Suspicious domain detected")
        if finding.phishing_similarity == "High":
            score += 20
            reasons.append("Phishing domain similarity")
        if any("Shortened" in note for note in finding.notes):
            score += 10
            reasons.append("Shortened URL obscures destination")
    return min(score, 100), reasons


def enrich_with_threat_intel(findings: List[UrlFinding]) -> Tuple[int, List[str], Dict[str, str]]:
    score = 0
    reasons: List[str] = []
    status: Dict[str, str] = {}
    urls = [finding.url for finding in findings]
    urlhaus_hit, urlhaus_reasons, urlhaus_status = urlhaus_check(urls)
    status["urlhaus"] = urlhaus_status
    if urlhaus_hit:
        score += 35
        reasons.extend(urlhaus_reasons)
        for finding in findings:
            if finding.reputation == "Unknown":
                finding.reputation = "Known scam domain"
                finding.notes.append("Flagged by URLhaus")

    for finding in findings:
        openphish_hit, openphish_reasons, openphish_status = openphish_check(finding.url)
        status["openphish"] = merge_status(status.get("openphish"), openphish_status)
        if openphish_hit:
            score += 30
            reasons.extend(openphish_reasons)
            finding.reputation = "Known scam domain"
            finding.notes.append("Flagged by OpenPhish feed")

        phishtank_hit, phishtank_reasons, phishtank_status = phishtank_feed_check(finding.url)
        status["phishtank_feed"] = merge_status(status.get("phishtank_feed"), phishtank_status)
        if phishtank_hit:
            score += 25
            reasons.extend(phishtank_reasons)
            finding.reputation = "Known scam domain"
            finding.notes.append("Flagged by PhishTank feed")

        vt_hit, vt_reasons, vt_status = virustotal_check(finding.url)
        status["virustotal"] = merge_status(status.get("virustotal"), vt_status)
        if vt_hit:
            score += 45
            reasons.extend(vt_reasons)
            finding.reputation = "Known scam domain"
            finding.notes.append("Flagged by VirusTotal")

    return min(score, 100), list(dict.fromkeys(reasons)), status


def build_reasons(patterns: List[str], url_reasons: List[str]) -> List[str]:
    reasons = []
    for pattern in patterns:
        if pattern.startswith("Urgency"):
            reasons.append("Urgent language detected")
        if pattern.startswith("Reward"):
            reasons.append("Reward bait language")
        if pattern.startswith("Authority"):
            reasons.append("Authority impersonation cues")
        if pattern.startswith("Financial"):
            reasons.append("Financial request detected")
        if pattern.startswith("Crypto"):
            reasons.append("Crypto scam indicators")
    reasons.extend(url_reasons)
    return list(dict.fromkeys(reasons))


def compute_risk_score(ai_score: float, pattern_score: int, url_score: int) -> int:
    weighted = ai_score * 100 * 0.4 + pattern_score * 0.2 + url_score * 0.4
    return max(0, min(100, int(round(weighted))))


def risk_level(score: int) -> str:
    if score >= 75:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def merge_status(current: str | None, incoming: str) -> str:
    priority = {
        "hit": 6,
        "rate_limited": 5,
        "error": 4,
        "cached": 3,
        "ok": 2,
        "pending": 1,
        "no_key": 0,
        "not_applicable": 0,
    }
    if current is None:
        return incoming
    return incoming if priority.get(incoming, 0) > priority.get(current, 0) else current


def base_threat_status(urls: List[str]) -> Dict[str, str]:
    if not urls:
        return {
            "urlhaus": "not_applicable",
            "virustotal": "not_applicable",
        }
    return {
        "urlhaus": "pending" if urls else "not_applicable",
        "virustotal": "pending" if VIRUSTOTAL_API_KEY else "no_key",
    }


def apply_intel_update(
    response: AnalyzeResponse,
    url_findings: List[UrlFinding],
    intel_score: int,
    intel_reasons: List[str],
    intel_status: Dict[str, str],
) -> AnalyzeResponse:
    url_score, url_reasons = score_urls(url_findings)
    risk_score_value = compute_risk_score(
        1 - response.categories["safe"],
        match_patterns(normalize_text(response.input))[1],
        min(100, url_score + intel_score),
    )
    reasons = build_reasons(match_patterns(normalize_text(response.input))[0], url_reasons + intel_reasons)
    scan_status = "complete"
    response.risk_score = risk_score_value
    response.scam_probability = int(round(max((1 - response.categories["safe"]) * 100, risk_score_value * 0.9)))
    response.risk_level = risk_level(risk_score_value)
    response.reasons = reasons
    response.url_findings = url_findings
    response.threat_intel_status = intel_status
    response.scan_status = scan_status
    response.created_at = datetime.now(timezone.utc).isoformat()
    return response


def build_scan_response(response: AnalyzeResponse, url: str) -> ScanResponse:
    return ScanResponse(
        id=response.id,
        url=url,
        scam_probability=response.scam_probability,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
        reasons=response.reasons,
        url_findings=response.url_findings,
        threat_intel_status=response.threat_intel_status,
        scan_status=response.scan_status,
        ai_provider=response.ai_provider,
        ai_model=response.ai_model,
        highlights=response.highlights,
        confidence=response.confidence,
        behavior_signals=response.behavior_signals,
        created_at=response.created_at,
    )


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, background_tasks: BackgroundTasks) -> AnalyzeResponse:
    response = await analyze_text_and_urls(
        payload.text,
        background_tasks,
        consent=bool(payload.consent),
    )
    return response


async def analyze_text_and_urls(
    text: str,
    background_tasks: BackgroundTasks,
    url_override: List[str] | None = None,
    behavior_signals: Dict[str, object] | None = None,
    consent: bool = False,
) -> AnalyzeResponse:
    normalized = normalize_text(text)
    patterns, pattern_score = match_patterns(normalized)
    urls = url_override if url_override is not None else extract_urls(text)
    url_findings = [inspect_domain(url) for url in urls]
    url_score, url_reasons = score_urls(url_findings)

    categories = await score_text_model_api(text) or score_text_ai(normalized)
    ai_primary = 1 - categories["safe"]
    highlights = extract_highlights(normalized)
    confidence = confidence_band(ai_primary)
    behavior_signals = behavior_signals or {}
    behavior_score = int(behavior_signals.get("behavior_score", 0))
    behavior_reasons = behavior_signals.get("behavior_reasons", [])

    risk_score_value = compute_risk_score(ai_primary, pattern_score, min(100, url_score + behavior_score))
    scam_probability = int(round(max(ai_primary * 100, risk_score_value * 0.9)))
    risk = risk_level(risk_score_value)

    reasons = build_reasons(patterns, url_reasons)
    reasons.extend(behavior_reasons)
    if not reasons and scam_probability > 60:
        reasons.append("Statistical anomaly detected by AI model")
    if not reasons:
        reasons.append("No strong scam indicators detected")

    threat_status = base_threat_status(urls)
    scan_status = "pending" if urls and any(value == "pending" for value in threat_status.values()) else "complete"

    response = AnalyzeResponse(
        id=str(uuid.uuid4()),
        input=text,
        scam_probability=scam_probability,
        risk_score=risk_score_value,
        risk_level=risk,
        categories=categories,
        reasons=reasons,
        patterns=patterns,
        url_findings=url_findings,
        threat_intel_status=threat_status,
        scan_status=scan_status,
        ai_provider=MODEL_PROVIDER if MODEL_API_URL and MODEL_API_KEY else "rules",
        ai_model=MODEL_NAME if MODEL_API_URL and MODEL_API_KEY else "rules-engine",
        highlights=highlights,
        confidence=confidence,
        behavior_signals=behavior_signals,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    store_scan(redact_response(response) if not consent else response)

    if scan_status == "pending":
        background_tasks.add_task(run_threat_enrichment, response, consent)
    return response


def run_threat_enrichment(response: AnalyzeResponse, consent: bool) -> None:
    url_findings = [inspect_domain(url.url) for url in response.url_findings]
    intel_score, intel_reasons, intel_status = enrich_with_threat_intel(url_findings)
    updated = apply_intel_update(response, url_findings, intel_score, intel_reasons, intel_status)
    update_scan(response.id, redact_response(updated) if not consent else updated)


@app.post("/scan-url", response_model=ScanResponse)
async def scan_url(payload: ScanUrlRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    response = await analyze_text_and_urls(
        payload.url,
        background_tasks,
        url_override=[payload.url],
        consent=bool(payload.consent),
    )
    return build_scan_response(response, payload.url)


@app.post("/scan-page", response_model=ScanResponse)
async def scan_page(payload: ScanPageRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    combined = f"{payload.url}\n\n{payload.content}"
    response = await analyze_text_and_urls(
        combined,
        background_tasks,
        url_override=[payload.url],
        behavior_signals=payload.signals,
        consent=bool(payload.consent),
    )
    return build_scan_response(response, payload.url)


@app.get("/history", response_model=List[AnalyzeResponse])
async def history() -> List[AnalyzeResponse]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, input, scam_probability, risk_score, risk_level, categories, reasons, patterns, url_findings, threat_intel_status, scan_status, ai_provider, ai_model, created_at FROM scans ORDER BY created_at DESC LIMIT 50"
    )
    rows = cursor.fetchall()
    conn.close()

    results: List[AnalyzeResponse] = []
    for row in rows:
        results.append(
            AnalyzeResponse(
                id=row[0],
                input=row[1],
                scam_probability=row[2],
                risk_score=row[3],
                risk_level=row[4],
                categories=json.loads(row[5]),
                reasons=json.loads(row[6]),
                patterns=json.loads(row[7]),
                url_findings=[UrlFinding(**finding) for finding in json.loads(row[8])],
                threat_intel_status=json.loads(row[9]) if row[9] else base_threat_status([]),
                scan_status=row[10] or "complete",
                ai_provider=row[11] or "rules",
                ai_model=row[12] or "rules-engine",
                created_at=row[13],
            )
        )
    return results


@app.get("/scan/{scan_id}", response_model=AnalyzeResponse)
async def scan_detail(scan_id: str) -> AnalyzeResponse:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, input, scam_probability, risk_score, risk_level, categories, reasons, patterns, url_findings, threat_intel_status, scan_status, ai_provider, ai_model, created_at FROM scans WHERE id = ?",
        (scan_id,),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return AnalyzeResponse(
        id=row[0],
        input=row[1],
        scam_probability=row[2],
        risk_score=row[3],
        risk_level=row[4],
        categories=json.loads(row[5]),
        reasons=json.loads(row[6]),
        patterns=json.loads(row[7]),
        url_findings=[UrlFinding(**finding) for finding in json.loads(row[8])],
        threat_intel_status=json.loads(row[9]) if row[9] else base_threat_status([]),
        scan_status=row[10] or "complete",
        ai_provider=row[11] or "rules",
        ai_model=row[12] or "rules-engine",
        highlights=[],
        confidence={"low": 0.0, "mid": 0.0, "high": 0.0, "confidence": 0.0},
        behavior_signals={},
        created_at=row[13],
    )


@app.get("/feeds/status")
async def feeds_status() -> Dict[str, object]:
    return {
        "feeds_disabled": True,
    }


@app.post("/feeds/refresh")
async def feeds_refresh() -> Dict[str, str]:
    return {
        "status": "disabled",
    }


@app.post("/report")
async def report(payload: ReportRequest) -> Dict[str, str]:
    store_report(payload)
    return {"status": "ok"}


@app.post("/explain", response_model=ExplainResponse)
async def explain(payload: ExplainRequest) -> ExplainResponse:
    explanation = await openai_explain(payload)
    return ExplainResponse(explanation=explanation)


@app.get("/metrics")
async def metrics() -> Dict[str, object]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    week_ago = datetime.now(timezone.utc).timestamp() - 7 * 24 * 60 * 60

    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE risk_level = 'High' AND strftime('%s', created_at) >= ?",
        (int(week_ago),),
    )
    blocked_week = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(risk_score) FROM scans WHERE risk_level = 'High'")
    total_risk_saved = cursor.fetchone()[0] or 0

    cursor.execute(
        "SELECT url, COUNT(*) AS c FROM reports GROUP BY url ORDER BY c DESC LIMIT 5"
    )
    top_reports = [{"url": row[0], "count": row[1]} for row in cursor.fetchall()]
    conn.close()

    return {
        "blocked_week": blocked_week,
        "total_risk_saved": int(total_risk_saved),
        "top_reports": top_reports,
    }
