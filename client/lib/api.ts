export type CategoryScores = {
  safe: number;
  spam: number;
  phishing: number;
  financial_scam: number;
  crypto_scam: number;
};

export type UrlFinding = {
  url: string;
  reputation: string;
  domain_age_days: number | null;
  phishing_similarity: string;
  notes: string[];
};

export type AnalysisResult = {
  id: string;
  input: string;
  scam_probability: number;
  risk_score: number;
  risk_level: "Low" | "Medium" | "High";
  categories: CategoryScores;
  reasons: string[];
  patterns: string[];
  url_findings: UrlFinding[];
  threat_intel_status: Record<string, string>;
  scan_status: string;
  ai_provider: string;
  ai_model: string;
  highlights: string[];
  confidence: {
    low: number;
    mid: number;
    high: number;
    confidence: number;
  };
  behavior_signals: Record<string, unknown>;
  threat_casefile: {
    archetype: string;
    victim_persona: string;
    operator_tactic: string;
    attack_stage: string;
    next_move_prediction: string;
    possible_outcome: string;
    narrative: string;
    immediate_actions: string[];
    campaign_signature: string[];
    mutation_risk: number;
  };
  manipulation_map: {
    fear: number;
    urgency: number;
    authority: number;
    greed: number;
    trust: number;
    confusion: number;
    pressure_points: { label: string; trigger: string; meaning: string }[];
    summary: string;
  };
  impact_forecast: {
    primary_target: string;
    likely_damage: string;
    loss_window: string;
    intervention_message: string;
    safe_alternative: string;
    escalation_path: string[];
  };
  created_at: string;
};

const FALLBACK_API_BASE_URL = "http://localhost:8000";
const HISTORY_KEY = "cybershield-history";
const LATEST_KEY = "cybershield-latest";
let inMemoryLatest: AnalysisResult | null = null;
let persistPreference: boolean = true;

export function getApiBaseUrl() {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  return (configured || FALLBACK_API_BASE_URL).replace(/\/+$/, "");
}

export async function analyzeMessage(message: string, consent: boolean): Promise<AnalysisResult> {
  const response = await fetch(`${getApiBaseUrl()}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: message, consent }),
  });

  if (!response.ok) {
    throw new Error("Analysis failed. Backend unavailable.");
  }

  const data = await response.json();
  return normalizeResult(data);
}

export async function fetchHistory(): Promise<AnalysisResult[]> {
  const response = await fetch(`${getApiBaseUrl()}/history`);
  if (!response.ok) {
    throw new Error("Failed to fetch history.");
  }
  const data = await response.json();
  return (data as AnalysisResult[]).map(normalizeResult);
}

export async function fetchScan(scanId: string): Promise<AnalysisResult> {
  const response = await fetch(`${getApiBaseUrl()}/scan/${scanId}`);
  if (!response.ok) {
    throw new Error("Failed to fetch scan.");
  }
  const data = await response.json();
  return normalizeResult(data);
}

export function saveLatest(result: AnalysisResult, persist?: boolean) {
  if (typeof window === "undefined") return;
  if (typeof persist === "boolean") {
    persistPreference = persist;
  }
  const shouldPersist = persistPreference;
  inMemoryLatest = result;
  if (!shouldPersist) return;
  localStorage.setItem(LATEST_KEY, JSON.stringify(result));
  const history = getHistory();
  history.unshift(result);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 50)));
}

export function getLatest(): AnalysisResult | null {
  if (typeof window === "undefined") return null;
  if (inMemoryLatest) return inMemoryLatest;
  const raw = localStorage.getItem(LATEST_KEY);
  return raw ? normalizeResult(JSON.parse(raw)) : null;
}

export function getHistory(): AnalysisResult[] {
  if (typeof window === "undefined") return [];
  const raw = localStorage.getItem(HISTORY_KEY);
  return raw ? (JSON.parse(raw) as AnalysisResult[]).map(normalizeResult) : [];
}

function normalizeResult(data: AnalysisResult): AnalysisResult {
  return {
    ...data,
    threat_intel_status: data.threat_intel_status ?? {
      urlhaus: "unknown",
      virustotal: "unknown",
    },
    scan_status: data.scan_status ?? "complete",
    ai_provider: data.ai_provider ?? "heuristic-intelligence",
    ai_model: data.ai_model ?? "behavioral-risk-engine",
    highlights: data.highlights ?? [],
    confidence: data.confidence ?? { low: 0, mid: 0, high: 0, confidence: 0 },
    behavior_signals: data.behavior_signals ?? {},
    threat_casefile: data.threat_casefile ?? {
      archetype: "Unclassified Threat",
      victim_persona: "General-purpose target",
      operator_tactic: "Unknown",
      attack_stage: "Unknown",
      next_move_prediction: "No prediction available.",
      possible_outcome: "Unknown",
      narrative: "No casefile available.",
      immediate_actions: [],
      campaign_signature: [],
      mutation_risk: 0,
    },
    manipulation_map: data.manipulation_map ?? {
      fear: 0,
      urgency: 0,
      authority: 0,
      greed: 0,
      trust: 0,
      confusion: 0,
      pressure_points: [],
      summary: "No manipulation map available.",
    },
    impact_forecast: data.impact_forecast ?? {
      primary_target: "Unknown",
      likely_damage: "Unknown",
      loss_window: "Unknown",
      intervention_message: "Pause and verify before taking action.",
      safe_alternative: "Use an official and trusted channel.",
      escalation_path: [],
    },
  };
}
