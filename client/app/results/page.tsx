"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AnalysisResult, fetchScan, getApiBaseUrl, getLatest, saveLatest } from "../../lib/api";
import { Logo } from "../../components/Logo";
import { RiskMeter } from "../../components/RiskMeter";
import { ThreatFeedStatus } from "../../components/ThreatFeedStatus";

const manipulationKeys = [
  { key: "fear", label: "Fear" },
  { key: "urgency", label: "Urgency" },
  { key: "authority", label: "Authority" },
  { key: "greed", label: "Greed" },
  { key: "trust", label: "Trust Hijack" },
  { key: "confusion", label: "Confusion" },
] as const;

function StatTile({ label, value, tone = "text-white" }: { label: string; value: string; tone?: string }) {
  return (
    <div className="metric-card">
      <p className="micro-label">{label}</p>
      <p className={`mt-3 text-xl font-semibold ${tone}`}>{value}</p>
    </div>
  );
}

export default function ResultsPage() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [explanation, setExplanation] = useState("");
  const [explaining, setExplaining] = useState(false);
  const router = useRouter();

  useEffect(() => {
    setResult(getLatest());
  }, []);

  useEffect(() => {
    if (!result || result.scan_status !== "pending") return;
    const interval = setInterval(async () => {
      try {
        const updated = await fetchScan(result.id);
        setResult(updated);
        saveLatest(updated);
        if (updated.scan_status !== "pending") clearInterval(interval);
      } catch {
        clearInterval(interval);
      }
    }, 3500);
    return () => clearInterval(interval);
  }, [result?.id, result?.scan_status]);

  if (!result) {
    return (
      <div className="app-shell">
        <Logo />
        <div className="mt-10 intelligence-panel">
          <p className="text-slate-300">No analysis found. Run a scan to see the current intelligence output.</p>
          <button className="app-button-primary mt-4" onClick={() => router.push("/analyze")}>
            Open Analyzer
          </button>
        </div>
      </div>
    );
  }

  const casefile = result.threat_casefile;
  const impact = result.impact_forecast;
  const manipulation = result.manipulation_map;
  const riskTone =
    result.risk_level === "High" ? "text-rose-300" : result.risk_level === "Medium" ? "text-amber-300" : "text-emerald-300";
  const topCategory = Object.entries(result.categories).sort((a, b) => b[1] - a[1])[0];

  return (
    <div className="app-shell">
      <header className="app-header">
        <Logo />
        <div className="app-actions">
          <button className="app-button-secondary" onClick={() => router.push("/analyze")}>
            New Scan
          </button>
          <button className="app-button-secondary" onClick={() => router.push("/history")}>
            Command Center
          </button>
        </div>
      </header>

      <section className="mt-10 intelligence-grid">
        <div className="space-y-6">
          <div className="intelligence-panel">
            <p className="micro-label">Threat Casefile</p>
            <div className="mt-4 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
              <div>
                <h1 className="text-3xl font-display text-white md:text-4xl">{casefile.archetype}</h1>
                <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300 md:text-base">{casefile.narrative}</p>
              </div>
              <div className="metric-card min-w-[220px]">
                <p className="micro-label">Predicted attacker success</p>
                <p className={`mt-3 text-3xl font-semibold ${riskTone}`}>{result.scam_probability}%</p>
              </div>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatTile label="Risk Level" value={result.risk_level.toUpperCase()} tone={riskTone} />
              <StatTile label="Victim Persona" value={casefile.victim_persona} />
              <StatTile label="Primary Target" value={impact.primary_target} />
              <StatTile label="Mutation Risk" value={`${casefile.mutation_risk}/100`} tone="text-cyan-300" />
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-[1.02fr_0.98fr]">
            <div className="intelligence-panel">
              <p className="micro-label">Evidence And Confidence</p>
              <div className="mt-4 flex items-center justify-between gap-4">
                <div className="text-xs text-slate-400">
                  <p>{new Date(result.created_at).toLocaleString()}</p>
                  <p>{Math.round(result.confidence.confidence * 100)}% confidence</p>
                </div>
                <div className="text-right text-xs text-slate-500">
                  {topCategory ? `${topCategory[0].replace("_", " ")} ${Math.round(topCategory[1] * 100)}%` : "Unknown"}
                </div>
              </div>
              <p className="mt-5 whitespace-pre-line rounded-[1.5rem] border border-slate-800 bg-slate-950/75 p-5 text-sm leading-7 text-slate-200">
                {result.input}
              </p>
              <div className="mt-5 grid gap-4 md:grid-cols-2">
                <RiskMeter score={result.risk_score} />
                <div className="metric-card">
                  <p className="micro-label">Confidence Band</p>
                  <p className="mt-3 text-sm leading-7 text-slate-300">
                    Low {Math.round(result.confidence.low * 100)}% / Mid {Math.round(result.confidence.mid * 100)}% / High {Math.round(result.confidence.high * 100)}%
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <ThreatFeedStatus
                statusMap={result.threat_intel_status}
                scanStatus={result.scan_status}
                aiProvider={result.ai_provider}
                aiModel={result.ai_model}
              />
              <div className="intelligence-panel">
                <p className="micro-label">Threat DNA</p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {casefile.campaign_signature.length ? (
                    casefile.campaign_signature.map((tag) => (
                      <span key={tag} className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-200">
                        {tag}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-slate-400">No signature tokens captured.</span>
                  )}
                </div>
                <div className="mt-6 signal-list">
                  {result.reasons.map((reason) => (
                    <div key={reason} className="signal-list-item text-sm text-slate-200">
                      {reason}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="intelligence-panel">
            <p className="micro-label">Attack Forecast</p>
            <div className="mt-4 signal-list">
              <div className="signal-list-item">
                <p className="micro-label">Likely next move</p>
                <p className="mt-2 text-sm leading-7 text-slate-200">{casefile.next_move_prediction}</p>
              </div>
              <div className="signal-list-item">
                <p className="micro-label">Likely damage</p>
                <p className="mt-2 text-sm leading-7 text-slate-200">{impact.likely_damage}</p>
              </div>
              <div className="signal-list-item">
                <p className="micro-label">Loss window</p>
                <p className="mt-2 text-sm leading-7 text-slate-200">{impact.loss_window}</p>
              </div>
              <div className="rounded-2xl border border-amber-400/20 bg-amber-400/10 p-4">
                <p className="micro-label text-amber-200">Intervention</p>
                <p className="mt-2 text-sm leading-7 text-amber-50">{impact.intervention_message}</p>
              </div>
            </div>
          </div>

          <div className="intelligence-panel">
            <p className="micro-label">Psychological Manipulation Map</p>
            <p className="mt-3 text-sm leading-7 text-slate-300">{manipulation.summary}</p>
            <div className="mt-5 space-y-3">
              {manipulationKeys.map(({ key, label }) => {
                const value = manipulation[key];
                return (
                  <div key={key}>
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span>{label}</span>
                      <span>{value}/100</span>
                    </div>
                    <div className="mt-2 h-2 rounded-full bg-slate-800">
                      <div
                        className="h-2 rounded-full bg-gradient-to-r from-cyan-400 via-amber-400 to-rose-500"
                        style={{ width: `${value}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-6 signal-list">
              {manipulation.pressure_points.map((point, index) => (
                <div key={`${point.trigger}-${index}`} className="signal-list-item">
                  <p className="micro-label text-rose-200">{point.label}</p>
                  <p className="mt-2 text-sm text-white">{point.trigger}</p>
                  <p className="mt-2 text-xs leading-6 text-slate-400">{point.meaning}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="intelligence-panel">
            <p className="micro-label">Safer Response Playbook</p>
            <div className="mt-4 signal-list">
              {casefile.immediate_actions.map((action) => (
                <div key={action} className="signal-list-item text-sm leading-7 text-slate-200">
                  {action}
                </div>
              ))}
            </div>
            <div className="mt-5 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-4">
              <p className="micro-label text-cyan-200">Safe Alternative</p>
              <p className="mt-2 text-sm leading-7 text-cyan-50">{impact.safe_alternative}</p>
            </div>
            <div className="mt-5 scan-rail pl-6">
              <div className="signal-list">
                {impact.escalation_path.map((step, index) => (
                  <div key={step} className="signal-list-item">
                    <div className="flex items-start gap-3">
                      <span className="trace-step-index mt-0.5">{index + 1}</span>
                      <span className="text-sm leading-6 text-slate-200">{step}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="intelligence-panel">
            <p className="micro-label">AI Copilot Brief</p>
            <p className="mt-3 text-sm leading-7 text-slate-400">
              Generate a structured explanation for security reporting, user education, and incident response workflows.
            </p>
            <button
              className="app-button-primary mt-4"
              onClick={async () => {
                setExplaining(true);
                try {
                  const res = await fetch(`${getApiBaseUrl()}/explain`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      text: result.input,
                      reasons: result.reasons,
                      risk_level: result.risk_level,
                      scam_probability: result.scam_probability,
                    }),
                  });
                  const data = await res.json();
                  setExplanation(data.explanation || "No explanation returned.");
                } catch {
                  setExplanation("Unable to generate explanation.");
                } finally {
                  setExplaining(false);
                }
              }}
              disabled={explaining}
            >
              {explaining ? "Generating Brief..." : "Generate Brief"}
            </button>
            {explanation && (
              <div className="mt-4 rounded-[1.5rem] border border-slate-800 bg-slate-950/75 p-4 text-sm leading-7 text-slate-200 whitespace-pre-line">
                {explanation}
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
