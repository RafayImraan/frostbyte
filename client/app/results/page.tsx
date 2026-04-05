"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AnalysisResult, fetchScan, getLatest, saveLatest } from "../../lib/api";
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
    <div className="rounded-2xl border border-slate-700 bg-midnight p-4">
      <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</p>
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
        if (updated.scan_status !== "pending") {
          clearInterval(interval);
        }
      } catch {
        clearInterval(interval);
      }
    }, 3500);
    return () => clearInterval(interval);
  }, [result?.id, result?.scan_status]);

  if (!result) {
    return (
      <div className="px-6 py-10 md:px-16 lg:px-24">
        <Logo />
        <div className="mt-10 rounded-2xl border border-slate-700 bg-carbon/80 p-6">
          <p className="text-slate-300">No analysis found. Run a scan to see results.</p>
          <button
            className="mt-4 rounded-full bg-neon px-5 py-2 font-semibold text-midnight"
            onClick={() => router.push("/analyze")}
          >
            Go to Analyzer
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
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between gap-4">
        <Logo />
        <div className="flex gap-3">
          <button
            className="rounded-full border border-slate-600 px-4 py-2 text-slate-200"
            onClick={() => router.push("/analyze")}
          >
            New Scan
          </button>
          <button
            className="rounded-full border border-slate-600 px-4 py-2 text-slate-200"
            onClick={() => router.push("/history")}
          >
            Command Center
          </button>
        </div>
      </header>

      <section className="mt-12 grid gap-8 lg:grid-cols-[1.5fr_1fr]">
        <div className="space-y-6">
          <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-7 shadow-haze">
            <p className="text-xs uppercase tracking-[0.28em] text-neon">Scam Intent Engine</p>
            <div className="mt-4 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
              <div>
                <h1 className="text-3xl font-display md:text-4xl">{casefile.archetype}</h1>
                <p className="mt-3 max-w-3xl text-slate-300">{casefile.narrative}</p>
              </div>
              <div className="min-w-[190px] rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3">
                <p className="text-xs text-slate-400">Predicted attacker success</p>
                <p className={`mt-2 text-3xl font-semibold ${riskTone}`}>{result.scam_probability}%</p>
              </div>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatTile label="Risk Level" value={result.risk_level.toUpperCase()} tone={riskTone} />
              <StatTile label="Victim Persona" value={casefile.victim_persona} />
              <StatTile label="Primary Target" value={impact.primary_target} />
              <StatTile label="Mutation Risk" value={`${casefile.mutation_risk}/100`} tone="text-cyan-300" />
            </div>

            <div className="mt-6 grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
              <div className="rounded-3xl border border-slate-700 bg-midnight p-5">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Attack Forecast</p>
                <div className="mt-4 space-y-4">
                  <div>
                    <p className="text-sm text-slate-400">Likely next move</p>
                    <p className="mt-1 text-sm text-slate-200">{casefile.next_move_prediction}</p>
                  </div>
                  <div>
                    <p className="text-sm text-slate-400">Likely damage</p>
                    <p className="mt-1 text-sm text-slate-200">{impact.likely_damage}</p>
                  </div>
                  <div>
                    <p className="text-sm text-slate-400">Loss window</p>
                    <p className="mt-1 text-sm text-slate-200">{impact.loss_window}</p>
                  </div>
                </div>
                <div className="mt-5 rounded-2xl border border-amber-400/20 bg-amber-400/10 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-amber-200">Intervention</p>
                  <p className="mt-2 text-sm text-amber-50">{impact.intervention_message}</p>
                </div>
              </div>

              <div className="rounded-3xl border border-slate-700 bg-midnight p-5">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Safe Response Playbook</p>
                <div className="mt-4 space-y-3">
                  {casefile.immediate_actions.map((action) => (
                    <div key={action} className="rounded-2xl border border-slate-700 bg-carbon/50 px-4 py-3 text-sm text-slate-200">
                      {action}
                    </div>
                  ))}
                </div>
                <div className="mt-5 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-cyan-200">Safe Alternative</p>
                  <p className="mt-2 text-sm text-cyan-50">{impact.safe_alternative}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
            <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Evidence</p>
                  <h2 className="mt-2 text-xl font-display">Scanned Input</h2>
                </div>
                <div className="text-right text-xs text-slate-400">
                  <p>{new Date(result.created_at).toLocaleString()}</p>
                  <p>{Math.round(result.confidence.confidence * 100)}% confidence</p>
                </div>
              </div>
              <p className="mt-5 whitespace-pre-line rounded-3xl border border-slate-700 bg-midnight p-5 text-sm leading-relaxed text-slate-200">
                {result.input}
              </p>

              <div className="mt-5 grid gap-4 md:grid-cols-2">
                <RiskMeter score={result.risk_score} />
                <div className="rounded-2xl border border-slate-700 bg-midnight p-4">
                  <p className="text-xs text-slate-400">Model leaning</p>
                  <p className="mt-2 text-xl font-semibold text-cyan-300">
                    {topCategory ? `${topCategory[0].replace("_", " ")} ${Math.round(topCategory[1] * 100)}%` : "Unknown"}
                  </p>
                  <p className="mt-2 text-xs text-slate-500">
                    Confidence band: low {Math.round(result.confidence.low * 100)}% / mid {Math.round(result.confidence.mid * 100)}% / high {Math.round(result.confidence.high * 100)}%
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

              <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Threat DNA</p>
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
                <div className="mt-6">
                  <p className="text-sm text-slate-400">Detected issues</p>
                  <div className="mt-3 space-y-2">
                    {result.reasons.map((reason) => (
                      <div key={reason} className="rounded-2xl border border-slate-700 bg-midnight px-4 py-3 text-sm text-slate-200">
                        {reason}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Psychological Manipulation Map</p>
            <p className="mt-2 text-sm text-slate-300">{manipulation.summary}</p>
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
            <div className="mt-6 space-y-3">
              {manipulation.pressure_points.map((point, index) => (
                <div key={`${point.trigger}-${index}`} className="rounded-2xl border border-slate-700 bg-midnight p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-rose-200">{point.label}</p>
                  <p className="mt-2 text-sm text-white">{point.trigger}</p>
                  <p className="mt-2 text-xs text-slate-400">{point.meaning}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Escalation Path</p>
            <div className="mt-4 space-y-3">
              {impact.escalation_path.map((step, index) => (
                <div key={step} className="rounded-2xl border border-slate-700 bg-midnight px-4 py-3 text-sm text-slate-200">
                  <span className="mr-3 inline-flex h-6 w-6 items-center justify-center rounded-full bg-rose-500/20 text-xs text-rose-200">
                    {index + 1}
                  </span>
                  {step}
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">AI Copilot Brief</p>
            <p className="mt-2 text-sm text-slate-400">
              Generates a plain-language explanation for security reporting, user awareness, and incident response workflows.
            </p>
            <button
              className="mt-4 rounded-full bg-neon px-4 py-2 text-sm font-semibold text-midnight"
              onClick={async () => {
                setExplaining(true);
                try {
                  const res = await fetch("http://localhost:8000/explain", {
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
              {explaining ? "Generating..." : "Generate Brief"}
            </button>
            {explanation && (
              <div className="mt-4 whitespace-pre-line rounded-3xl border border-slate-700 bg-midnight p-4 text-sm text-slate-200">
                {explanation}
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
