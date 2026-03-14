"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { fetchScan, getLatest, saveLatest, AnalysisResult } from "../../lib/api";
import { Logo } from "../../components/Logo";
import { RiskMeter } from "../../components/RiskMeter";
import { ThreatFeedStatus } from "../../components/ThreatFeedStatus";

export default function ResultsPage() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [feedUpdated, setFeedUpdated] = useState<string>("Live feeds: URLhaus + VirusTotal");
  const [feedNotice, setFeedNotice] = useState<string>("");
  const [explanation, setExplanation] = useState<string>("");
  const [explaining, setExplaining] = useState(false);
  const router = useRouter();

  useEffect(() => {
    setResult(getLatest());
  }, []);

  useEffect(() => {
    fetch("http://localhost:8000/feeds/status")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data) return;
        if (data.feeds_disabled) {
          setFeedNotice("");
          setFeedUpdated("Live feeds: URLhaus + VirusTotal");
          return;
        }
      })
      .catch(() => {});
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
      } catch (error) {
        clearInterval(interval);
      }
    }, 3500);
    return () => clearInterval(interval);
  }, [result?.id, result?.scan_status]);

  if (!result) {
    return (
      <div className="px-6 py-10 md:px-16 lg:px-24">
        <Logo />
        <div className="mt-10 bg-carbon/80 border border-slate-700 rounded-2xl p-6">
          <p className="text-slate-300">No analysis found. Run a scan to see results.</p>
          <button
            className="mt-4 px-5 py-2 rounded-full bg-neon text-midnight font-semibold"
            onClick={() => router.push("/analyze")}
          >
            Go to Analyzer
          </button>
        </div>
      </div>
    );
  }

  const feedHits = result
    ? Object.entries(result.threat_intel_status).filter(([, value]) => value === "hit")
    : [];
  const feedCount = result ? Object.keys(result.threat_intel_status).length : 0;
  const feedImpact = feedCount ? Math.round((feedHits.length / feedCount) * 100) : 0;
  const feedColor =
    feedImpact >= 60 ? "from-rose-500" : feedImpact >= 30 ? "from-amber-400" : "from-emerald-400";

  const categoryTop = result
    ? Object.entries(result.categories).sort((a, b) => b[1] - a[1])[0]
    : null;
  const oneLineExplanation = result
    ? `Likely ${result.risk_level.toLowerCase()} risk — model leans ${categoryTop ? categoryTop[0].replace("_", " ") : "unknown"} (${Math.round((categoryTop?.[1] ?? 0) * 100)}%) with confidence ${Math.round(result.confidence.confidence * 100)}%.`
    : "";

  return (
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between">
        <Logo />
        <div className="flex gap-3">
          <button
            className="px-4 py-2 rounded-full border border-slate-600 text-slate-200"
            onClick={() => router.push("/analyze")}
          >
            New Scan
          </button>
          <button
            className="px-4 py-2 rounded-full border border-slate-600 text-slate-200"
            onClick={() => router.push("/history")}
          >
            History
          </button>
        </div>
      </header>

      <section className="mt-12 grid lg:grid-cols-[2fr_1fr] gap-8">
        <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
          <p className="text-xs text-slate-400">Scanned Message</p>
          <p className="mt-3 text-sm text-slate-200 whitespace-pre-line">{result.input}</p>
          <div className="mt-6 grid md:grid-cols-2 gap-4">
            <div className="bg-midnight border border-slate-700 rounded-2xl p-4">
              <p className="text-xs text-slate-400">Scam Probability</p>
              <p className="text-2xl font-semibold mt-2">{result.scam_probability}%</p>
            </div>
            <div className="bg-midnight border border-slate-700 rounded-2xl p-4">
              <p className="text-xs text-slate-400">Risk Level</p>
              <p className={`text-2xl font-semibold mt-2 ${result.risk_level === "High" ? "text-ember" : result.risk_level === "Medium" ? "text-amber-300" : "text-emerald-300"}`}>
                {result.risk_level.toUpperCase()}
              </p>
            </div>
            <RiskMeter score={result.risk_score} />
            <div className="bg-midnight border border-slate-700 rounded-2xl p-4">
              <p className="text-xs text-slate-400">Analysis Timestamp</p>
              <p className="text-sm mt-2">{new Date(result.created_at).toLocaleString()}</p>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <ThreatFeedStatus
            statusMap={result.threat_intel_status}
            scanStatus={result.scan_status}
            aiProvider={result.ai_provider}
            aiModel={result.ai_model}
          />
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Live Threat Feed Meter</h2>
            <p className="text-xs text-slate-400 mt-1">Last updated: {feedUpdated}</p>
            {feedNotice && <p className="text-xs text-amber-300 mt-1">{feedNotice}</p>}
            <div className="mt-4 h-2 rounded-full bg-slate-800">
              <div
                className={`h-2 rounded-full bg-gradient-to-r ${feedColor} to-neon`}
                style={{ width: `${feedImpact}%` }}
              />
            </div>
            <p className="text-xs text-slate-400 mt-2">{feedHits.length} feed hit(s) detected</p>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Detected Issues</h2>
            <ul className="mt-4 text-sm text-slate-300 space-y-2">
              {result.reasons.map((reason, index) => (
                <li key={index}>• {reason}</li>
              ))}
            </ul>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">AI Assistant Explanation</h2>
            <p className="text-xs text-slate-400 mt-1">
              Generates a plain‑language explanation (uses OpenAI if configured).
            </p>
            <button
              className="mt-4 px-4 py-2 rounded-full bg-neon text-midnight text-sm font-semibold"
              onClick={async () => {
                if (!result) return;
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
                } catch (err) {
                  setExplanation("Unable to generate explanation.");
                } finally {
                  setExplaining(false);
                }
              }}
              disabled={explaining}
            >
              {explaining ? "Generating..." : "Explain with AI"}
            </button>
            {explanation && (
              <div className="mt-4 text-sm text-slate-300 whitespace-pre-line">
                {explanation}
              </div>
            )}
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Explainable AI Highlights</h2>
            {result.highlights.length === 0 ? (
              <p className="text-sm text-slate-400 mt-3">No suspicious phrases detected.</p>
            ) : (
              <div className="mt-4 flex flex-wrap gap-2">
                {result.highlights.map((item) => (
                  <span
                    key={item}
                    className="px-3 py-1 rounded-full bg-rose-500/10 border border-rose-400/30 text-xs text-rose-200"
                  >
                    {item}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Pattern Matches</h2>
            <div className="mt-4 flex flex-wrap gap-2">
              {result.patterns.map((pattern, index) => (
                <span key={index} className="px-3 py-1 rounded-full bg-midnight border border-slate-700 text-xs">
                  {pattern}
                </span>
              ))}
            </div>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Confidence Band</h2>
            <div className="mt-3 h-2 rounded-full bg-slate-800">
              <div
                className="h-2 rounded-full bg-gradient-to-r from-emerald-400 via-amber-400 to-rose-500"
                style={{ width: `${Math.round(result.confidence.mid * 100)}%` }}
              />
            </div>
            <div className="mt-3 flex justify-between text-xs text-slate-400">
              <span>Low {Math.round(result.confidence.low * 100)}%</span>
              <span>Mid {Math.round(result.confidence.mid * 100)}%</span>
              <span>High {Math.round(result.confidence.high * 100)}%</span>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-xs text-slate-300">
              <div className="bg-midnight border border-slate-700 rounded-lg p-3 text-center">
                <p className="text-slate-400">Low</p>
                <p className="mt-1 text-emerald-300">{Math.round(result.confidence.low * 100)}%</p>
              </div>
              <div className="bg-midnight border border-slate-700 rounded-lg p-3 text-center">
                <p className="text-slate-400">Mid</p>
                <p className="mt-1 text-amber-300">{Math.round(result.confidence.mid * 100)}%</p>
              </div>
              <div className="bg-midnight border border-slate-700 rounded-lg p-3 text-center">
                <p className="text-slate-400">High</p>
                <p className="mt-1 text-rose-300">{Math.round(result.confidence.high * 100)}%</p>
              </div>
            </div>
            <p className="mt-4 text-xs text-slate-400">{oneLineExplanation}</p>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Behavioral Signals</h2>
            {Object.keys(result.behavior_signals).length === 0 ? (
              <p className="text-sm text-slate-400 mt-3">No behavioral indicators detected.</p>
            ) : (
              <div className="mt-3 text-sm text-slate-300 space-y-2">
                {Object.entries(result.behavior_signals).map(([key, value]) => (
                  <div key={key} className="flex items-center justify-between">
                    <span className="text-slate-400">{key.replaceAll("_", " ")}</span>
                    <span>{String(value)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
            <h2 className="font-display text-lg">Feed Hit Highlights</h2>
            {feedHits.length === 0 ? (
              <p className="text-sm text-slate-400 mt-3">No threat feed hits detected.</p>
            ) : (
              <ul className="mt-3 text-sm text-slate-300 space-y-2">
                {feedHits.map(([key]) => (
                  <li key={key}>• {key.replaceAll("_", " ")}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      <section className="mt-10 bg-carbon/80 border border-slate-700 rounded-3xl p-6">
        <h2 className="font-display text-lg">URL & Reputation Findings</h2>
        <div className="mt-4 grid md:grid-cols-2 gap-4">
          {result.url_findings.length === 0 && (
            <p className="text-sm text-slate-300">No URLs detected in this message.</p>
          )}
          {result.url_findings.map((finding, index) => (
            <div key={index} className="bg-midnight border border-slate-700 rounded-2xl p-4">
              <p className="text-xs text-slate-400">URL</p>
              <p className="text-sm text-plasma break-all mt-1">{finding.url}</p>
              <p className="text-xs text-slate-400 mt-3">Reputation</p>
              <p className="text-sm mt-1">{finding.reputation}</p>
              <p className="text-xs text-slate-400 mt-3">Domain Age</p>
              <p className="text-sm mt-1">
                {finding.domain_age_days !== null ? `${finding.domain_age_days} days` : "Unknown"}
              </p>
              <p className="text-xs text-slate-400 mt-3">Phishing Similarity</p>
              <p className="text-sm mt-1">{finding.phishing_similarity}</p>
              {finding.notes.length > 0 && (
                <ul className="mt-3 text-xs text-slate-400 space-y-1">
                  {finding.notes.map((note, noteIndex) => (
                    <li key={noteIndex}>• {note}</li>
                  ))}
                </ul>
              )}
              <button
                className="mt-4 px-3 py-2 text-xs rounded-full border border-slate-700 text-slate-300 hover:text-white"
                onClick={() =>
                  fetch("http://localhost:8000/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: finding.url, source: "results" }),
                  })
                }
              >
                Report Suspicious URL
              </button>
            </div>
          ))}
        </div>
      </section>

      <section className="mt-10 bg-carbon/80 border border-slate-700 rounded-3xl p-6">
        <h2 className="font-display text-lg">Model Scores</h2>
        <div className="mt-4 grid sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {Object.entries(result.categories).map(([key, value]) => (
            <div key={key} className="bg-midnight border border-slate-700 rounded-2xl p-4 text-center">
              <p className="text-xs text-slate-400 uppercase">{key.replace("_", " ")}</p>
              <p className="text-lg font-semibold mt-2">{Math.round(value * 100)}%</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
