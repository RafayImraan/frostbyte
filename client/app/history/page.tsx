"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { fetchHistory, getHistory, AnalysisResult } from "../../lib/api";
import { Logo } from "../../components/Logo";

export default function HistoryPage() {
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [metrics, setMetrics] = useState<{ blocked_week: number; total_risk_saved: number; top_reports: { url: string; count: number }[] } | null>(null);
  const router = useRouter();

  useEffect(() => {
    const load = async () => {
      try {
        const remote = await fetchHistory();
        setHistory(remote);
      } catch (error) {
        setHistory(getHistory());
      }
    };
    load();
    fetch("http://localhost:8000/metrics")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setMetrics(data))
      .catch(() => {});
  }, []);

  return (
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between">
        <Logo />
        <button
          className="px-4 py-2 rounded-full border border-slate-600 text-slate-200"
          onClick={() => router.push("/analyze")}
        >
          New Scan
        </button>
      </header>

      <section className="mt-12">
        <h1 className="text-3xl font-display">Threat History</h1>
        <p className="text-slate-300 mt-2">Recent scans stored locally for quick demo review.</p>

        <div className="mt-8 grid md:grid-cols-3 gap-4">
          <div className="bg-carbon/80 border border-slate-700 rounded-2xl p-5">
            <p className="text-xs text-slate-400">Scams Blocked (7 days)</p>
            <p className="text-2xl font-semibold mt-2">{metrics?.blocked_week ?? "--"}</p>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-2xl p-5">
            <p className="text-xs text-slate-400">Cumulative Risk Saved</p>
            <p className="text-2xl font-semibold mt-2">{metrics?.total_risk_saved ?? "--"}</p>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-2xl p-5">
            <p className="text-xs text-slate-400">Top Reported URLs</p>
            {metrics?.top_reports?.length ? (
              <ul className="mt-2 text-xs text-slate-300 space-y-1">
                {metrics.top_reports.map((item) => (
                  <li key={item.url}>• {item.url} ({item.count})</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-slate-500 mt-2">No reports yet</p>
            )}
          </div>
        </div>

        <div className="mt-8 grid gap-4">
          {history.length === 0 && (
            <div className="bg-carbon/80 border border-slate-700 rounded-2xl p-6 text-slate-300">
              No scans yet. Run the analyzer to build a history.
            </div>
          )}
          {history.map((item) => (
            <div
              key={`${item.id}-${item.created_at}`}
              className="bg-carbon/80 border border-slate-700 rounded-2xl p-6"
            >
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                <div>
                  <p className="text-xs text-slate-400">{new Date(item.created_at).toLocaleString()}</p>
                  <p className="text-sm text-slate-200 mt-2">{item.input}</p>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-sm text-slate-300">{item.scam_probability}%</span>
                  <span className={`px-3 py-1 rounded-full text-xs ${item.risk_level === "High" ? "bg-rose-500/20 text-rose-200" : item.risk_level === "Medium" ? "bg-amber-500/20 text-amber-200" : "bg-emerald-500/20 text-emerald-200"}`}>
                    {item.risk_level.toUpperCase()}
                  </span>
                </div>
              </div>
              <div className="mt-4 text-xs text-slate-400 flex flex-wrap gap-2">
                {item.reasons.slice(0, 4).map((reason, index) => (
                  <span key={index} className="px-2 py-1 border border-slate-700 rounded-full">
                    {reason}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
