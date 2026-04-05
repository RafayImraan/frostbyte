"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AnalysisResult, fetchHistory, getApiBaseUrl, getHistory } from "../../lib/api";
import { Logo } from "../../components/Logo";

type Metrics = {
  blocked_week: number;
  total_risk_saved: number;
  top_reports: { url: string; count: number }[];
};

type Cluster = {
  key: string;
  count: number;
  archetype: string;
  avgRisk: number;
  signatures: string[];
};

function buildClusters(history: AnalysisResult[]): Cluster[] {
  const map = new Map<string, Cluster>();
  history.forEach((item) => {
    const key = item.threat_casefile.archetype;
    const existing = map.get(key);
    const signatures = item.threat_casefile.campaign_signature.slice(0, 4);
    if (existing) {
      existing.count += 1;
      existing.avgRisk += item.scam_probability;
      existing.signatures = Array.from(new Set([...existing.signatures, ...signatures])).slice(0, 6);
      return;
    }
    map.set(key, {
      key,
      count: 1,
      archetype: item.threat_casefile.archetype,
      avgRisk: item.scam_probability,
      signatures,
    });
  });

  return Array.from(map.values())
    .map((cluster) => ({ ...cluster, avgRisk: Math.round(cluster.avgRisk / cluster.count) }))
    .sort((a, b) => b.count - a.count || b.avgRisk - a.avgRisk)
    .slice(0, 6);
}

export default function HistoryPage() {
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const router = useRouter();

  useEffect(() => {
    const load = async () => {
      try {
        setHistory(await fetchHistory());
      } catch {
        setHistory(getHistory());
      }
    };
    load();
    fetch(`${getApiBaseUrl()}/metrics`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setMetrics(data))
      .catch(() => {});
  }, []);

  const clusters = buildClusters(history);

  return (
    <div className="app-shell">
      <header className="app-header">
        <Logo />
        <div className="app-actions">
          <button className="app-button-secondary" onClick={() => router.push("/analyze")}>
            New Scan
          </button>
          <button className="app-button-secondary" onClick={() => router.push("/")}>
            Platform Home
          </button>
        </div>
      </header>

      <section className="mt-10 intelligence-panel">
        <p className="micro-label">Campaign Command Center</p>
        <div className="mt-4 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <h1 className="text-3xl font-display text-white md:text-4xl">Campaign intelligence and cluster tracking</h1>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300 md:text-base">
              Group detections into repeatable scam archetypes, compare their signature traits, and monitor evolving
              social-engineering patterns through a shared operational view.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="metric-card min-w-[180px]">
              <p className="micro-label">Scams blocked / 7 days</p>
              <p className="mt-3 text-3xl font-semibold text-white">{metrics?.blocked_week ?? "--"}</p>
            </div>
            <div className="metric-card min-w-[180px]">
              <p className="micro-label">Cumulative risk saved</p>
              <p className="mt-3 text-3xl font-semibold text-cyan-200">{metrics?.total_risk_saved ?? "--"}</p>
            </div>
            <div className="metric-card min-w-[180px]">
              <p className="micro-label">Active clusters</p>
              <p className="mt-3 text-3xl font-semibold text-emerald-300">{clusters.length}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="mt-8 intelligence-grid">
        <div className="intelligence-panel">
          <p className="micro-label">Cluster Radar</p>
          <div className="mt-5 signal-list">
            {clusters.length === 0 ? (
              <div className="signal-list-item text-sm text-slate-400">No campaign clusters yet. Run more scans to populate the command center.</div>
            ) : (
              clusters.map((cluster) => (
                <div key={cluster.key} className="signal-list-item">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-lg font-semibold text-white">{cluster.archetype}</p>
                      <p className="mt-1 text-xs text-slate-400">
                        {cluster.count} incident{cluster.count === 1 ? "" : "s"} grouped
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="micro-label">Avg risk</p>
                      <p className="mt-2 text-xl font-semibold text-rose-300">{cluster.avgRisk}%</p>
                    </div>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {cluster.signatures.map((sig) => (
                      <span key={sig} className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-200">
                        {sig}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="space-y-6">
          {history.length === 0 && (
            <div className="intelligence-panel text-slate-300">No scans yet. Run the analyzer to populate the command center.</div>
          )}

          {history.map((item) => (
            <div key={`${item.id}-${item.created_at}`} className="intelligence-panel">
              <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                <div>
                  <p className="micro-label">{item.threat_casefile.archetype}</p>
                  <h2 className="mt-3 text-2xl font-display text-white">{item.threat_casefile.attack_stage}</h2>
                  <p className="mt-3 text-sm leading-7 text-slate-300">{item.threat_casefile.narrative}</p>
                </div>
                <div className="metric-card min-w-[170px] text-right">
                  <p className="micro-label">{new Date(item.created_at).toLocaleString()}</p>
                  <p className="mt-3 text-3xl font-semibold text-rose-300">{item.scam_probability}%</p>
                  <p className="mt-1 text-xs text-slate-400">{item.risk_level.toUpperCase()} risk</p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 xl:grid-cols-[1.02fr_0.98fr]">
                <div className="signal-list">
                  <div className="signal-list-item">
                    <p className="micro-label">Predicted next move</p>
                    <p className="mt-2 text-sm leading-7 text-slate-200">{item.threat_casefile.next_move_prediction}</p>
                  </div>
                  <div className="signal-list-item">
                    <p className="micro-label">Likely outcome</p>
                    <p className="mt-2 text-sm leading-7 text-slate-200">{item.threat_casefile.possible_outcome}</p>
                  </div>
                </div>

                <div className="signal-list-item">
                  <p className="micro-label">Threat DNA</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {item.threat_casefile.campaign_signature.map((sig) => (
                      <span key={sig} className="rounded-full border border-rose-400/20 bg-rose-500/10 px-3 py-1 text-xs text-rose-200">
                        {sig}
                      </span>
                    ))}
                  </div>
                  <p className="mt-4 text-xs text-slate-400">Mutation risk {item.threat_casefile.mutation_risk}/100</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
