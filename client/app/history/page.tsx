"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AnalysisResult, fetchHistory, getHistory } from "../../lib/api";
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
    .map((cluster) => ({
      ...cluster,
      avgRisk: Math.round(cluster.avgRisk / cluster.count),
    }))
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
        const remote = await fetchHistory();
        setHistory(remote);
      } catch {
        setHistory(getHistory());
      }
    };

    load();
    fetch("http://localhost:8000/metrics")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setMetrics(data))
      .catch(() => {});
  }, []);

  const clusters = buildClusters(history);

  return (
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between gap-4">
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
            onClick={() => router.push("/")}
          >
            Landing
          </button>
        </div>
      </header>

      <section className="mt-12">
        <p className="text-xs uppercase tracking-[0.28em] text-neon">Command Center</p>
        <h1 className="mt-3 text-3xl md:text-4xl font-display">Campaign Intelligence View</h1>
        <p className="mt-3 max-w-3xl text-slate-300">
          Instead of a flat scan list, this view groups detections into repeatable scam archetypes so security teams can track campaign behavior the way a threat analyst would.
        </p>

        <div className="mt-8 grid gap-4 md:grid-cols-3">
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-5">
            <p className="text-xs text-slate-400">Scams blocked in 7 days</p>
            <p className="mt-2 text-3xl font-semibold">{metrics?.blocked_week ?? "--"}</p>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-5">
            <p className="text-xs text-slate-400">Cumulative risk saved</p>
            <p className="mt-2 text-3xl font-semibold">{metrics?.total_risk_saved ?? "--"}</p>
          </div>
          <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-5">
            <p className="text-xs text-slate-400">Active campaign clusters</p>
            <p className="mt-2 text-3xl font-semibold">{clusters.length}</p>
          </div>
        </div>

        <div className="mt-8 grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
          <div className="bg-carbon/80 border border-slate-700 rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Cluster Radar</p>
            <div className="mt-5 space-y-4">
              {clusters.length === 0 ? (
                <p className="text-sm text-slate-400">No scan clusters yet. Run more demos to generate campaign patterns.</p>
              ) : (
                clusters.map((cluster) => (
                  <div key={cluster.key} className="rounded-3xl border border-slate-700 bg-midnight p-4">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <p className="text-lg font-semibold">{cluster.archetype}</p>
                        <p className="mt-1 text-xs text-slate-400">
                          {cluster.count} incident{cluster.count === 1 ? "" : "s"} grouped
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-slate-500">Avg risk</p>
                        <p className="text-xl font-semibold text-rose-300">{cluster.avgRisk}%</p>
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

          <div className="space-y-4">
            {history.length === 0 && (
              <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6 text-slate-300">
                No scans yet. Run the analyzer to populate the command center.
              </div>
            )}

            {history.map((item) => (
              <div key={`${item.id}-${item.created_at}`} className="bg-carbon/80 border border-slate-700 rounded-[2rem] p-6">
                <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                  <div>
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-500">{item.threat_casefile.archetype}</p>
                    <h2 className="mt-2 text-xl font-display">{item.threat_casefile.attack_stage}</h2>
                    <p className="mt-2 text-sm text-slate-300">{item.threat_casefile.narrative}</p>
                  </div>
                  <div className="rounded-2xl border border-slate-700 bg-midnight px-4 py-3 text-right min-w-[150px]">
                    <p className="text-xs text-slate-500">{new Date(item.created_at).toLocaleString()}</p>
                    <p className="mt-2 text-2xl font-semibold text-rose-300">{item.scam_probability}%</p>
                    <p className="text-xs text-slate-400">{item.risk_level.toUpperCase()} risk</p>
                  </div>
                </div>

                <div className="mt-5 grid gap-4 lg:grid-cols-[1.05fr_0.95fr]">
                  <div className="rounded-3xl border border-slate-700 bg-midnight p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Predicted next move</p>
                    <p className="mt-2 text-sm text-slate-200">{item.threat_casefile.next_move_prediction}</p>
                    <p className="mt-4 text-xs uppercase tracking-[0.18em] text-slate-500">Likely outcome</p>
                    <p className="mt-2 text-sm text-slate-200">{item.threat_casefile.possible_outcome}</p>
                  </div>

                  <div className="rounded-3xl border border-slate-700 bg-midnight p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Threat DNA</p>
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
        </div>
      </section>
    </div>
  );
}
