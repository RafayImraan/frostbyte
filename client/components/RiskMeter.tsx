export function RiskMeter({ score }: { score: number }) {
  const clamped = Math.min(100, Math.max(0, score));
  const gradient = clamped < 40 ? "from-emerald-400" : clamped < 70 ? "from-amber-400" : "from-rose-500";
  return (
    <div className="bg-midnight border border-slate-700 rounded-2xl p-4">
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Risk Score</span>
        <span>{clamped}/100</span>
      </div>
      <div className="mt-3 h-2 rounded-full bg-slate-800">
        <div className={`h-2 rounded-full bg-gradient-to-r ${gradient} to-neon`} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}
