export function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div className="bg-carbon/60 border border-slate-700 rounded-xl p-3">
      <p className="text-[10px] text-slate-400 uppercase tracking-[0.2em]">{label}</p>
      <p className={`text-lg font-semibold mt-1 ${accent ?? ""}`}>{value}</p>
    </div>
  );
}
