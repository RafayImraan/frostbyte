type StatusProps = {
  statusMap: Record<string, string>;
  scanStatus: string;
  aiProvider: string;
  aiModel: string;
};

const STATUS_STYLES: Record<string, string> = {
  pending: "bg-amber-500/20 text-amber-200",
  hit: "bg-rose-500/20 text-rose-200",
  ok: "bg-emerald-500/20 text-emerald-200",
  cached: "bg-blue-500/20 text-blue-200",
  rate_limited: "bg-orange-500/20 text-orange-200",
  error: "bg-slate-500/20 text-slate-200",
  no_key: "bg-slate-600/40 text-slate-300",
  not_applicable: "bg-slate-600/40 text-slate-300",
  complete: "bg-emerald-500/20 text-emerald-200",
};

const labelMap: Record<string, string> = {
  urlhaus: "URLhaus (community feed)",
  virustotal: "VirusTotal",
};

function badge(status: string) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.error;
  return <span className={`px-3 py-1 rounded-full text-xs ${style}`}>{status.replace("_", " ")}</span>;
}

export function ThreatFeedStatus({ statusMap, scanStatus, aiProvider, aiModel }: StatusProps) {
  const relevantEntries = Object.entries(statusMap).filter(([key]) => key in labelMap);
  const relevantValues = relevantEntries.map(([, value]) => value);
  const noUrls = relevantValues.length > 0 && relevantValues.every((value) => value === "not_applicable");
  const hasRateLimit = relevantValues.some((value) => value === "rate_limited");
  const hasError = relevantValues.some((value) => value === "error");
  return (
    <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6">
      <h2 className="font-display text-lg">Threat Feeds</h2>
      <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
        <span>Scan Status</span>
        {badge(scanStatus)}
      </div>
      <div className="mt-4 space-y-3 text-sm text-slate-300">
        {Object.keys(labelMap).map((key) => (
          <div key={key} className="flex items-center justify-between">
            <span>{labelMap[key]}</span>
            {badge(statusMap[key] ?? "not_applicable")}
          </div>
        ))}
      </div>
      {noUrls && <p className="mt-3 text-xs text-slate-400">No URLs detected in this scan.</p>}
      {hasRateLimit && <p className="mt-3 text-xs text-amber-300">Some feeds are rate-limited. Retrying soon.</p>}
      {hasError && <p className="mt-2 text-xs text-rose-300">Some feeds returned errors. Check backend logs.</p>}
      <div className="mt-5 border-t border-slate-700 pt-4 text-xs text-slate-400">
        AI Model: {aiProvider} / {aiModel}
      </div>
    </div>
  );
}
