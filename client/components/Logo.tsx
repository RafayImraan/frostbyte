export function Logo() {
  return (
    <div className="flex items-center gap-3">
      <div className="brand-mark">
        <span className="brand-mark-core" />
        <span className="brand-mark-ring brand-mark-ring-one" />
        <span className="brand-mark-ring brand-mark-ring-two" />
      </div>
      <div>
        <p className="text-lg font-display text-white">CyberShield</p>
        <p className="text-xs tracking-[0.18em] uppercase text-slate-500">Scam Defense Platform</p>
      </div>
    </div>
  );
}
