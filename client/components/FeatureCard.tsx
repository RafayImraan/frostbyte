export function FeatureCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="feature-card group">
      <div className="feature-card-glow" />
      <p className="feature-card-label">Operational Layer</p>
      <h3 className="mt-3 font-display text-xl text-white transition duration-300 group-hover:text-cyan-100">
        {title}
      </h3>
      <p className="mt-4 text-sm leading-7 text-slate-300">{description}</p>
      <div className="mt-6 flex items-center gap-3 text-xs uppercase tracking-[0.18em] text-slate-500">
        <span className="h-px w-8 bg-slate-700 transition duration-300 group-hover:w-12 group-hover:bg-cyan-300/60" />
        Active
      </div>
    </div>
  );
}
