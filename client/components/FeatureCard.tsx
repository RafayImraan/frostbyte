export function FeatureCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="bg-carbon/70 border border-slate-700 rounded-2xl p-6 shadow-haze">
      <h3 className="font-display text-lg">{title}</h3>
      <p className="text-slate-300 mt-3 text-sm leading-relaxed">{description}</p>
    </div>
  );
}
