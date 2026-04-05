import Link from "next/link";
import { FeatureCard } from "../components/FeatureCard";
import { StatCard } from "../components/StatCard";
import { Logo } from "../components/Logo";

const pillars = [
  {
    title: "Intent Reconstruction",
    description: "CyberShield identifies what the attacker actually wants: credentials, payment, wallet access, or panic-driven compliance.",
  },
  {
    title: "Manipulation Mapping",
    description: "The system scores fear, urgency, greed, authority abuse, trust hijack, and confusion to reveal the human exploit layer.",
  },
  {
    title: "Attack Forecast",
    description: "Instead of only flagging a scam, CyberShield predicts the next likely attacker move and the likely damage path.",
  },
  {
    title: "Live Intervention",
    description: "The browser extension interrupts risky pages, guards form submission, and gives a safe alternative before damage happens.",
  },
];

export default function HomePage() {
  return (
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between gap-4">
        <Logo />
        <nav className="hidden items-center gap-6 text-sm text-slate-300 md:flex">
          <Link href="#why" className="hover:text-white">
            Why It Wins
          </Link>
          <Link href="#flow" className="hover:text-white">
            Product Flow
          </Link>
          <Link
            href="/analyze"
            className="rounded-full bg-neon px-4 py-2 font-semibold text-midnight shadow-glow"
          >
            Launch Platform
          </Link>
        </nav>
      </header>

      <section className="mt-16 grid items-start gap-12 lg:grid-cols-[1.08fr_0.92fr]">
        <div>
          <p className="text-xs uppercase tracking-[0.32em] text-neon">AI Scam Intent And Intervention Engine</p>
          <h1 className="mt-4 max-w-4xl text-4xl font-display font-semibold leading-tight md:text-6xl">
            CyberShield does not just detect scams. It predicts attacker intent and interrupts the victim journey.
          </h1>
          <p className="mt-6 max-w-3xl text-lg leading-relaxed text-slate-300">
            Built for real-world phishing, reward scams, fake banking alerts, and crypto wallet traps, CyberShield reconstructs the scammer playbook, exposes the psychological pressure being used, and stops the risky action before credentials, money, or wallet access are lost.
          </p>

          <div className="mt-8 flex flex-col gap-4 sm:flex-row">
            <Link
              href="/analyze"
              className="rounded-full bg-neon px-6 py-3 text-center font-semibold text-midnight shadow-glow"
            >
              Generate Threat Casefile
            </Link>
            <Link
              href="/history"
              className="rounded-full border border-slate-600 px-6 py-3 text-center text-slate-200"
            >
              Open Command Center
            </Link>
          </div>

          <div className="mt-8 grid gap-4 sm:grid-cols-3">
            <StatCard label="Attacker Success Forecast" value="92%" accent="text-rose-300" />
            <StatCard label="Manipulation Vectors" value="6 Layers" accent="text-cyan-300" />
            <StatCard label="Intervention Mode" value="Live" accent="text-emerald-300" />
          </div>
        </div>

        <div className="floaty rounded-[2rem] border border-slate-700 bg-carbon/80 p-8 shadow-haze">
          <p className="text-sm text-slate-400">Live Threat Snapshot</p>
          <div className="mt-4 rounded-3xl border border-slate-700 bg-midnight p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Scanned message</p>
            <p className="mt-3 text-sm leading-relaxed text-slate-200">
              Urgent: your bank noticed suspicious activity. Verify immediately at
              <span className="text-plasma"> http://paypal-secure-login.xyz</span> or your account will be suspended.
            </p>

            <div className="mt-6 grid grid-cols-3 gap-4 text-center">
              <StatCard label="Casefile" value="Authority Fraud" />
              <StatCard label="Next Move" value="OTP Capture" accent="text-amber-300" />
              <StatCard label="Intervention" value="Blocked" accent="text-emerald-300" />
            </div>
          </div>

          <div className="mt-6 grid gap-3">
            <div className="rounded-2xl border border-rose-400/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
              Manipulation detected: fear + urgency + authority abuse
            </div>
            <div className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 px-4 py-3 text-sm text-cyan-100">
              Forecast: spoof login → credential entry → OTP prompt → account takeover
            </div>
            <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">
              Safe alternative: open the official bank site manually and verify through a trusted number
            </div>
          </div>
        </div>
      </section>

      <section id="why" className="mt-20">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-neon">Why It Wins</p>
            <h2 className="mt-3 text-2xl font-display md:text-3xl">A sharper category than “phishing detector”</h2>
          </div>
          <p className="max-w-2xl text-sm leading-relaxed text-slate-300">
            Most security tools stop at classification. CyberShield goes further: it reconstructs scam intent, explains the human manipulation layer, and actively intervenes at the point of risk.
          </p>
        </div>

        <div className="mt-8 grid gap-6 md:grid-cols-2 xl:grid-cols-4">
          {pillars.map((pillar) => (
            <FeatureCard key={pillar.title} title={pillar.title} description={pillar.description} />
          ))}
        </div>
      </section>

      <section id="flow" className="mt-20 grid gap-6 lg:grid-cols-3">
        <FeatureCard
          title="1. Analyze The Artifact"
          description="Paste a suspicious message or scan a live page. CyberShield extracts risky language, URLs, structural signals, and page behavior."
        />
        <FeatureCard
          title="2. Reconstruct The Attack"
          description="The backend generates a threat casefile, manipulation map, escalation path, and impact forecast instead of returning only a score."
        />
        <FeatureCard
          title="3. Intervene Before Loss"
          description="The extension warns, pauses risky pages, guards form submission, and gives the user a safer path before compromise happens."
        />
      </section>

      <section className="mt-20 grid gap-8 xl:grid-cols-[1fr_1fr]">
        <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-8">
          <p className="text-xs uppercase tracking-[0.24em] text-neon">Built For Operational Impact</p>
          <div className="mt-5 space-y-4 text-sm text-slate-300">
            <p>The results page feels like a threat intelligence console, not a class project dashboard.</p>
            <p>The extension creates an immediate intervention moment users can act on before damage occurs.</p>
            <p>The history view turns isolated scans into evolving scam campaigns and mutation patterns.</p>
          </div>
        </div>

        <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-8">
          <p className="text-xs uppercase tracking-[0.24em] text-neon">Closing Line</p>
          <h3 className="mt-4 text-2xl font-display">
            “CyberShield detects scams, predicts attacker intent, maps psychological manipulation, and intervenes before the victim falls.”
          </h3>
          <Link
            href="/analyze"
            className="mt-6 inline-flex rounded-full bg-plasma px-6 py-3 font-semibold text-midnight shadow-glow"
          >
            Launch CyberShield
          </Link>
        </div>
      </section>
    </div>
  );
}
