import Link from "next/link";
import { FeatureCard } from "../components/FeatureCard";
import { Logo } from "../components/Logo";

const pillars = [
  {
    title: "Intent Reconstruction",
    description:
      "CyberShield identifies what the attacker is actually trying to obtain, whether that is credentials, payment, account access, or wallet approvals.",
  },
  {
    title: "Manipulation Mapping",
    description:
      "The platform measures fear, urgency, authority abuse, reward bait, trust hijack, and confusion to expose the human pressure layer.",
  },
  {
    title: "Attack Forecasting",
    description:
      "Each scan projects the likely next step and likely damage path so users and teams can intervene before compromise occurs.",
  },
  {
    title: "Live Intervention",
    description:
      "The browser layer highlights risk, protects form submission, and gives a safe alternative when a high-risk flow is detected.",
  },
];

const operations = [
  {
    title: "Message And Page Analysis",
    description:
      "Analyze suspicious messages, links, and page content through a combined intelligence pipeline of language signals, domain heuristics, and behavioral indicators.",
  },
  {
    title: "Threat Casefile Generation",
    description:
      "Turn raw artifacts into an actionable casefile with attacker archetype, target persona, next-move prediction, and impact forecast.",
  },
  {
    title: "Intervention Workflow",
    description:
      "Move from detection to action with safer alternatives, response guidance, and browser-side interruption before sensitive user input is submitted.",
  },
];

const liveSignals = [
  "Credential harvest pattern isolated",
  "Authority abuse pressure cluster confirmed",
  "OTP extraction path projected",
  "Intervention layer armed for form submission",
];

const pathSteps = [
  "Message lure enters analysis pipeline",
  "Manipulation signals extracted and classified",
  "Likely attacker objective reconstructed",
  "Intervention layer blocks the risky handoff",
];

export default function HomePage() {
  return (
    <div className="px-6 py-8 md:px-14 lg:px-20 xl:px-24">
      <header className="flex items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <Logo />
        <nav className="hidden items-center gap-8 text-sm text-slate-400 md:flex">
          <Link href="#capabilities" className="hover:text-white">
            Capabilities
          </Link>
          <Link href="#operations" className="hover:text-white">
            Operations
          </Link>
          <Link
            href="/analyze"
            className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 font-semibold text-cyan-100 transition hover:border-cyan-300/50 hover:bg-cyan-400/15"
          >
            Open Platform
          </Link>
        </nav>
      </header>

      <section className="relative mt-12 overflow-hidden rounded-[2.5rem] border border-slate-800/80 bg-[linear-gradient(180deg,rgba(6,11,22,0.94),rgba(2,6,14,0.98))] px-6 py-8 shadow-[0_30px_120px_rgba(2,6,23,0.55)] md:px-8 md:py-10 xl:px-10">
        <div className="hero-orb hero-orb-left" />
        <div className="hero-orb hero-orb-right" />
        <div className="hero-ring hero-ring-one" />
        <div className="hero-ring hero-ring-two" />
        <div className="hero-scanline" />
        <div className="signal-node signal-node-a" />
        <div className="signal-node signal-node-b" />
        <div className="signal-node signal-node-c" />

        <div className="relative z-10 grid gap-12 lg:grid-cols-[1.02fr_0.98fr] lg:items-center">
          <div className="space-y-8">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-[11px] uppercase tracking-[0.24em] text-cyan-200">
              Real-Time Scam Detection And Intervention Platform
            </div>

            <div className="space-y-6">
              <h1 className="max-w-4xl text-4xl font-display font-semibold leading-[0.98] text-white md:text-5xl xl:text-6xl">
                A live interception layer for phishing, fraud, and malicious trust workflows.
              </h1>
              <p className="max-w-2xl text-base leading-8 text-slate-300 md:text-lg">
                CyberShield combines scam detection, attacker-intent reconstruction, manipulation analysis,
                and browser intervention into a single operational system designed to stop compromise before
                users hand over credentials, money, or wallet access.
              </p>
            </div>

            <div className="flex flex-col gap-4 sm:flex-row">
              <Link
                href="/analyze"
                className="rounded-full bg-white px-6 py-3 text-center font-semibold text-slate-950 transition hover:bg-slate-200"
              >
                Analyze Threat Artifact
              </Link>
              <Link
                href="/history"
                className="rounded-full border border-slate-700 px-6 py-3 text-center text-slate-200 transition hover:border-slate-500 hover:bg-slate-900/60"
              >
                View Command Center
              </Link>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="glass-tile">
                <p className="micro-label">Threat Forecast</p>
                <p className="mt-3 text-2xl font-semibold text-white">Next-Step Aware</p>
              </div>
              <div className="glass-tile">
                <p className="micro-label">Manipulation Map</p>
                <p className="mt-3 text-2xl font-semibold text-cyan-200">6 Signal Classes</p>
              </div>
              <div className="glass-tile">
                <p className="micro-label">Intervention Layer</p>
                <p className="mt-3 text-2xl font-semibold text-emerald-300">Browser Active</p>
              </div>
            </div>

            <div className="rounded-3xl border border-slate-800 bg-slate-950/55 p-4">
              <p className="micro-label">Live Signal Stream</p>
              <div className="mt-4 space-y-3">
                {liveSignals.map((signal, index) => (
                  <div
                    key={signal}
                    className="signal-feed-item"
                    style={{ animationDelay: `${index * 1.35}s` }}
                  >
                    <span className="signal-dot" />
                    <span>{signal}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="relative">
            <div className="hero-panel">
              <div className="hero-panel-top">
                <div>
                  <p className="micro-label">Live Interception Console</p>
                  <h2 className="mt-2 text-xl font-display text-white">Authority Fraud Detection</h2>
                </div>
                <div className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-medium text-emerald-200">
                  Intervention Active
                </div>
              </div>

              <div className="mt-5 space-y-4">
                <div className="hero-content-card">
                  <div className="hero-content-overlay" />
                  <p className="micro-label">Observed content</p>
                  <p className="mt-3 text-sm leading-7 text-slate-200">
                    Urgent: your bank noticed suspicious activity. Verify immediately at
                    <span className="text-cyan-300"> http://paypal-secure-login.xyz</span> or your account will be suspended.
                  </p>
                </div>

                <div className="intercept-grid">
                  <div className="intercept-stat">
                    <p className="micro-label">Casefile</p>
                    <p className="mt-3 text-xl font-semibold text-white">Authority Fraud</p>
                  </div>
                  <div className="intercept-stat intercept-stat-amber">
                    <p className="micro-label">Likely Next Move</p>
                    <p className="mt-3 text-xl font-semibold text-amber-300">OTP Capture</p>
                  </div>
                  <div className="intercept-stat intercept-stat-green">
                    <p className="micro-label">Safeguard</p>
                    <p className="mt-3 text-xl font-semibold text-emerald-300">Submission Blocked</p>
                  </div>
                </div>

                <div className="trace-panel">
                  <div className="trace-rail" />
                  <p className="micro-label">Projected attack path</p>
                  <div className="mt-4 space-y-4">
                    {pathSteps.map((step, index) => (
                      <div key={step} className="trace-step">
                        <span
                          className="trace-step-index"
                          style={{ animationDelay: `${index * 1.1}s` }}
                        >
                          {index + 1}
                        </span>
                        <span className="text-sm leading-6 text-slate-200">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-2xl border border-rose-400/15 bg-rose-500/10 px-4 py-4 text-sm text-rose-100">
                  Manipulation pressure identified across fear, urgency, and authority abuse.
                </div>
                <div className="rounded-2xl border border-cyan-400/15 bg-cyan-500/10 px-4 py-4 text-sm text-cyan-100">
                  Forecast path: spoof login to credential entry to OTP prompt to account takeover.
                </div>
                <div className="rounded-2xl border border-emerald-400/15 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-100">
                  Safe alternative: open the official banking portal manually and verify through a trusted contact path.
                </div>
              </div>
            </div>

            <div className="hero-connector hero-connector-one" />
            <div className="hero-connector hero-connector-two" />
          </div>
        </div>
      </section>

      <section id="capabilities" className="section-shell mt-24">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Core Capabilities</p>
            <h2 className="mt-3 text-3xl font-display text-white">Built for modern social-engineering defense</h2>
          </div>
          <p className="max-w-2xl text-sm leading-7 text-slate-400">
            CyberShield is designed to move beyond simple URL or keyword checks and into operational
            decision support for real-world scam and impersonation workflows.
          </p>
        </div>

        <div className="mt-8 grid gap-6 md:grid-cols-2 xl:grid-cols-4">
          {pillars.map((pillar) => (
            <FeatureCard key={pillar.title} title={pillar.title} description={pillar.description} />
          ))}
        </div>
      </section>

      <section id="operations" className="section-shell mt-24">
        <div className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Operational Sequence</p>
            <h2 className="mt-3 text-3xl font-display text-white">A continuous flow from detection to disruption</h2>
          </div>
          <p className="max-w-2xl text-sm leading-7 text-slate-400">
            The platform is designed as a chain of defensive actions, turning raw suspicious artifacts
            into attacker intelligence and then into safer user outcomes.
          </p>
        </div>
        <div className="grid gap-6 lg:grid-cols-3">
        {operations.map((item) => (
          <FeatureCard key={item.title} title={item.title} description={item.description} />
        ))}
        </div>
      </section>

      <section className="section-shell mt-24 mb-10 grid gap-8 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="outcome-panel">
          <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Operational Outcome</p>
          <div className="mt-5 space-y-4 text-sm leading-7 text-slate-300">
            <p>Users receive detection, explanation, and action guidance within a single workflow.</p>
            <p>Security teams get structured casefiles, campaign patterns, and safer response recommendations.</p>
            <p>The browser layer shifts protection from passive alerting to active interruption at the moment of risk.</p>
          </div>
        </div>

        <div className="positioning-panel">
          <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Platform Positioning</p>
          <h3 className="mt-4 text-2xl font-display leading-tight text-white">
            CyberShield is a real-time scam detection and intervention platform designed for high-risk trust workflows.
          </h3>
          <Link
            href="/analyze"
            className="mt-6 inline-flex rounded-full border border-cyan-400/30 bg-cyan-400/10 px-6 py-3 font-semibold text-cyan-100 transition hover:border-cyan-300/50 hover:bg-cyan-400/15"
          >
            Enter Platform
          </Link>
        </div>
      </section>
    </div>
  );
}
