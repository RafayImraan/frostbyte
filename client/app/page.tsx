import Link from "next/link";
import { FeatureCard } from "../components/FeatureCard";
import { StatCard } from "../components/StatCard";
import { Logo } from "../components/Logo";

export default function HomePage() {
  return (
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between">
        <Logo />
        <nav className="hidden md:flex items-center gap-6 text-sm text-slate-300">
          <Link href="#how" className="hover:text-white">How it works</Link>
          <Link href="#features" className="hover:text-white">Features</Link>
          <Link href="/analyze" className="px-4 py-2 rounded-full bg-neon text-midnight font-semibold shadow-glow">Live Demo</Link>
        </nav>
      </header>

      <section className="mt-16 grid lg:grid-cols-2 gap-12 items-center">
        <div>
          <p className="text-neon uppercase tracking-[0.3em] text-xs">AI CyberShield</p>
          <h1 className="mt-4 text-4xl md:text-5xl font-display font-semibold leading-tight">
            Real-Time Scam & Fraud Detection System
          </h1>
          <p className="mt-6 text-slate-300 leading-relaxed">
            Analyze suspicious messages, phishing links, and crypto wallet activity with AI-driven
            risk scoring, threat intelligence, and explainable insights.
          </p>
          <div className="mt-8 flex flex-col sm:flex-row gap-4">
            <Link
              href="/analyze"
              className="px-6 py-3 rounded-full bg-neon text-midnight font-semibold shadow-glow text-center"
            >
              Run a Live Scan
            </Link>
            <Link
              href="/history"
              className="px-6 py-3 rounded-full border border-slate-600 text-slate-200 text-center"
            >
              View Threat History
            </Link>
          </div>
        </div>
        <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-8 shadow-haze floaty">
          <p className="text-sm text-slate-400">Live Demo Preview</p>
          <div className="mt-4 bg-midnight rounded-2xl p-6 border border-slate-700">
            <p className="text-slate-400 text-xs">Sample Message</p>
            <p className="mt-2 text-sm">
              Congratulations! You won $5000. Click here to claim your reward:
              <span className="text-plasma"> http://paypal-secure-login.xyz</span>
            </p>
            <div className="mt-6 grid grid-cols-3 gap-4 text-center">
              <StatCard label="Scam Probability" value="92%" />
              <StatCard label="Risk Level" value="HIGH" accent="text-ember" />
              <StatCard label="Signals" value="11" />
            </div>
          </div>
          <div className="mt-6 flex items-center justify-between text-xs text-slate-400">
            <span>AI Model: DistilBERT + Rules</span>
            <span>Threat Feeds: Active</span>
          </div>
        </div>
      </section>

      <section id="how" className="mt-20">
        <h2 className="text-2xl font-display">How it works</h2>
        <div className="mt-8 grid md:grid-cols-3 gap-6">
          <FeatureCard title="1. Analyze" description="Paste any message, email, or crypto address. CyberShield extracts risky patterns and URLs." />
          <FeatureCard title="2. Enrich" description="Threat intelligence checks reputation, domain age, and blacklist sources." />
          <FeatureCard title="3. Explain" description="You get a clear scam probability, risk score, and explanation for each signal." />
        </div>
      </section>

      <section id="features" className="mt-20">
        <h2 className="text-2xl font-display">Platform features</h2>
        <div className="mt-8 grid md:grid-cols-2 xl:grid-cols-4 gap-6">
          <FeatureCard title="NLP Scam Detection" description="DistilBERT-ready pipeline for classifying phishing, spam, and crypto scams." />
          <FeatureCard title="URL Scanner" description="Domain age, suspicious keywords, shortened URL detection, and similarity checks." />
          <FeatureCard title="Risk Score Engine" description="Combines AI score, rules, and threat feeds into a single score." />
          <FeatureCard title="Threat History" description="Every scan is saved so analysts can track emerging scams." />
        </div>
      </section>

      <section className="mt-20 mb-10">
        <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-8 md:p-12 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div>
            <h3 className="text-2xl font-display">Ready to stop scams in real time?</h3>
            <p className="text-slate-300 mt-2">Run a live scan and see your risk score instantly.</p>
          </div>
          <Link href="/analyze" className="px-6 py-3 rounded-full bg-plasma text-midnight font-semibold shadow-glow">
            Launch Analyzer
          </Link>
        </div>
      </section>
    </div>
  );
}
