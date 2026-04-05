"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { analyzeMessage, saveLatest } from "../../lib/api";
import { Logo } from "../../components/Logo";

const SAMPLES = [
  {
    label: "Authority Fraud",
    text: "Urgent: your bank noticed suspicious activity. Verify immediately at http://paypal-secure-login.xyz or your account will be suspended.",
  },
  {
    label: "Prize Funnel",
    text: "Congratulations! You won $5000. Claim your reward now and send a small processing fee by gift card to release the payout.",
  },
  {
    label: "Wallet Drain",
    text: "Exclusive airdrop for early users. Connect your wallet now and verify your seed phrase to unlock the reward before the countdown ends.",
  },
];

const workflow = [
  "Content enters the intelligence pipeline",
  "Behavioral and language signals are scored",
  "Attacker objective and pressure vectors are reconstructed",
  "A threat casefile and safer response path are generated",
];

export default function AnalyzePage() {
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [consent, setConsent] = useState(true);
  const router = useRouter();

  const handleSubmit = async () => {
    setError(null);
    if (!message.trim()) {
      setError("Paste a suspicious message, page text, or URL to scan.");
      return;
    }
    setLoading(true);
    try {
      const result = await analyzeMessage(message.trim(), consent);
      saveLatest(result, consent);
      router.push("/results");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <Logo />
        <div className="app-actions">
          <button className="app-button-secondary" onClick={() => router.push("/")}>
            Platform Home
          </button>
          <button className="app-button-secondary" onClick={() => router.push("/history")}>
            Command Center
          </button>
        </div>
      </header>

      <section className="mt-10 intelligence-grid">
        <div className="intelligence-panel">
          <p className="micro-label">Threat Intake Console</p>
          <h1 className="mt-3 text-3xl font-display text-white md:text-4xl">
            Convert suspicious content into an actionable threat casefile.
          </h1>
          <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-300 md:text-base">
            Submit suspicious messages, phishing content, fake promotions, or wallet lures for analysis.
            CyberShield reconstructs attacker intent, scores psychological pressure, and predicts the likely
            escalation path before generating intervention guidance.
          </p>

          <div className="mt-6 flex flex-wrap gap-3">
            {SAMPLES.map((sample) => (
              <button
                key={sample.label}
                className="rounded-full border border-slate-700 bg-slate-950/70 px-4 py-2 text-sm text-slate-200 transition hover:border-cyan-300/40 hover:bg-slate-900"
                onClick={() => setMessage(sample.text)}
                disabled={loading}
              >
                {sample.label}
              </button>
            ))}
          </div>

          <div className="mt-6">
            <textarea
              className="min-h-[260px] w-full rounded-[1.75rem] border border-slate-800 bg-slate-950/75 p-5 text-sm leading-7 text-white outline-none transition focus:border-cyan-300/40 focus:ring-2 focus:ring-cyan-400/20"
              placeholder="Paste suspicious content, phishing copy, or a risky workflow description..."
              value={message}
              onChange={(event) => setMessage(event.target.value)}
            />
          </div>

          <div className="mt-5 flex flex-col gap-3 sm:flex-row">
            <button className="app-button-primary" onClick={handleSubmit} disabled={loading}>
              {loading ? "Generating Casefile..." : "Generate Threat Casefile"}
            </button>
            <button className="app-button-secondary" onClick={() => setMessage("")} disabled={loading}>
              Clear Input
            </button>
          </div>

          <label className="mt-5 flex items-center gap-3 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
              className="h-4 w-4 rounded border-slate-600 bg-slate-950/70 text-cyan-300 focus:ring-cyan-300"
            />
            Store this scan for campaign clustering and operational history
          </label>

          <p className="mt-2 text-[11px] text-slate-500">
            If disabled, the original content is not preserved in scan history.
          </p>

          {error && <p className="mt-4 text-sm text-rose-300">{error}</p>}
        </div>

        <div className="space-y-6">
          <div className="intelligence-panel">
            <p className="micro-label">Processing Sequence</p>
            <div className="mt-4 scan-rail pl-6">
              <div className="signal-list">
                {workflow.map((item, index) => (
                  <div key={item} className="signal-list-item">
                    <div className="flex items-start gap-3">
                      <span className="trace-step-index mt-0.5">{index + 1}</span>
                      <span className="text-sm leading-6 text-slate-200">{item}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="intelligence-panel">
            <p className="micro-label">Expected Output</p>
            <div className="mt-4 grid gap-3">
              <div className="metric-card">
                <p className="micro-label">Threat Casefile</p>
                <p className="mt-3 text-lg font-semibold text-white">Attacker archetype, target persona, and next move</p>
              </div>
              <div className="metric-card">
                <p className="micro-label">Manipulation Map</p>
                <p className="mt-3 text-lg font-semibold text-cyan-200">Fear, urgency, authority, greed, trust hijack, confusion</p>
              </div>
              <div className="metric-card">
                <p className="micro-label">Impact Forecast</p>
                <p className="mt-3 text-lg font-semibold text-emerald-300">Likely damage, loss window, and safer alternative</p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
