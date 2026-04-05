"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { analyzeMessage, saveLatest } from "../../lib/api";
import { Logo } from "../../components/Logo";

const SAMPLES = [
  {
    label: "Bank Panic",
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
    <div className="px-6 py-10 md:px-16 lg:px-24">
      <header className="flex items-center justify-between gap-4">
        <Logo />
        <button
          className="rounded-full border border-slate-600 px-4 py-2 text-slate-200"
          onClick={() => router.push("/")}
        >
          Back to Landing
        </button>
      </header>

      <section className="mt-14 grid gap-10 lg:grid-cols-[1.1fr_0.9fr]">
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-neon">Scam Intent Analyzer</p>
          <h1 className="mt-4 text-3xl font-display md:text-4xl">Detect the scam. Predict the next move. Interrupt the damage.</h1>
          <p className="mt-4 max-w-2xl text-slate-300">
            Paste a suspicious message, fake promotion, phishing page text, or wallet lure. CyberShield will reconstruct the attacker strategy, map the psychological pressure being used, and forecast the likely damage path.
          </p>

          <div className="mt-6 flex flex-wrap gap-3">
            {SAMPLES.map((sample) => (
              <button
                key={sample.label}
                className="rounded-full border border-slate-700 bg-carbon/50 px-4 py-2 text-sm text-slate-200"
                onClick={() => setMessage(sample.text)}
                disabled={loading}
              >
                {sample.label}
              </button>
            ))}
          </div>

          <div className="mt-6 flex flex-col gap-4">
            <textarea
              className="min-h-[240px] rounded-3xl border border-slate-700 bg-carbon/60 p-5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-neon"
              placeholder="Paste a suspicious message or page text here..."
              value={message}
              onChange={(event) => setMessage(event.target.value)}
            />
            <div className="flex flex-col gap-3 sm:flex-row">
              <button
                className="rounded-full bg-neon px-6 py-3 text-center font-semibold text-midnight shadow-glow"
                onClick={handleSubmit}
                disabled={loading}
              >
                {loading ? "Analyzing..." : "Generate Threat Casefile"}
              </button>
              <button
                className="rounded-full border border-slate-600 px-6 py-3 text-center text-slate-200"
                onClick={() => setMessage("")}
                disabled={loading}
              >
                Clear Input
              </button>
            </div>
            <label className="flex items-center gap-3 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={consent}
                onChange={(event) => setConsent(event.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-carbon/60 text-neon focus:ring-neon"
              />
              Allow storing this scan in history and campaign clustering
            </label>
            <p className="text-[11px] text-slate-500">
              If unchecked, the original content is not saved to scan history.
            </p>
            {error && <p className="text-sm text-ember">{error}</p>}
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6 shadow-haze">
            <h2 className="text-lg font-display">What this scan returns</h2>
            <div className="mt-5 grid gap-4">
              <div className="rounded-2xl border border-slate-700 bg-midnight p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Threat Casefile</p>
                <p className="mt-2 text-sm text-slate-300">Attacker archetype, target persona, attack stage, next-step prediction, and mutation risk.</p>
              </div>
              <div className="rounded-2xl border border-slate-700 bg-midnight p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Psychological Manipulation Map</p>
                <p className="mt-2 text-sm text-slate-300">Fear, urgency, greed, authority, trust hijack, and confusion signals with exact pressure points.</p>
              </div>
              <div className="rounded-2xl border border-slate-700 bg-midnight p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Impact Forecast</p>
                <p className="mt-2 text-sm text-slate-300">Primary target, likely damage, loss window, safe alternative, and intervention path.</p>
              </div>
            </div>
          </div>

          <div className="rounded-[2rem] border border-slate-700 bg-carbon/80 p-6">
            <h2 className="text-lg font-display">Operational Value</h2>
            <p className="mt-3 text-sm text-slate-300">
              CyberShield does not just classify scams. It reconstructs attacker intent, exposes the human manipulation layer, and helps stop the victim before credentials, money, or wallet access are handed over.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
