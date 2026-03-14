"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { analyzeMessage, saveLatest } from "../../lib/api";
import { Logo } from "../../components/Logo";

const SAMPLE =
  "Congratulations! You won $5000. Click here to claim your reward: http://paypal-secure-login.xyz";

export default function AnalyzePage() {
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [consent, setConsent] = useState(true);
  const router = useRouter();

  const handleSubmit = async () => {
    setError(null);
    if (!message.trim()) {
      setError("Paste a message, email, or URL to scan.");
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
      <header className="flex items-center justify-between">
        <Logo />
        <button
          className="px-4 py-2 rounded-full border border-slate-600 text-slate-200"
          onClick={() => router.push("/")}
        >
          Back to Landing
        </button>
      </header>

      <section className="mt-14 grid lg:grid-cols-2 gap-10">
        <div>
          <h1 className="text-3xl font-display">Analyzer Dashboard</h1>
          <p className="text-slate-300 mt-4">
            Paste SMS, emails, WhatsApp messages, or suspicious links. The AI model scans for
            phishing patterns, scam signals, and risky URLs.
          </p>

          <div className="mt-6 flex flex-col gap-4">
            <textarea
              className="min-h-[220px] rounded-2xl border border-slate-700 bg-carbon/60 p-4 text-sm text-white focus:outline-none focus:ring-2 focus:ring-neon"
              placeholder="Paste a suspicious message here..."
              value={message}
              onChange={(event) => setMessage(event.target.value)}
            />
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                className="px-6 py-3 rounded-full bg-neon text-midnight font-semibold shadow-glow"
                onClick={handleSubmit}
                disabled={loading}
              >
                {loading ? "Analyzing..." : "Analyze for Scam"}
              </button>
              <button
                className="px-6 py-3 rounded-full border border-slate-600 text-slate-200"
                onClick={() => setMessage(SAMPLE)}
                disabled={loading}
              >
                Use Sample Text
              </button>
            </div>
            <label className="flex items-center gap-3 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={consent}
                onChange={(event) => setConsent(event.target.checked)}
                className="h-4 w-4 rounded border-slate-600 bg-carbon/60 text-neon focus:ring-neon"
              />
              Allow storing this scan in history
            </label>
            <p className="text-[11px] text-slate-500">
              Privacy note: If unchecked, the message content won’t be saved.
            </p>
            {error && <p className="text-ember text-sm">{error}</p>}
          </div>
        </div>

        <div className="bg-carbon/80 border border-slate-700 rounded-3xl p-6 shadow-haze">
          <h2 className="text-lg font-display">What we scan</h2>
          <ul className="mt-4 text-sm text-slate-300 space-y-3">
            <li>AI text classifier (phishing, spam, financial, crypto)</li>
            <li>URL inspection and suspicious keyword matching</li>
            <li>Threat intelligence reputations</li>
            <li>Urgency, reward bait, impersonation, and payment signals</li>
          </ul>
          <div className="mt-6 border border-slate-700 rounded-2xl p-4 bg-midnight">
            <p className="text-xs text-slate-400">Expected output</p>
            <p className="text-sm mt-2">Scam Probability: 92% | Risk Level: HIGH</p>
            <p className="text-xs text-slate-400 mt-2">Reasons: suspicious domain, urgency phrase, reward bait</p>
          </div>
        </div>
      </section>
    </div>
  );
}
