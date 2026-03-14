# AI CyberShield – Real‑Time Scam & Fraud Detection System

AI CyberShield is a hackathon‑ready, end‑to‑end security product that detects scams, phishing attempts, and malicious links in real time. It combines AI classification, threat intelligence, and behavioral signals to deliver **scam probability**, **risk level**, and **explainable reasons**—plus a **browser extension** that protects users while they browse.

---

## Judge‑Focused Summary
I built this as a **working prototype**, not just a dashboard. It actively protects users with:
- Live AI analysis of messages and links
- Threat‑intel reputation checks
- Explainable results (highlights + confidence bands)
- A browser extension with real‑time warnings and optional auto‑block

This turns AI CyberShield from a passive tool into an **active defense system**.

---

## Prototype Stack (Why These Choices)
To maximize impact, speed, and reliability for judging:
- **Frontend:** Next.js + TailwindCSS for a clean, product‑grade UI
- **Backend:** FastAPI for fast AI scoring and real‑time API responses
- **AI/NLP:** Hugging Face Inference API (model: `gplsi/Aitana-FraudDetection-R-1.0`)
- **Threat Intel:** URLhaus + VirusTotal (stable free feeds)
- **Database:** SQLite for lightweight demo storage
- **Browser Extension:** Chrome Manifest V3 for real‑time scanning

---

## Core Features
- AI NLP scam classification (hosted model)
- URL scanning with reputation hints and brand impersonation checks
- Pattern detection engine (urgency, reward bait, authority, financial, crypto)
- Explainable output with highlights + confidence band
- Behavioral phishing detection (login forms, hidden inputs, popups, redirects, crypto wallets)
- Real‑time browser extension with offline fallback and auto‑block
- Threat history dashboard with metrics and reporting

---

## Architecture

Frontend (Next.js + Tailwind)
- Landing Page
- Analyzer Dashboard
- Results Page
- History Page

Backend (FastAPI)
- `/analyze` -> AI + rules + URL scan
- `/scan-url` -> fast URL scan for extension
- `/scan-page` -> URL + page content + behavior signals
- `/scan/{id}` -> polling endpoint for async updates
- `/history` -> scan history
- `/report` -> community reporting
- `/metrics` -> dashboard metrics
- `/explain` -> AI assistant explanation (optional)

---

## Local Setup

### 1) Backend
```bash
cd server
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

### 2) Frontend
```bash
cd client
npm install
npm run dev
```

Open `http://localhost:3000`.

---

## API Example
```json
POST /analyze
{
  "text": "Congratulations! You won $5000. Click here to claim your reward: http://paypal-secure-login.xyz",
  "consent": true
}
```

---

## Security & Privacy
- **Consent‑first storage:** message content is saved only if the user opts in
- **Local fallback:** extension still flags risks if API is unavailable
- **Model transparency:** AI endpoint is configurable and replaceable

---

## Browser Extension (Real‑Time Protection)
The `extension/` folder contains a Chrome Manifest V3 extension.

### What it does
- Captures URL + page text
- Calls `/scan-page`
- Shows warning banner for high‑risk pages
- Highlights suspicious phrases and links
- Auto‑block quarantine mode (optional)
- Offline heuristic scan if API is down

### Load the extension
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

---

## Demo Checklist (What Judges Can See)
- Landing page with live demo preview
- Analyzer dashboard (paste + scan)
- Results page with explainable AI + confidence band
- Threat feeds panel + risk meter
- Browser extension warning banner
- History dashboard with metrics

---

## Deployment
- Frontend: Vercel
- Backend: Render / Railway / Docker

---

## Docker (Backend)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY server/ /app/
RUN pip install -r requirements.txt
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
