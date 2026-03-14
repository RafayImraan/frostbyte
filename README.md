# AI CyberShield – Real-Time Scam & Fraud Detection System

AI CyberShield is a hackathon-ready prototype that analyzes suspicious messages, URLs, and crypto-related content using a hybrid AI + rules engine. It returns a scam probability, risk level, and an explanation of why content is suspicious.

## Features

- AI NLP scam classification (rule-driven stand-in for DistilBERT/RoBERTa)
- URL scanning with reputation hints, suspicious TLDs, and brand impersonation checks
- Pattern detection engine (urgency, reward bait, authority, financial request, crypto)
- Risk score engine that fuses AI + URL + pattern signals
- Explainable output with reasons and matched patterns
- History storage (SQLite for demo) with API endpoint

## Architecture

Frontend (Next.js + Tailwind)
- Landing Page
- Analyzer Dashboard
- Results Page
- History Page

Backend (FastAPI)
- `/analyze` -> runs AI scoring, URL scan, pattern matching, risk score
- `/history` -> returns recent scans

```
client (Next.js)
  -> /analyze
server (FastAPI)
  -> AI Text Analyzer
  -> URL Scanner
  -> Reputation + Pattern Engine
  -> Risk Score Engine
```

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

## API Example

```
POST /analyze
{
  "text": "Congratulations! You won $5000. Click here to claim your reward: http://paypal-secure-login.xyz"
}
```

Response fields:
- `scam_probability` (0-100)
- `risk_score` (0-100)
- `risk_level` (Low | Medium | High)
- `reasons` (explainable signals)
- `url_findings` (domain reputation, age, similarity)

## Notes

- This prototype uses rule-based scoring to simulate an NLP model. Swap in a fine-tuned DistilBERT/RoBERTa model in `server/main.py`.
- You can enable a hosted NLP model by setting `MODEL_API_URL` and `MODEL_API_KEY` (e.g., Hugging Face Inference API).
- SQLite is used for the hackathon demo. Replace with MongoDB or PostgreSQL by swapping `store_scan` and `history` logic.
- Threat intelligence integrations are optional; URLhaus (free) and VirusTotal enrich URL reputation.
- Threat feeds run asynchronously; results update the scan status and can be polled via `/scan/{id}`.

## Demo Checklist

- Landing page with live demo CTA
- Analyzer dashboard with sample text
- Results page with risk meter and explanations
- History page showing prior scans

## Deployment

- Frontend: Vercel
- Backend: Render / Railway / Docker

## Security & Privacy

- **Consent-first storage:** message content is not stored in scan history unless the user explicitly opts in.
- **Local processing fallback:** the browser extension performs a local heuristic scan if the API is unavailable.
- **Model transparency:** the AI model endpoint is configurable via env vars and can be swapped for open-source fine-tuned models.

## Browser Extension (Real-Time Protection)

The `extension/` folder contains a Chrome Manifest V3 extension that scans pages in real-time and shows an alert for high-risk pages.

### Load the extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

### What it does

- Captures the current page URL + text snippet
- Calls `POST /scan-page`
- Shows a warning banner for high risk pages
- Updates the popup with threat feed status

```
Docker backend example
FROM python:3.11-slim
WORKDIR /app
COPY server/ /app/
RUN pip install -r requirements.txt
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
