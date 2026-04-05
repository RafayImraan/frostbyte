# CyberShield

CyberShield is a real-time scam detection and intervention platform for phishing, impersonation, payment fraud, and wallet-drain attacks.

It combines:
- AI-assisted text risk analysis
- URL and domain intelligence
- behavioral page inspection
- psychological manipulation mapping
- attacker intent reconstruction
- in-browser intervention before sensitive user actions

## Architecture

CyberShield is split into three runtime surfaces:

1. `server/`
FastAPI backend that performs content analysis, threat scoring, manipulation mapping, impact forecasting, history storage, and explanation generation.

2. `client/`
Next.js application that presents the analyzer, results console, campaign command center, and platform landing experience.

3. `extension/`
Chrome extension that scans the active page, highlights suspicious signals, guards risky form submissions, and opens an intervention panel when a high-risk flow is detected.

## Core Capabilities

- Real-time message and URL analysis
- Threat casefile generation with attacker archetype and predicted next move
- Psychological manipulation mapping across fear, urgency, authority, greed, trust hijack, and confusion
- Impact forecasting with likely damage path and safer alternative
- Threat-feed enrichment through URLhaus and VirusTotal
- Campaign clustering and scan history
- Browser-side intervention for risky pages and credential capture surfaces

## Run Locally

### Backend

```powershell
cd server
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend

```powershell
cd client
npm install
npm run dev
```

The web application will be available at `http://localhost:3000`.

If a stale Next.js cache causes missing chunk errors such as `Cannot find module './860.js'`, run:

```powershell
cd client
npm run dev:clean
```

### Browser Extension

1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select the `extension/` directory

## Environment Variables

Create `server/.env` from `server/.env.example`.

Important variables:
- `VIRUSTOTAL_API_KEY`
- `MODEL_API_URL`
- `MODEL_API_KEY`
- `MODEL_NAME`
- `MODEL_PROVIDER`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`

## Validation

Frontend build:

```powershell
cd client
npm run build
```

Backend syntax check:

```powershell
cd ..
python -m py_compile server\main.py
```

## Security Notes

- Do not commit live API keys to source control.
- Rotate any keys that were previously stored in a tracked `.env` file.
- Keep `server/.env` local and use `server/.env.example` for sharing configuration shape.

## Product Positioning

CyberShield does not stop at identifying suspicious content.

It is built to answer five operational questions in real time:
- Is this dangerous?
- What is the attacker trying to obtain?
- Which psychological pressure tactics are being used?
- What happens next if the user continues?
- What is the safest immediate response?
