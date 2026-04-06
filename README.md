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
copy .env.example .env.local
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
Create `client/.env.local` from `client/.env.example`.

Important variables:
- `VIRUSTOTAL_API_KEY`
- `MODEL_API_URL`
- `MODEL_API_KEY`
- `MODEL_NAME`
- `MODEL_PROVIDER`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `CORS_ALLOW_ORIGINS`
- `NEXT_PUBLIC_API_BASE_URL`

## Deploy To Vercel

Deploy the frontend and backend as two separate Vercel projects.

### Frontend project

1. Import the repository into Vercel.
2. Set the project `Root Directory` to `client`.
3. Add `NEXT_PUBLIC_API_BASE_URL` and point it to your deployed backend URL.
4. Deploy.

### Backend project

1. Import the same repository into Vercel again as a second project.
2. Set the project `Root Directory` to `server`.
3. Add the variables from `server/.env.example`.
4. Set `CORS_ALLOW_ORIGINS` to your deployed frontend URL, for example:

```text
https://your-frontend.vercel.app
```

5. Deploy. [app.py](/c:/Users/HomePC/Desktop/frosbyte/server/app.py) is included as the FastAPI entrypoint for Vercel.

Important: the backend currently stores history in local SQLite. On Vercel that storage is not durable across deployments, so deployed scan history should be treated as temporary until you move it to a hosted database.

## Validation

Frontend build:

```powershell
cd client
npm run build
```

Backend syntax check:

```powershell
cd ..
python -m py_compile server\main.py server\app.py
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

Live demo of project = https://frostbyte-xfvz.vercel.app/
Youtube video = https://youtu.be/iVNT909mYTU?si=i8Ff6P9hlOvypJ_Q
