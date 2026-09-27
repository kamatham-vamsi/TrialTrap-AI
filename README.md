# TrialTrap AI

TrialTrap AI is a full-stack subscription intelligence app for tracking recurring payments, protecting free trials, monitoring renewals, importing subscriptions and asking a local smart AI advisor.

## Stack
- Python + FastAPI
- SQLite (PostgreSQL-ready configuration)
- HTML/CSS/JavaScript
- PWA support for mobile installation
- QR, CSV and calendar integrations

## Run locally
```bash
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload
```
Open `http://127.0.0.1:8000/app`.

## Environment
Copy `.env.example` to `.env` and set a strong `TRIALTRAP_SECRET` for deployment. SMTP/Twilio variables are optional.

## GitHub
Do not commit `backend/trialtrap.db` if it contains real user data. Use environment variables/secrets for production credentials.

## Mobile
Open the deployed HTTPS URL in Chrome on Android and use **Install App / Add to Home screen**.
