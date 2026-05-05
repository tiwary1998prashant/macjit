# MacJit Garage Management System — KT Document

**Stack:** FastAPI (Python) + React (CRA) + MongoDB  
**Hosting:** Render.com (backend) | Render / Netlify / Vercel (frontend)  
**Branches:** `main` → Production | `dev` → Development / Staging

---

## Project Structure

```
macjit-garage/
├── backend/
│   ├── server.py              # App entry point — FastAPI app, all middleware wired here
│   ├── config.py              # Reads env vars + loads the right .env.* file automatically
│   ├── constants.py           # Static values (default prices, loyalty discount %)
│   ├── database.py            # MongoDB connection (Motor async client)
│   ├── models.py              # Pydantic request/response models
│   ├── business.py            # Business logic helpers
│   ├── events.py              # Internal event bus (WebSocket fan-out)
│   ├── server_shared.py       # Shared helpers used across route files
│   ├── requirements.txt       # Python dependencies — pip install -r this
│   ├── render.yaml            # Render.com deployment config (startCommand lives here)
│   ├── adapters/
│   │   ├── razorpay.py        # Razorpay payment link + webhook signature verification
│   │   ├── twilio.py          # WhatsApp / SMS via Twilio
│   │   ├── kafka.py           # Kafka event bus (optional, enable by setting KAFKA_BOOTSTRAP)
│   │   └── rabbit.py          # RabbitMQ adapter (optional, enable by setting RABBITMQ_URL)
│   ├── routes/
│   │   ├── auth/auth.py       # Login, OTP, JWT
│   │   ├── admin/             # Admin dashboard (staff, services, transactions)
│   │   ├── booking/           # Booking CRUD + progress updates
│   │   ├── shop/              # Counter sales, refunds, Razorpay webhook
│   │   ├── customer/          # Public vehicle tracker (no login needed)
│   │   ├── hr/                # HR / salary routes
│   │   └── core/              # WebSocket, notifications, seeding
│   ├── utils/
│   │   ├── encryption.py      # Fernet field-level encryption / decryption
│   │   ├── auth.py            # JWT helpers, role guards
│   │   ├── otp.py             # OTP generation
│   │   └── rate_limit.py      # In-memory rate limiter
│   ├── .env.example           # SAFE TO COMMIT — template with placeholder values only
│   ├── .env.local             # NOT committed — your local machine secrets
│   ├── .env.dev               # NOT committed — dev/staging secrets
│   └── .env.prod              # NOT committed — prod secrets (only for running prod locally)
└── frontend/
    ├── src/
    │   ├── pages/             # All page components
    │   ├── lib/api.js         # Axios instance — reads REACT_APP_API_BASE from env
    │   └── App.jsx            # Router + auth wrapper
    ├── .env.example           # SAFE TO COMMIT — template only
    ├── .env.local             # NOT committed — local dev
    ├── .env.development       # NOT committed — staging build
    └── .env.production        # NOT committed — production build
```

---

## How Environment Switching Works (read this first)

### Backend

`config.py` automatically picks the right `.env` file based on ONE shell variable you set before starting the server:

```
ENVIRONMENT=local   →  loads backend/.env.local
ENVIRONMENT=dev     →  loads backend/.env.dev
ENVIRONMENT=prod    →  loads backend/.env.prod
```

**Zero lines of code need to be commented or changed between environments.**  
Everything (HTTPS, CORS, trusted hosts) is controlled by env vars — see table below.

| Feature | Controlled by env var | Local value | Prod value |
|---|---|---|---|
| HTTPS redirect | `FORCE_HTTPS` | leave blank / `0` | `1` |
| Trusted host check | `ALLOWED_HOSTS` | leave blank | `your-domain.com` |
| CORS allowed origins | `CORS_ORIGINS` | `http://localhost:3000` | `https://your-domain.com` |
| Razorpay enabled | `RAZORPAY_KEY_ID` | leave blank = disabled | set real key |
| Twilio enabled | `TWILIO_ACCOUNT_SID` | leave blank = disabled | set real SID |

### Frontend

React CRA picks the right env file automatically by `NODE_ENV`:

```
npm start        →  reads .env.local  (NODE_ENV=development)
npm run build    →  reads .env.production  (NODE_ENV=production)
```

**Zero lines of frontend code need to be changed between environments.**

---

## 1. Run Locally — After Any Bug Fix or Feature

### One-time setup

```bash
# Clone the repo
git clone <your-repo-url>
cd macjit-garage
```

### Backend setup

```bash
cd backend

# Create and activate Python virtual environment
python -m venv .venv

# Activate — Mac/Linux:
source .venv/bin/activate
# Activate — Windows CMD:
.venv\Scripts\activate
# Activate — Windows PowerShell:
.venv\Scripts\Activate.ps1

# Install all dependencies
pip install -r requirements.txt
```

### Create your local env file

```bash
cp .env.example .env.local
```

Open `backend/.env.local` and fill in these values (minimum required):

```
ENVIRONMENT=local
MONGO_URL=mongodb://localhost:27017        # if running MongoDB locally
# OR use your Atlas free-tier connection string:
# MONGO_URL=mongodb+srv://user:pass@cluster.mongodb.net
DB_NAME=macjit_local
JWT_SECRET=any-random-string-is-fine-locally
ENCRYPTION_KEY=any-32-character-string!!99
PUBLIC_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000
```

Leave `RAZORPAY_*` and `TWILIO_*` blank — they disable themselves automatically when not set.

### Start the backend

```bash
# Mac/Linux:
ENVIRONMENT=local uvicorn server:app --reload --host 0.0.0.0 --port 8000

# Windows CMD:
set ENVIRONMENT=local && uvicorn server:app --reload --host 0.0.0.0 --port 8000

# Windows PowerShell:
$env:ENVIRONMENT="local"; uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

Backend runs at: `http://localhost:8000`  
Swagger API docs: `http://localhost:8000/docs`  
Health check: `http://localhost:8000/api/health` → should return `{"status":"ok"}`

### Frontend setup

```bash
cd ../frontend

# First time only:
npm install

# Create your local env file:
cp .env.example .env.local
```

`frontend/.env.local` should contain:

```
REACT_APP_API_BASE=http://localhost:8000/api
REACT_APP_WS_BASE=ws://localhost:8000/ws
```

### Start the frontend

```bash
npm start
```

Frontend opens at: `http://localhost:3000`

---

## 2. Run Dev / Staging Environment

Dev environment uses a separate staging MongoDB DB and Razorpay test keys.

### Backend — dev

Fill in `backend/.env.dev` with real staging values:

```
ENVIRONMENT=dev
MONGO_URL=mongodb+srv://user:pass@cluster.mongodb.net
DB_NAME=macjit_dev                  # different DB name from prod — important!
JWT_SECRET=a-staging-secret-string
ENCRYPTION_KEY=staging-encryption-key-32chars
RAZORPAY_KEY_ID=rzp_test_xxxx       # use Razorpay TEST keys, not live
RAZORPAY_KEY_SECRET=xxxx
RAZORPAY_WEBHOOK_SECRET=test-webhook-secret
TWILIO_ACCOUNT_SID=ACxxxx
TWILIO_AUTH_TOKEN=xxxx
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
PUBLIC_URL=https://your-dev-domain.com
CORS_ORIGINS=https://your-dev-frontend.com
```

Start backend on your staging server:

```bash
ENVIRONMENT=dev uvicorn server:app --host 0.0.0.0 --port 8000
```

### Frontend — dev build

Edit `frontend/.env.development`:

```
REACT_APP_API_BASE=https://your-dev-backend.com/api
REACT_APP_WS_BASE=wss://your-dev-backend.com/ws
```

Build and deploy:

```bash
npm run build
# Upload the build/ folder to your staging host (Netlify / Vercel / S3 / etc.)
```

---

## 3. Push to Production

### Git workflow

```bash
# After testing locally:
git add .
git commit -m "feat: describe what you added"

# Push to dev branch → test on staging
git push origin dev

# Once staging is confirmed OK → merge to main → triggers Render auto-deploy
git checkout main
git merge dev
git push origin main
git checkout dev   # go back to dev for next work
```

### Render.com — backend production setup

Production env vars are set INSIDE the Render dashboard only.  
**Do NOT rely on `.env.prod` on Render** — that file won't be deployed there.  
The `.env.prod` file exists only so you can run with prod config locally if needed.

**Go to: Render Dashboard → Your backend service → Environment → Add these:**

```
ENVIRONMENT             prod
MONGO_URL               mongodb+srv://user:pass@cluster.mongodb.net
DB_NAME                 macjit
JWT_SECRET              <generate: python -c "import secrets; print(secrets.token_hex(32))">
ENCRYPTION_KEY          <generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
RAZORPAY_KEY_ID         rzp_live_xxxx
RAZORPAY_KEY_SECRET     xxxx
RAZORPAY_WEBHOOK_SECRET xxxx
TWILIO_ACCOUNT_SID      ACxxxx
TWILIO_AUTH_TOKEN       xxxx
TWILIO_WHATSAPP_FROM    whatsapp:+91xxxxxxxxxx
TWILIO_SMS_FROM         +91xxxxxxxxxx
PUBLIC_URL              https://your-production-domain.com
CORS_ORIGINS            https://your-production-domain.com
FORCE_HTTPS             1
ALLOWED_HOSTS           your-production-domain.com
```

Render's start command (already in `render.yaml`, no change needed):

```
uvicorn server:app --host 0.0.0.0 --port $PORT
```

Every `git push origin main` triggers an auto-deploy on Render.

### Frontend — production build

Edit `frontend/.env.production`:

```
REACT_APP_API_BASE=https://your-production-domain.com/api
REACT_APP_WS_BASE=wss://your-production-domain.com/ws
```

```bash
npm run build
# Deploy the build/ folder to Netlify / Vercel / Render static site / S3+CloudFront
```

---

## Files — What to Commit vs What to Skip

### Add to `.gitignore` before your first commit

```
# Backend — secrets, never commit these
backend/.env.local
backend/.env.dev
backend/.env.prod
backend/.venv/
backend/__pycache__/
backend/**/__pycache__/
backend/**/*.pyc

# Frontend — secrets and build output
frontend/.env.local
frontend/.env.development
frontend/.env.production
frontend/node_modules/
frontend/build/
```

### Safe to commit (no real secrets inside)

```
backend/.env.example      ← has placeholder values only, commit this
frontend/.env.example     ← same, commit this
backend/render.yaml       ← Render config, commit this (no secrets)
backend/requirements.txt  ← dependency list, commit this
```

**Why this matters:** If `.env.dev` or `.env.prod` gets committed accidentally, your  
MongoDB password, Razorpay keys, and JWT secret become part of git history forever —  
even after deletion. Rotate all secrets immediately if this happens.

---

## Razorpay Webhook — Local Testing

Razorpay cannot reach `localhost`. Use ngrok to expose your local port:

```bash
# Terminal 1 — backend running:
ENVIRONMENT=local uvicorn server:app --reload --port 8000

# Terminal 2 — ngrok tunnel:
ngrok http 8000
# ngrok gives you a URL like: https://abc123.ngrok-free.app

# In Razorpay Dashboard → Settings → Webhooks → Add Webhook:
#   URL: https://abc123.ngrok-free.app/api/webhooks/razorpay
#   Secret: must match RAZORPAY_WEBHOOK_SECRET in your .env.local
```

---

## Common Issues

| Problem | Cause | Fix |
|---|---|---|
| `KeyError: 'MONGO_URL'` on startup | `ENVIRONMENT` var not set | Add `ENVIRONMENT=local` before the uvicorn command |
| Frontend shows network error | Backend not running or wrong port | Check backend terminal, verify `.env.local` has correct port |
| CORS error in browser | Origin mismatch | `CORS_ORIGINS` must exactly match your frontend URL (no trailing slash) |
| Old JWT tokens rejected after change | `JWT_SECRET` changed | Log out and log in again — expected |
| `ModuleNotFoundError: cryptography` | venv not activated or fresh install | Run `pip install -r requirements.txt` inside activated venv |
| Razorpay webhook returns 400 | Signature mismatch | `RAZORPAY_WEBHOOK_SECRET` must match the secret set in Razorpay dashboard exactly |
| `ALLOWED_HOSTS` blocking requests | Set in dev accidentally | Leave `ALLOWED_HOSTS` blank for local; only set it in prod |
