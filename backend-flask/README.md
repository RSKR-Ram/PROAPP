# HRMS Flask Backend (GAS Migration)

This folder contains a Flask + SQLAlchemy backend that matches the existing Google Apps Script `/doPost` contract:

- `POST /api`
- Request JSON: `{ "action": "...", "token": "...", "data": { ... } }`
- Success: `{ "ok": true, "data": ... }`
- Error: `{ "ok": false, "error": { "code": "...", "message": "..." } }`

## Setup (local)

```bash
cd backend-flask
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

## Run (production-style)

Install deps and run with Gunicorn:

```bash
cd backend-flask
pip install -r requirements.txt
gunicorn -b 0.0.0.0:5000 -w 2 wsgi:app
```

## Deploy (GCP Cloud Run)

This folder includes a `Dockerfile` suitable for Cloud Run.

```bash
gcloud run deploy hrms-backend \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated
```

Set these env vars in Cloud Run:

- `DATABASE_URL` (recommended: `postgresql+psycopg2://...`)
- `ALLOWED_ORIGINS` (your GitHub Pages origin)
- `GOOGLE_CLIENT_ID`

## Environment

See `.env.example` for all supported variables.

## Data migration (optional)

If you export Google Sheets tabs as CSVs (one file per tab), you can import them:

```bash
cd backend-flask
python services/sheets_migration.py --csv-dir ./csv
```

## Endpoints

- `GET /health` (open `http://127.0.0.1:5000/health` in browser)
- `POST /api` (use Postman/curl; don’t type `GET /api` in the browser URL)
- `GET /files/<fileId>?token=ST-...` (opens uploaded CVs/screenshots/docs stored in `UPLOAD_DIR`)

## Quick API test (PowerShell)

```powershell
$body = @{
  action = "GET_ME"
  token  = "ST-..."
  data   = @{}
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/api" -ContentType "application/json" -Body $body
```

## Tests

```bash
cd backend-flask
pytest
```

## Rate limiting

Rate limits are per-IP and configurable via env vars:
- `RATE_LIMIT_DEFAULT` (per-action; default `300 per minute`)
- `RATE_LIMIT_GLOBAL` (overall; default `2000 per minute`)
- `RATE_LIMIT_LOGIN` (login endpoints; default `30 per minute`)
