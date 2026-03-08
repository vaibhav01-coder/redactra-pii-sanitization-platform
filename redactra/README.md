# THE BUREAU / CASE FILED

## Frontend: Vanilla HTML + CSS + JavaScript

The **canonical UI** is in the **`ui/`** folder (Vanilla HTML, CSS, and JavaScript). It is served directly by FastAPI: static assets at `/ui/*`, and the same `ui/index.html` shell for routes like `/`, `/login`, `/register`, `/dashboard`, `/upload`, `/operations`, `/token-vault`, and `/files/:id`.

- **`ui/index.html`** — Single-page shell (auth + app views).
- **`ui/styles.css`** — Layout, theme (light/dark), components.
- **`ui/app.js`** — All API calls, auth, navigation, dashboard, upload, file results, operations, token vault.

No build step: the backend serves these files as-is.

## Run locally

### 1. Backend (serves API + UI)

From the project root:

```bash
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 2. Access the project

Open in your browser: **http://localhost:8000** or **http://localhost:8000/login**

- **Login:** `lead.detective@casefiled.com` / `ChangeMe123!` (from `.env`).
- Or **Create Account** to register, then log in.

All routes (`/login`, `/dashboard`, `/upload`, etc.) serve the same `ui/index.html`; the vanilla app switches views with JavaScript and calls the FastAPI API on the same origin.

## V2 Additions Implemented

- Contextual PII linking (window + field-name anchors)
- Security sweep gate (VirusTotal hash lookup)
- Public user self-registration
- Row-level case privacy (`owner_id` enforcement)
- Batch uploads (`/upload/batch`) and status (`/upload/batch/{id}/status`)
- Auto-detect zip archives in `/upload/bulk`
- Duplicate detection via SHA-256
- Honeypot validation (`bureau_field`)
- File size anomaly and magic-byte checks
- EXIF stripping for images before processing
- Biometric recognizer expansion
- Format-preserving sealed output extension
- Bulk sealed download zip (`/files/bulk-download`)
- Auto-destruct scheduler every 30 min

## Important Notes

- If `VIRUSTOTAL_API_KEY` is empty, security sweep defaults to optimistic pass.
- For existing local DBs, reset/migrate schema because `case_files` and enums were expanded.
- For OCR in cloud, use Docker with Tesseract installed.
