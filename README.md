# Bug Bunny.ai Local Audit Console

Local MVP for an audit console with a React dashboard, Python FastAPI backend, SQLite storage, and per-run artifacts.

This is mock scanner mode only. It does not perform active exploitation, does not use Google APIs, and does not require an OpenAI API key.

## Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm install
```

## Run Backend

```bash
npm run api
```

FastAPI runs at:

```text
http://127.0.0.1:8000
```

## Run Frontend

In a second terminal:

```bash
npm run web
```

Open:

```text
http://127.0.0.1:5173/
```

## Run Both

```bash
npm run dev
```

## API

- `POST /api/audits/create`
- `GET /api/audits`
- `GET /api/audits/{run_id}`
- `POST /api/audits/{run_id}/run-mock-scan`
- `GET /api/audits/{run_id}/findings`
- `POST /api/audits/{run_id}/generate-report`

## Storage

SQLite database:

```text
audit_console.sqlite3
```

Each created hunt writes:

```text
runs/{run_id}/
runs/{run_id}/raw/
runs/{run_id}/reports/
```

Mock scan output:

```text
runs/{run_id}/raw/mock_scan.json
```

Generated report:

```text
runs/{run_id}/reports/report.md
```
