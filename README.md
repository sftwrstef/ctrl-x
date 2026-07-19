# Bug Bunny.ai Local Audit Console

Local security-proof console with a React dashboard, Python FastAPI backend,
SQLite storage, per-run artifacts, and an executable victim-centered IDOR
replay.

The original May audit pipeline remains mock scanner mode. The OpenAI Build
Week extension adds a real, bounded proof that runs only against an ephemeral
localhost fixture. It does not contact an external target and does not require
an OpenAI API key.

## OpenAI Build Week extension

**Verified IDOR Replay** moves Bug Bunny beyond a scanner-shaped dashboard:

1. Start a deliberately vulnerable profile API on `127.0.0.1` using a random
   port and deterministic attacker/victim seed data.
2. Confirm the endpoint rejects an unauthenticated request.
3. Execute the strongest truthful control: the attacker requests their own
   profile and receives it successfully.
4. From the same state and identity, execute the disputed request: the attacker
   requests the victim profile and receives the victim's private data.
5. Assert the victim-centered harm, redact the bearer token, hash the state and
   responses, and write a machine-readable proof artifact.
6. Render the control/exploit matrix in the product UI.

Pre-existing and eligible work are separated in
[`PREEXISTING.md`](PREEXISTING.md) and
[`DEV_WEEK_WORK.md`](DEV_WEEK_WORK.md).

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

Open `http://127.0.0.1:5173/`, scroll to **Verified IDOR Replay**, and select
**Run real proof**.

## Run the proof without the UI

```bash
npm run prove:idor
npm run test:proof
```

The CLI writes `artifacts/idor-before.json`. A dated verified sample and UI
screenshot are preserved in `evidence/dev-week/`.

## API

- `POST /api/audits/create`
- `GET /api/audits`
- `GET /api/audits/{run_id}`
- `POST /api/audits/{run_id}/run-mock-scan`
- `GET /api/audits/{run_id}/findings`
- `POST /api/audits/{run_id}/generate-report`
- `POST /api/proofs/idor/run`

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

## Codex collaboration

The Build Week extension was implemented in Codex Desktop with GPT-5.6 Sol.

- Primary session ID: `019f7376-015c-78b3-a2ea-7b43e4b03b40`
- Codex implemented the localhost proof fixture, same-state control/exploit
  oracle, assertions, FastAPI endpoint, React proof matrix, focused test, and
  evidence documentation.
- Human product decisions kept the slice to one vulnerability class, required
  victim-private-data exposure instead of treating a status code as proof,
  required the strongest truthful control from identical state, and prohibited
  external targets.
- Codex was also used to restore and verify clean dependencies, run the focused
  proof test, build the frontend, check dependency advisories, and exercise the
  UI in a real browser.

Run `/feedback` in this primary Codex task before submitting and enter the
resulting session ID in Devpost.

## Supported and verified platform

- Verified: macOS 26.5, Node.js 25.9.0, Python 3.14.4.
- Intended: current macOS with Node.js 20+ and Python 3.11+.
- No API credentials, external service, Docker daemon, or non-local target is
  needed for the verified replay.
