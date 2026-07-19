<div align="center">

# 🐰 Bug Bunny

### Authorized Web recon. Evidence-first findings. Verified proof replay.

`LOCAL-FIRST` &nbsp; `VICTIM-CENTERED` &nbsp; `EVIDENCE-BACKED` &nbsp; `OPENAI BUILD WEEK 2026`

<sub>Built with Codex · React / FastAPI / SQLite · bounded GET/HEAD checks</sub>

</div>

---

> [!IMPORTANT]
> **Observe broadly. Claim narrowly. Prove what matters.**
>
> Bug Bunny maps an authorized Web target with bounded live checks, separates
> observations from verified findings, builds reproducible evidence, and can take
> an authorization claim through a same-state exploit replay.

![Bug Bunny authorized Safe Web Hunter](evidence/dev-week/safe-web-hunter.png)

## What the live Web hunter does

| Phase | Bounded behavior | Output |
| --- | --- | --- |
| **Scope** | Requires explicit authorization and records operator limits | Immutable run context |
| **Recon** | DNS, homepage, title, forms, same-origin links, robots.txt | Raw local evidence |
| **Route map** | Same-origin `GET`/`HEAD` checks with time, redirect, and size limits | Route/status inventory |
| **Trust checks** | Headers, cookies, CORS, dotfile validation | Evidence-backed observations |
| **Handoff** | Repro commands, duplicate-search leads, timeline, Markdown | Persistent SQLite run + report |

Generic hardening gaps are labeled as observations—not inflated into bounty-grade
vulnerabilities. Active exploitation remains disabled for live targets.

## Verified IDOR proof, at a glance

| | Check | Result |
| :---: | --- | --- |
| `01` | **Negative control** | No token → `401 Unauthorized` |
| `02` | **Truthful control** | Attacker can read *their own* profile |
| `03` | **Exploit replay** | Attacker reads the victim’s private data |
| `04` | **Evidence** | Tokens redacted; state and responses hashed |

> [!NOTE]
> This is not a status-code demo. The replay asserts exposure of victim-private data
> from the same seeded state and identity used for the valid control.

## How proof replay works

```text
seed attacker + victim
          │
          ▼
start vulnerable API on localhost
          │
          ├── valid request ─────► attacker profile
          │
          └── disputed request ──► victim private data
                                          │
                                          ▼
                                  write redacted proof artifact
```

The proof fixture uses a random `127.0.0.1` port and never contacts a third-party target.

## Run it

```bash
git clone https://github.com/sftwrstef/bug-bunny.git
cd bug-bunny

npm install
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

npm run dev
```

Open the Vite URL. Choose **Run safe Web audit** for the authorized read-only hunter,
or **Run real proof** for the deterministic localhost IDOR replay.

```bash
# Verify both real workflows without the UI
npm run test:web
.venv/bin/python -m unittest tests.test_idor_proof -v
```

Evidence is written to [`evidence/dev-week/verified-idor-proof.json`](evidence/dev-week/verified-idor-proof.json).

## Inside the repo

```text
src/                    React hunt console + evidence views
server/auditEngine.js   Bounded live Web recon and analysis engine
backend/                Persistent API, report pipeline, proof bridge
proofs/idor_proof.py    Local fixture + replay engine
tests/                  Deterministic local Web audit + IDOR proof tests
evidence/dev-week/      Generated artifact + demo screenshot
```

## Dev Week provenance

| Pre-existing baseline | Dev Week extension |
| --- | --- |
| Dashboard, FastAPI API, SQLite storage, disconnected Web engine | Live engine integration, scope guardrails, persistent evidence, verified IDOR replay, focused tests |

Built collaboratively with **Codex** using **GPT-5.6 Sol**.
Primary session: `019f7376-015c-78b3-a2ea-7b43e4b03b40`.

Read the boundary in [`PREEXISTING.md`](PREEXISTING.md) and [`DEV_WEEK_WORK.md`](DEV_WEEK_WORK.md).

---

<div align="center">

`make the harm legible.`

</div>
