# Dev Week work ledger

Submission period: July 13, 2026 at 9:00 AM PT through July 21, 2026 at
5:00 PM PT.

## Administrative baseline work

- July 19: Imported the untouched May Bug Bunny source into the Dev Week
  workspace so subsequent work can be tracked in Git.
- July 19: Added baseline disclosure, source hashes, and pre-existing QA
  screenshots.

Administrative baseline work is not claimed as new product functionality.

## Eligible product work

### July 19: Verified IDOR Replay

- Added an ephemeral localhost profile API with deterministic attacker and
  victim records.
- Added a same-state truthful control and attacker replay over real HTTP.
- Added a negative control proving unauthenticated access is rejected.
- Added assertions for legitimate attacker access and unauthorized exposure of
  the victim's private record.
- Added redacted, hashed, machine-readable proof artifacts.
- Added `POST /api/proofs/idor/run` to execute and persist the proof.
- Added the Verified IDOR Replay control/exploit matrix to the React UI.
- Added a focused standard-library test and one-command CLI reproduction.
- Restored clean dependencies and updated the imported lockfile until
  `npm audit` reported zero known vulnerabilities.
- Removed Uvicorn reload mode from the judge/demo command after clean setup
  showed it repeatedly watching and restarting on `.venv` files.

This is the first product functionality claimed as Dev Week work. It was built
in Codex Desktop with GPT-5.6 Sol in primary session
`019f7376-015c-78b3-a2ea-7b43e4b03b40`.

## Verification receipts

- `python3 -m unittest tests.test_idor_proof -v`: pass.
- Two independent proof executions were identical after removing only the
  generated timestamp.
- `npm run build`: pass with Vite 7.3.6.
- `npm audit --omit=dev`: zero known vulnerabilities.
- Browser flow: opened the app, selected **Run real proof**, observed the
  verified control/exploit matrix, and recorded no browser console errors.
- JSON proof: `evidence/dev-week/verified-idor-proof.json`.
- UI capture: `evidence/dev-week/dev-week-verified-idor.png`.
