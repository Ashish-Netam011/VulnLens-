# VulnLens Frontend — Security Investigation Cockpit

The redesigned UI communicates the product's core loop on every screen:

> **Detect the risk → trace the attack path → understand the impact → fix the vulnerability.**

The deterministic scanner remains the source of truth. AI explains; the
scanner decides. This page documents the information architecture, the data
each screen reads, the AI/UI boundary, and the additive source-context
endpoint that powers the code viewer.

## Information architecture

```
VULNLENS
Overview                → Security posture (score, risk, recent scans/findings)
  Projects              → Codebase organization + per-project history
Scans
  New Scan              → Paste / file / folder upload → summary
  Scan History          → Every run, score trend, exports
Findings                → Filter/sort any scan's findings
  Finding Detail        → Verdict, code, data flow, Copilot (centerpiece)
Security Analysis
  Data Flow             → Source → propagation → sink per finding
AI Copilot              → Explain any deterministic finding
Reports                 → SARIF / JSON / in-app summary
Settings                → Session & security model (no server toggles)
```

### Pages → real data

| Screen | Backend source |
|---|---|
| Overview | `GET /api/dashboard`, `GET /api/projects`, `GET /api/scans/:id` (latest scan) |
| New Scan | `POST /api/scans` (code) or `POST /api/scans/upload` (folder) |
| Scan History | `GET /api/scans` |
| Scan detail | `GET /api/scans/:id`, `GET /api/scans/:id/comparison` |
| Findings / Finding detail | same scan endpoints; source window via `GET /api/scans/:id/source` |
| Security Analysis | scan findings + deterministic `evidence` flow paths |
| AI Copilot | `POST /api/ai/explain` |
| Reports | `GET /api/reports/:id/download`, `GET /api/reports/:id/sarif` |
| Settings | `GET /api/auth/me` (session only) |

Nothing is fabricated: fields a backend capability does not provide are shown
as honest empty/unavailable states rather than fake functionality.

## Finding Detail — the hero experience

1. **Verdict header** — severity (icon + label), deterministic verdict,
   confidence, rescan status (New / Pre-existing), file:line, rule id.
2. **What happened** — deterministic `evidence.explanation` / `reason`.
3. **Source context** — a bounded (~40-line) window around the finding from
   the source endpoint; the sink/finding line and any traced source lines are
   emphasized. When full source is unavailable, the captured
   `affectedCode` snippet is shown instead.
4. **Data flow** — vertical SOURCE → propagation → SINK chain(s) read from
   `evidence.interprocedural.correlation.dataFlow.paths` with
   parameterized/sanitized/constant flags. Findings without a traced flow get
   an explicit “no traced source→sink flow” state.
5. **AI Security Copilot** — structured explanation of *this* finding via the
   real endpoint, labelled **Detected by VulnLens · explained by AI Copilot**.
   Failure shows “AI explanation unavailable — the deterministic finding
   remains valid”, with retry.

## AI / UI boundary

- The UI renders finding severity/confidence/verdict read-only from scan data.
- The Copilot panel can only add explanation text; there is no UI path that
  creates, suppresses, or mutates a finding.
- Copilot “confidence” is labelled as explanation quality, never as a
  vulnerability verdict.
- Source context sent to the Copilot is the same bounded window the code
  viewer shows (max ~40 lines), never a whole repository.

## Source-context endpoint

`GET /api/scans/:id/source?file=<rel>&around=<line>`

- Read-only, JWT-protected, owner-scoped (same `Scan.findOne({_id, owner})`
  check as every scan route).
- The file is resolved **purely against the scan's own stored sources** —
  there is no filesystem access, so traversal is impossible by construction.
- Strict file grammar: `..`, `%`-encoding, backslashes, absolute paths and
  drive letters → `400`; well-formed names absent from the scan → `404`.
- `around` must be a positive integer within the file (else `400`); the
  response is at most 40 lines (20 above / 19 below), clamped at the file
  edges, with per-line truncation at 320 chars.
- Response: `{ success, file, startLine, endLine, targetLine, lines:[{line, code}] }`.

## Design system & accessibility

- Dark-first graphite surfaces, restrained indigo accent, severity colors
  reserved for severity. Inter for UI, JetBrains Mono for code/paths/ids.
- Severity is never color-only: badge = label + icon + tone.
- Global `:focus-visible` styling; semantic HTML (`table`/`caption`,
  `nav`, `main`, dialogs with `role="dialog"` + focus containment); keyboard
  navigation on tables and finding prev/next.
- `prefers-reduced-motion` disables animation; scrollbars and selection are
  styled; layouts collapse gracefully to a mobile drawer below `lg`.

## Limitations

- Source windows only exist for scans whose stored content is available; older
  or content-less scans fall back to the one-line snippet.
- Scan-level findings carry no CLI-style `baselineStatus`; regression state is
  shown from the scan-comparison API (`NEW` vs `Pre-existing` per finding).
- The scan request itself is synchronous — progress text reflects real client
  phases (read files → scan request) without invented percentages.
