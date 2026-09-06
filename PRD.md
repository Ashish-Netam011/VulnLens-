# VulnLens AI — Product Requirements Document (PRD)

**Status:** Active · **Version:** 1.3 · **Last updated:** 2026-09-01

This document is the source of truth for the VulnLens AI product. Code comments reference
sections here as `PRD §<n>`. It describes the product as currently built, including the
multi-file **folder upload** capability.

---

## 1. Product Overview

VulnLens AI is an AI-powered cybersecurity analysis platform that helps developers and
security reviewers identify, understand, and verify security vulnerabilities in their
source code. It combines a deterministic rule-based static scanner with optional AI
explanations, rescan verification, and downloadable JSON reports.

The platform scans **single files (paste or upload) and entire project folders**, attributes
every finding to its file path, and tracks fixes over time via structured rescan diffing.

### 1.1 Problem statement

- Static-analysis tools are noisy and produce results developers don't trust.
- AI-only scanners are non-deterministic and can hallucinate severity or fixes.
- Teams lack a lightweight way to verify that reported vulnerabilities are actually fixed.
- Reviewing a whole project today means uploading files one at a time.

### 1.2 Solution

- A **deterministic rule engine** produces reproducible, severity-weighted findings.
- **AI enrichment** (Opt-in; OpenRouter cloud or Ollama local) adds explanations, impact,
  remediation, and secure examples without controlling the score.
- **Rescan verification** diffs stable finding keys to report resolved / remaining / new.
- **Multi-file scanning** lets a user review an entire project folder in one pass, with
  findings tied to relative file paths.

### 1.2a Shipped reference — verified working features

The following are **implemented, tested, and running** (verified via `npm test` — 10 passing —
plus live end-to-end checks in §6). See §4 for full details:

- **Auth & ownership** — JWT register/login/me, bcrypt hashing, owner-isolated data.
- **Projects** — full CRUD with per-owner isolation.
- **Scanning — single file** — paste code or upload one file; 8 rule categories.
- **Scanning — project folder** — select an entire folder or drag-and-drop it (≤100 files),
  per-file finding attribution, path sanitization, `language: "mixed"`.
- **Risk score (0–100)** — deterministic, severity-weighted, AI-independent.
- **AI enrichment (opt-in)** — `none`/`openrouter`/`ollama`, with offline rule fallback.
- **Rescan verification** — resolved / remaining / new diffing (single-file & folder).
- **Reports** — JSON download with per-file breakdown for folder scans; secrets masked.
- **Dashboard** — cross-project security metrics.
- **Security hardening** — helmet headers, CORS, rate limiting, Zod validation.


### 1.3 Goals (v1) — all shipped & working

> **Every feature listed in this PRD is implemented and operational.** Run tests with
> `cd backend && npm test` (10 pass) and see the live end-to-end checklist in §6.
> Nothing in this document is a mockup or placeholder — the folder-upload feature was
> verified live (upload → per-file findings → rescan diffing).

1. Scan code reliably and reproducibly (single file and project folder).
2. Give every finding a severity, a human explanation, and remediation guidance.
3. Verify fixes objectively via rescan comparison.
4. Keep data owner-isolated and the product safe to self-host.
5. Deliver a usable dark-theme SPA dashboard.

### 1.4 Out of scope (NOT built — listed for clarity, not shipped)

These are explicitly **not implemented** and should not be mistaken for working features:

- Real-time IDE integration / daemonized watching.
- Automated code fixing / write-back to repositories.
- Central SaaS hosting / billing / multi-tenant admin panel.
- Dependency / package-vulnerability (CVE) scanning.

---

## 2. Personas

| Persona | Goals | Pain points addressed |
|---|---|---|
| **Developer** | Find and fix issues in code they write | Clear remediation, secure examples, file-line attribution |
| **Security reviewer / auditor** | Review a repo before release | Folder-level scanning, deterministic scores, fast triage |
| **Engineering manager** | Confirm issues are fixed | Rescan diffing (resolved/remaining/new) over time |
---

## 3. User stories

1. As a developer, I can paste code and immediately see a risk score and findings.
2. As a developer, I can upload a single source file to have it scanned.
3. As a security reviewer, I can **select an entire project folder** and have every
   supported source file scanned, with each finding linked to its relative file path,
   so I can review a whole repo in one pass.
4. As a reviewer, I can see which file and line each finding came from and jump to
   the relevant code.
5. As a user, I can rescan after making fixes and see exactly what was resolved,
   what remains, and what is new.
6. As a user, I can download a JSON report of any scan, including a per-file breakdown
   for folder scans.
7. As an owner, I can create multiple projects and keep scans isolated to my account.

---

## 4. Functional Requirements

All requirements below are **implemented and working**, each tagged with its status.
Functional requirements are grouped by PRD section and referenced from code comments.

### §4 Auth & account — ✅ Working
- **FR-1** Email + password registration and login (JWT bearer tokens; `/auth/register`,
  `/auth/login`, `/auth/me`).
- **FR-2** Passwords hashed with bcrypt (never stored in plaintext).
- **FR-3** Ownership isolation: every query is scoped to the authenticated user
  (`owner: req.userId`); a user cannot read or mutate another user's data.

### §5 Projects — ✅ Working
- **FR-4** Create / list / update / delete projects (name + optional description).
- **FR-5** Projects are always owned by exactly one user.

### §6 Scans — single file — ✅ Working
- **FR-6** Create a scan from pasted code or an uploaded single file
  (`POST /scans`, `POST /scans/upload` with one file).
- **FR-7** The scanner normalizes the submitted file's language and validates input
  (size limits, extension whitelist).
- **FR-8** Output includes: severity counts, 0–100 score, findings, and optional AI
  enrichment for each finding.

### §9 Scans — project folder (multi-file) — ✅ Working [NEW in v1.2]
- **FR-9** A user can select a **project folder** (browser directory picker,
  `webkitdirectory`) and upload it in one request.
- **FR-10** Supported source files (extension whitelist) are uploaded; unsupported
  files are filtered out **client-side and server-side**.
- **FR-11** The backend normalizes each relative path (strips `..` traversal, leading
  slashes, backslashes, control chars) via `sanitizeRelativePath`.
- **FR-12** Upload constraints:
  - File count: **≤ 100 files** (backend rejects more).
  - Per-file size: **≤ 2 MB** (multer, memory storage).
  - Total code size: **≤ 5,000,000 characters**.
- **FR-13** The scanner runs every rule per file and merges findings; each finding
  carries its source `filePath`.
- **FR-14** The scan's `language` is reported as **`mixed`** and the folder is labeled
  from the first file's top-level directory (e.g. `myapp/`).
- **FR-15** Rescan comparison keys are **namespaced by file path**
  (e.g. `api/server.js:<key>`), so identical snippets in different files are tracked as
  distinct findings.
- **FR-16** The scan persists the uploaded files (`sourceFiles: [{path, content}]`) and
  exposes a `fileCount` on scan responses and listings.

### §7 Risk scoring — ✅ Working
- **FR-17** Reproducible 0–100 score derived deterministically from findings and severity
  weights (critical > high > medium > low > informational).
- **FR-18** The score is **independent of AI** — AI enriches, never decides the score.

### §8 AI enrichment (opt-in) — ✅ Working
- **FR-19** Pluggable provider layer: `none` (offline fallback), `openrouter` (cloud),
  or `ollama` (local).
- **FR-20** When enabled, each finding may receive explanation, impact, remediation,
  secure example, severity normalization, and confidence.
- **FR-21** If the AI is disabled or fails, findings fall back to **rule-authored
  enrichment** so the app works fully offline (`AI_PROVIDER=none`).

### §9 Rescan verification — ✅ Working
- **FR-22** Each completed scan is compared against the project's most recent previous
  completed scan.
- **FR-23** Findings are classified into **resolved / remaining / newly-introduced**
  using stable `comparisonKey`s, plus a score `delta`.
- **FR-24** Verification works for both single-file and folder scans.

### §10 Reports — ✅ Working
- **FR-25** Any scan can be downloaded as a structured JSON report.
- **FR-26** Folder scans' reports include a **per-file breakdown** (`fileCount` and the
  list of scanned file paths).
- **FR-27** Secrets found in code are **masked** upstream by the scanner — raw secret
  values are not echoed into reports.

### §11 Dashboard — ✅ Working
- **FR-28** A global dashboard aggregates metrics across all of the user's projects
  (trends, totals, recent activity).

### §12 API & validation — ✅ Working
- **FR-29** All input validated with Zod schemas (`validation.js`) before processing.
- **FR-30** Security headers (helmet), CORS, and rate limiting applied globally.

---

## 5. Non-functional requirements

- **Determinism**: identical input + configuration ⇒ identical findings and score.
- **Performance**: folder scans bounded by explicit size/file-count limits.
- **Security**: OWASP-minded — minimal endpoints, ownership checks, path sanitization,
  masked secrets, rate limiting, security headers.
- **Offline capability**: core scanning works with no AI dependency.
- **Testability**: scanner + rescan logic unit-testable without a database.
- **Portability**: Node 18+ (ESM) backend, MongoDB (Atlas), React/Vite SPA.

---

## 6. Acceptance criteria (folder upload — v1.2)

- [x] User can pick a folder; supported source files are listed with relative paths.
- [x] Folder-scan UX — live per-file read progress bar, in-list file search/filter.
- [x] Drag-and-drop a folder or file onto the Source Code card.
- [x] Findings list supports search, severity + status filters, keyboard navigation, and
  deep-linkable findings (`#finding=<key>`).
- [x] Folder upload passes ≤ 100 files, ≤ 2 MB each, ≤ 5M total chars.
- [x] Unsupported files are filtered out (client and server).
- [x] Path traversal (`../`, absolute, backslash) is neutralized.
- [x] Findings show the correct `filePath` and line.
- [x] `language` is `mixed`; `fileCount` is reported.
- [x] Rescan diffing treats identical snippets in different files as separate findings.
- [x] Reports include per-file breakdown.
- [x] Single-file (paste / upload) scanning still works (no regression).

---

## 7. Recent change log

| Version | Date | Change |
|---|---|---|
| 1.3 | 2026-09-01 | **Scan UX** — folder drag-and-drop (`webkitGetAsEntry`/`createReader` recursive walk), per-file read progress bar, in-list file search; findings search + severity/status filters, keyboard navigation, deep-linkable finding details. |
| 1.2 | 2026-09-01 | **Folder/project upload** — multi-file scanning, per-file finding attribution, namespaced comparison keys, path sanitization, file-count surfaces, per-file report breakdown. |
| 1.1 | — | Rescan verification (resolved/remaining/new), AI provider layer with offline fallback. |
| 1.0 | — | Initial product — auth, projects, single-file scan, scoring, reports, dashboard. |

---

## 8. Backlog (planned features — NOT built, not in scope)

These items are **future work** and are **not part of the currently-shipped feature set**.
They are listed for roadmap clarity only:

1. **Phase 7 — Hardening**: CSP tuning, deeper input sanitization audit.
2. **Phase 8 — Testing & docs**: integration tests for the upload endpoint, API docs
   (OpenAPI), production deployment config.
3. Dependency / CVE scanning.
4. Export to SARIF ("Static Analysis Results Interchange Format") for CI integration.
5. Team workspaces / shared projects with role-based access (multi-tenant).
 