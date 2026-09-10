# VulnLens AI — Hackathon Demo Script

**Total time: ~4 minutes** (leave buffer for Q&A)

---

## 🎬 SCENE 1 — Title Card (0:00 – 0:05)

**On screen:** Slide 1 (HTML title card) or just the VulnLens logo.

**Say:**
> "This is VulnLens AI — a security scanner that decides, and an AI that explains."

---

## 🎯 SCENE 2 — The Problem (0:05 – 0:20)

**On screen:** Slide 2 (Problem) or your own talking-head.

**Say:**
> "Today's security scanners fall into two camps. Rule-based scanners are deterministic but noisy — they tell you *what* went wrong, but not *how* to fix it. AI-based scanners sound impressive, but they hallucinate findings. You can't trust either one to gate your CI pipeline.
>
> VulnLens fixes this by cleanly separating the two jobs."

---

## 💡 SCENE 3 — The Solution (0:20 – 0:40)

**On screen:** Slide 3 (Architecture diagram).

**Say:**
> "A deterministic rule engine scans your code and produces findings with evidence, severity, confidence, and an attack path. No LLM is ever consulted to decide if something is a vulnerability.
>
> The AI copilot works *after* detection — it explains the finding, shows the impact, and suggests a fix with secure code. It can never add, remove, or hide a finding.
>
> This makes VulnLens suitable as a CI security gate."

---

## 🔍 SCENE 4 — Live Demo: Scan (0:40 – 1:40)

**On screen:** Browser with the VulnLens frontend.

### Steps:
1. **Register/Login** (5s) — Show the login screen, register a quick account.
2. **Create Project** (5s) — Click "New Project", name it (e.g. "Demo App").
3. **New Scan** (10s) — Click "New Scan", upload the `backend/tests/security-fixtures` folder (or drag a few vulnerable files).
4. **Scan running** (10s) — Show the scan progress (real per-file counts, no fake progress).
5. **Scan results** (30s) — Show the scan summary: severity counts, 0–100 score, per-file results. Point out:
   > "Every finding has a rule, severity, confidence, verdict, file path, and line number — all deterministic, all reproducible."

### Tips:
- Use a mix of files: SQL injection, hardcoded secrets, XSS, weak crypto.
- If the upload is slow, have the files pre-staged and just show the results page.

---

## 📋 SCENE 5 — Findings Detail (1:40 – 2:10)

**On screen:** Findings page → click into a SQL injection finding.

**Say:**
> "Let's look at a real finding. SQL injection — CWE-89. The scanner detected user input flowing into a database query without parameterization. Here's the evidence: the exact rule that matched, the severity, and the code region."

### Steps:
1. Show the findings list with filters (severity, rule, search).
2. Click into a finding — show verdict header, severity badge, evidence.
3. Show the **Source Context** panel — the highlighted code region.
4. Say: *"The source viewer pulls from the scan's own stored sources — no filesystem access needed."*

---

## 🔀 SCENE 6 — Data Flow (2:10 – 2:35)

**On screen:** Finding Detail → Data Flow tab (or the Data Flow page).

**Say:**
> "For tainted findings, VulnLens traces the attack path — source to sink. Here we see user-controlled input flowing through variable aliases into a dangerous database query. This is the exact path an attacker would exploit."

### Steps:
1. Show the data flow graph: `SOURCE → propagation → SINK`.
2. Point out the arrow visualization.
3. Say: *"This is targeted taint analysis — not a grep match, but a real data-flow trace."*

---

## 🤖 SCENE 7 — AI Copilot (2:35 – 3:00)

**On screen:** Finding Detail → AI Copilot panel.

**Say:**
> "Now let's ask the AI copilot to explain this. It gets the finding, the evidence, and the data flow — and returns a structured explanation."

### Steps:
1. Click "Explain with Copilot".
2. Show the result: what the vulnerability is, why it matters, exploit scenario, and a secure code fix.
3. Say: *"Notice: the AI never re-judges the finding. It only explains and advises. The scanner is still the source of truth."*

### If AI is offline (AI_PROVIDER=none):
> "And when AI is disabled — it falls back to rule-authored explanations. The app works fully offline."

---

## 🔄 SCENE 8 — Rescan & Fix (3:00 – 3:20)

**On screen:** Terminal (CLI) or browser.

**Say:**
> "Let's fix it and verify."

### Steps:
1. Fix the vulnerable code (parameterize the query).
2. Rescan the same project.
3. Show the comparison: the finding moved from "NEW" to "RESOLVED".
4. Say: *"Stable comparison keys mean the scanner knows when a fix is real — not just moved code."*

---

## 🖥️ SCENE 9 — CLI & CI (3:20 – 3:40)

**On screen:** Terminal.

**Say:**
> "The same scanner runs in CI."

### Steps:
1. Run:
   ```bash
   cd backend
   node bin/vulnlens.js scan ../README.md --format table
   ```
2. Show the table output with findings.
3. Run with SARIF:
   ```bash
   node bin/vulnlens.js scan ../README.md --format sarif --output demo.sarif
   ```
4. Say: *"SARIF 2.1.0 — compatible with GitHub Code Scanning. And the CI gate fails on new HIGH findings while baselined findings stay visible."*

---

## 🏁 SCENE 10 — Closing Stats (3:40 – 4:00)

**On screen:** Slide 4 (Closing) or back to the VulnLens dashboard.

**Say:**
> "VulnLens: 8 vulnerability families, deterministic scoring, source-to-sink data flow, AI copilot for remediation, baseline-aware CI regression, SARIF export, and 616 passing tests — all self-scanning in CI. The scanner decides. AI explains. Thank you."

---

## 📋 Quick Reference — What to Have Ready

| Item | Where |
|------|-------|
| `backend/tests/security-fixtures/` | Sample vulnerable code folder for upload |
| A fixed version of `vulnerable-direct.js` | For the rescan demo (parameterized query) |
| Dev servers running | `cd backend && npm run dev` + `cd frontend && npm run dev` |
| MongoDB connection | `.env` with working `MONGODB_URI` |
| Browser open to `localhost:3000` | Frontend ready |
| Terminal open | For CLI demo |

## 🎙️ Recording Tips

- **Tool:** OBS (free), QuickTime (Mac), or Loom (quick & shareable)
- **Resolution:** 1920×1080 or match your screen
- **Font size:** Bump terminal/editor font to 16–18pt so it's readable at 720p
- **Browser zoom:** 110–120% in Chrome so UI elements are visible
- **One take:** Do a dry run first, then record in one pass — cuts are hard to edit
- **Narrate confidently:** Don't narrate every click. Explain *why* things matter.
- **Keep transitions tight:** No dead air between scenes. Practice the handoffs.
