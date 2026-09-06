# AI Security Copilot (Phase 8)

The VulnLens AI Security Copilot turns **one deterministic VulnLens finding**
into a structured, actionable security explanation: what the vulnerability is,
why it matters, how it could be exploited, and how to fix it — including a
secure code example.

It is **not** an AI vulnerability detector. The deterministic scanner decides
what is vulnerable. The Copilot only explains and remediates.

---

## Deterministic scanner vs. AI — responsibilities

| Concern | Owner | Notes |
|---|---|---|
| Vulnerability verdict | Deterministic scanner | Never the AI |
| Severity / confidence / risk | Deterministic scanner | Never modified by AI |
| Rule ID, evidence, `comparisonKey` | Deterministic scanner | Immutable through the AI layer |
| Baseline classification (NEW / BASELINED / RESOLVED) | Deterministic pipeline | AI never touches it |
| CI gate / exit codes / SARIF | Deterministic pipeline | AI never participates |
| Explanation / impact / remediation | AI Copilot | Presentation only |

The AI can never:
- create a finding ("AI says vulnerable → finding"),
- suppress a finding ("AI says safe → drop it"),
- modify severity, confidence, rule ID, evidence, `comparisonKey`,
  `baselineStatus`, or `baselineEscalated`,
- influence the `--fail-on` gate or any exit code.

## Supported providers

No new provider abstraction was introduced. The Copilot reuses the existing
provider facade (`backend/src/ai/provider.js`) and both existing providers:

- **OpenRouter** (`AI_PROVIDER=openrouter`, `OPENROUTER_API_KEY`,
  `OPENROUTER_MODEL`)
- **Ollama** (local, `AI_PROVIDER=ollama`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`)

Providers accept an optional per-call `prompts` override; when absent the
default enrichment prompts are used, so existing scanService behavior is
unchanged. API keys stay server-side only and are never part of the model
prompt.

## Configuration

```bash
# Cloud (OpenRouter)
AI_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-...
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet   # or any OpenRouter model id

# Local (Ollama)
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
```

`AI_PROVIDER=none` (default) disables the Copilot; requests degrade to
`success:false, source:'unavailable'` without errors.

## Input contract (what the AI receives)

The Copilot builds a compact prompt from the finding:

- rule ID, deterministic severity and confidence
- finding message (`reason`), affected code
- file name, line number, `comparisonKey`
- a **bounded source context** window: ±4 lines around the finding's line,
  hard-capped at 2,000 characters (never the whole file, never the
  repository, never `node_modules`, `.env`, credentials, or unrelated files)
- a compact **data-flow summary** derived from deterministic evidence when
  present, e.g. `req.query.id → db.query()` (Phase 4C flow + Phase 7 sources,
  including `parameterized`/`sanitized`/`template-only` flags)

## Output contract (what the AI must return)

```json
{
  "findings": [
    {
      "comparisonKey": "<echoed input key>",
      "explanation": "why the finding exists",
      "impact": "what damage or risk this allows",
      "attackScenario": "concise exploitation sketch",
      "remediation": "concrete fix steps",
      "secureExample": "safer code",
      "confidence": "high|medium|low"
    }
  ]
}
```

Validation rules:

- `explanation` and `remediation` are required; anything else is discarded.
- Fields are length-capped (1,400 chars each) and trimmed.
- Invalid confidence values default to `low`.
- Responses are parsed tolerantly (markdown fences / surrounding text) but any
  parse or validation failure degrades to `success:false` with a safe
  fallback — never a crash.

## API

```
POST /api/ai/explain        (auth-protected, like all routes)
Content-Type: application/json

{
  "finding": { "ruleId": "...", "severity": "high", "confidence": 0.9,
               "filePath": "app.js", "line": 10, "reason": "...",
               "affectedCode": "...", "comparisonKey": "...",
               "evidence": { ... } },
  "code": "<optional bounded source context source>",
  "fileName": "app.js"
}

200 OK
{ "success": true, "copilot": { "explanation": "...", "impact": "...",
  "attackScenario": "...", "remediation": "...", "secureExample": "...",
  "confidence": "high" }, "source": "openrouter" }
```

When AI is unavailable or fails, the response is still HTTP 200 with
`success:false` and `copilot:null` — the caller's finding is untouched.

## CLI

```bash
vulnlens scan ./src --explain
```

`--explain` is strictly **opt-in**. Normal scans (`vulnlens scan .`) remain
deterministic, offline, and AI-free. With `--explain`:

- up to 10 findings are explained, highest severity first;
- `copilot` fields are added to table and JSON output;
- SARIF output is untouched (the SARIF 2.1.0 contract never carries AI text);
- findings, baseline classification, the security gate, and exit codes are
  never changed by AI success or failure;
- with no provider configured, a single stderr note is printed and the scan
  proceeds exactly as a normal scan.

## Security guardrails

- **Scanned code is untrusted data.** The Copilot system prompt instructs the
  model that source code and evidence are data, not instructions; to ignore
  any embedded instructions/role-play; to never reveal system prompts, API
  keys, or environment variables; to never invent evidence; and to only
  explain the supplied deterministic finding.
- **Prompt injection** cannot change the output contract: responses are
  schema-validated and only the six contract keys survive.
- **Secret safety**: API keys travel only in provider HTTP headers; env
  configuration and `.env` content are never serialized into prompts.
- **Bounded context**: ±4 lines / ≤2,000 chars of source per finding, and at
  most 10 findings per `--explain` run. One request per finding, never one
  per file or per repository.
- **No target-code execution**: the scanner and Copilot only read text; they
  never execute scanned application code (`eval` is never used on target
  source).
- **Finding integrity**: the Copilot receives a normalized copy of the finding
  and never mutates the caller's object.

## Failure behavior

| Failure | Behavior |
|---|---|
| No provider configured | `success:false`, `source:'unavailable'`; CLI prints one note |
| Network error / timeout / rate limit | `success:false` with error; retries per provider config |
| Malformed AI response | `success:false`, `copilot:null` — safe fallback |
| Oversized input | Context is truncated before the provider call |

The deterministic scan, findings, SARIF, baseline classification, and CI gate
are identical whether AI is present, absent, or failing.

## Limitations

- Explanations are only as good as the model; the deterministic verdict and
  the AI explanation may occasionally disagree — the verdict always wins.
- `confidence` inside `copilot` is the model's self-assessment of its
  explanation quality, not a vulnerability-confidence value (the finding's
  own deterministic confidence remains authoritative).
- Data-flow summaries depend on deterministic evidence; findings without flow
  evidence prompt the model to say so explicitly rather than guess.
- Live model output varies by provider/model; the output contract is enforced
  by validation, not by the model.