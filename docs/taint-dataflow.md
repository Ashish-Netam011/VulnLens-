# Phase 7 — Targeted Data-Flow Analysis

VulnLens's scanner has shipped a deterministic source→sink analysis layer since
Phases 4C/5A–5E (request-source recognition, intra-function taint, sanitizer +
parameterization model, flow-path evidence, calibration). Phase 7 closes three
specific gaps that the earlier layers could not express, all layered on the
same engine — no parallel analyzer, no new dependencies, no network, and no
change to the verdict model.

## What Phase 7 adds

| Flow family | New detection | Rule ID(s) |
|---|---|---|
| File read with request-derived path via alias / `*Sync` | `fs.readFile`, `fs.readFileSync`, and `fs.writeFile`, `fs.writeFileSync`, `fs.appendFile`, `fs.appendFileSync` whose **path argument** is request-tainted through variable aliases, destructuring, or multi-hop assignments | `unchecked-file-read`, `file-write-user` (existing IDs) |
| NoSQL / MongoDB document-query injection | request-tainted object literals, aliases, or whole-request values passed to `Model.find/findOne/where/…` or `db.<collection>.<op>` | `nosql-object-query` (new) |

## Supported request sources (unchanged from the AST model)

`req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, `req.files`,
`req.get(...)` / `req.header(...)`, `process.argv[n]`, `document.cookie` /
`document.URL` / `document.referrer`, `location.search/hash/href/pathname`,
`new URLSearchParams(...).get(...)`.

Trusted request metadata (`req.user`, `req.session`) is deliberately **not** an
attacker-controlled source.

## Example vulnerable flows (both detected as CONFIRMED)

```js
// File read — alias + sync variant
const fs = require('fs');
const p = req.query.path;
fs.readFileSync(p, 'utf8', cb);            // unchecked-file-read, CONFIRMED

// NoSQL — object query built from request data
const User = require('./user');
User.find({ name: req.query.name }, cb);   // nosql-object-query, CONFIRMED

// NoSQL — whole request body as the query
Item.find(req.body, cb);                   // nosql-object-query, CONFIRMED
```

## Example safe flows (never reported)

```js
fs.readFileSync('/opt/config/app.json', 'utf8');   // constant path
const p = process.env.CONFIG_DIR + '/app.json';    // unrelated variable
fs.readFileSync(p, 'utf8');

db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);  // parameterized

User.findById(req.params.id, cb);   // ObjectId scalar — cannot carry operators
User.find({ status: 'active' }, cb);  // constant filter
User.findOne({ _id: req.user.id }, cb);  // trusted session identity
```

## Sanitizer model

Sanitization is conservative and explicit (unchanged from Phase 4C): a value is
"sanitized" only when it passes through a recognized sanitizer
(`escapeHtml`, `sanitize`, `DOMPurify`, `encodeURIComponent`, `xss`,
`stripTags`, `sanitizeHtml`, …) **before** reaching the sink. A sanitized
value is never reported CONFIRMED — at most a low-severity POTENTIAL lead
(the rule fires, the evidence engine demotes it). Arbitrary functions named
`sanitize`/`clean`/`safe` are not trusted by name alone; only the explicit list
is recognized.

## False-positive philosophy

- Detection triggers only when the AST taint analysis can prove the sink
  argument is request-derived (constants, literals, and unrelated variables
  never trigger).
- Findings already covered by the existing inline-request regex rules are not
  duplicated.
- Verdicts remain CONFIRMED / POTENTIAL / FALSE_POSITIVE with severity derived
  from the verdict — the new detections never inflate severity or confidence.
- The `findById`-style id-lookup family is excluded from the NoSQL sink set
  because an ObjectId scalar cannot carry MongoDB operator keys.

## Known limitations (documented, deliberate)

- **Intra-function only for verdicts.** Request data that crosses a function
  boundary (argument → parameter → sink) is not verdict-CONFIRMED; such flows
  surface as existing low-severity leads plus structural metadata from
  Phases 5A–5C. A cross-function verdict upgrade is deliberately out of scope.
- **Statement-root sinks.** The taint walker collects sinks only from
  expression-statement call expressions; chained forms such as
  `fs.createReadStream(p).pipe(res)` or `db.users.find({...}).toArray()` are
  not collected (and therefore not confirmed).
- **Bare `exec(input)`.** An identifier callee without a member receiver (for
  example a destructured `const { exec } = require('child_process')`) is not
  treated as a command sink, which avoids false positives on
  `RegExp.prototype.exec`. Member-form calls
  (`child_process.execSync(...)`, `require('child_process').exec(...)`) are
  confirmed normally.
- **`eval`** remains statically flagged (any use reported at high severity),
  per the existing dangerous-function convention, rather than data-flow gated.
- **No alias/pointer analysis, no cross-file analysis, no TypeScript.** The
  analysis is bounded, deterministic local AST taint only.

## Reviewing findings

Every data-flow finding carries the standard evidence object (`source.names`,
`flow.established`, `sink.type`, explanation) so a reviewer can see the
`req.query.x → alias → sink` chain before deciding whether the flow is truly
exploitable. When in doubt, run a targeted scan with
`--format json` and inspect `evidence.flow.sources`.
