// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-22", "ruleId": "file-write-user"}
// Unvalidated write: a request-derived path reaches fs.writeFileSync through an
// alias. The regex rule only sees inline `req.` inside fs.writeFile(, so the
// sync + indirection shape needs the Phase 7 request-taint pass.
const fs = require("fs");
const destination = req.query.file;
fs.writeFileSync(destination, "attacker-controlled-content");
