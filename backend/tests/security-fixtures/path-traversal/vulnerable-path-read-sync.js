// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-22", "ruleId": "unchecked-file-read"}
// Path traversal via fs.readFileSync with a request-derived alias. The sync
// variant plus the variable indirection are invisible to the inline-request
// regex rule; the Phase 7 request-taint pass must confirm the flow.
const fs = require("fs");
const target = req.query.path;
fs.readFileSync(target, "utf8", function (err, data) {});
