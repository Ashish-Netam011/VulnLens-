// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-22", "ruleId": "unchecked-file-read"}
// Path traversal via a for-of loop whose body reads a user-controlled path.
// Before Phase 4D, ForOfStatement bodies were never walked by the taint
// analyzer — this fixture locks in the fix.
const fs = require("fs");
for (const p of req.query.files) {
  fs.readFile(req.query.path, () => {});
}