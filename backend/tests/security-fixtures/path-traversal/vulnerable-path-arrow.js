// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-22", "ruleId": "unchecked-file-read"}
// Path traversal via an arrow function whose body reads a user-controlled
// path. Before Phase 4D, arrow function bodies were never walked by the taint
// analyzer (only the rule layer saw the inline req source).
const fs = require("fs");
const read = () => {
  fs.readFile(req.query.path, () => {});
};
read();