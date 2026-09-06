// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-22", "ruleId": "unchecked-file-read"}
// Path traversal / arbitrary file read: attacker-controlled path reaches fs.
const fs = require("fs");
fs.readFile(req.query.path, function (err, data) {});
