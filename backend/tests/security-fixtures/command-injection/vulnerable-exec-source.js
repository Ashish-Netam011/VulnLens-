// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-78", "ruleId": "child-process"}
// Command injection: attacker-controlled input is concatenated into an
// exec() command string.
const cp = require("child_process");
cp.exec("ls " + req.query.dir);
