// @expects {"case": "safe", "flagged": true, "verdict": "POTENTIAL", "cwe": "CWE-78"}
// The exec call has no user-controlled source (fixed command string), so it
// cannot be confirmed as command injection. Reported as a low-severity
// POTENTIAL lead because the dangerous sink shape is present.
const cp = require("child_process");
cp.exec("ls");