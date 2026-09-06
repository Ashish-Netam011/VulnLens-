// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: executing a RegExp against a string is NOT child process execution.
// Regression pin for the Phase 6C child-process rule fix (bare `.exec(` no
// longer matches RegExp.prototype.exec / Mongoose Query#exec).
const re = /^[a-z]+$/;
const result = re.exec(text);