// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: a hardcoded SQL literal with no concatenation or interpolation. There
// is no injection surface. The engine must NOT flag this.
db.query("SELECT 1");