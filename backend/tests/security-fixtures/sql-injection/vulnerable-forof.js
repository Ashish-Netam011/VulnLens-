// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// For-of loop with user-controlled iterable. Before Phase 4D, ForOfStatement
// was not handled — this fixture locks in the fix.
const items = req.query.items;
for (const item of items) {
  db.query("SELECT * FROM users WHERE id=" + item);
}