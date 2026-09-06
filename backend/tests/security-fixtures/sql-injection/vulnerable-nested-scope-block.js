// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Nested block scope with a shared env: taint defined in an outer block remains
// visible inside an inner block. Intra-function scope must flow through blocks.
const id = req.query.id;
{
  const q = "SELECT * FROM users WHERE id=" + id;
  db.query(q);
}