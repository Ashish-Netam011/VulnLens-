// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: a parameterized / prepared query. The engine must NOT flag this even
// though the input is user-controlled, because it never reaches a SQL sink
// through string concatenation or template interpolation.
db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
