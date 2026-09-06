// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-template"}
// Nested template literals: a template literal interpolates another template
// literal containing user input, which reaches the query sink.
const name = req.query.name;
const q = `SELECT * FROM users WHERE name='${`hello ${name}`}'`;
db.query(q);