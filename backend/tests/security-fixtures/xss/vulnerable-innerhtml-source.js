// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-79", "ruleId": "innerhtml"}
// Stored/reflected XSS: user-controlled input is written into the DOM via
// innerHTML with no escaping.
el.innerHTML = req.query.q;
