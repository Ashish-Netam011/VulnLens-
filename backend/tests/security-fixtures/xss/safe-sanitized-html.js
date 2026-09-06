// @expects {"case": "safe", "flagged": true, "verdict": "POTENTIAL", "cwe": "CWE-79"}
// Safe-ish: user-controlled input is HTML-escaped before being written via
// innerHTML, so it is not exploitable. The rule fires (innerHTML present) but
// the evidence engine recognizes the sanitizer and reports POTENTIAL / low.
el.innerHTML = escapeHtml(req.query.q);