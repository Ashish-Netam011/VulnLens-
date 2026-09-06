// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: textContent does not interpret HTML, so user input here is not XSS.
el.textContent = req.query.q;
