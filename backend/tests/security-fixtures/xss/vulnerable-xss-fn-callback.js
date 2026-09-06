// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-79", "ruleId": "innerhtml"}
// XSS via a function expression callback writing user input to innerHTML.
// Before Phase 4D, function expression bodies were never walked.
const q = req.query.q;
document.addEventListener("DOMContentLoaded", function () {
  document.getElementById("app").innerHTML = q;
});