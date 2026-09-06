// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-79", "ruleId": "innerhtml"}
// XSS via an arrow function writing user input to innerHTML. Before Phase 4D,
// arrow function bodies were never walked — this fixture locks in the fix.
const id = req.query.q;
const render = () => {
  el.innerHTML = id;
};
render();