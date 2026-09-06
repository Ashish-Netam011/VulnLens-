// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-79", "ruleId": "innerhtml"}
// Nested arrow function: an outer arrow defines a render helper that writes
// user input to innerHTML. Recursive nested-function walking must find it.
const q = req.query.q;
const setup = () => {
  const render = () => {
    document.getElementById("app").innerHTML = q;
  };
  render();
};
setup();