// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-78", "ruleId": "child-process"}
// Command injection via an arrow function whose body concatenates user input
// into an exec() command. Before Phase 4D, arrow function bodies were not walked.
const cp = require("child_process");
const dir = req.query.dir;
const run = () => {
  cp.exec("ls " + dir);
};
run();