// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: the path variable is derived from process state, not from a request
// source, so the Phase 7 request-taint pass must NOT report it (TN).
const fs = require("fs");
const p = process.env.CONFIG_DIR + "/app.json";
fs.readFileSync(p, "utf8", function (err, data) {});
