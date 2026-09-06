// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: a fixed hardcoded path passed to fs.readFileSync. No request source
// exists, so no finding may be produced (constant path = TN).
const fs = require("fs");
fs.readFileSync("/opt/config/app.json", "utf8", function (err, data) {});
