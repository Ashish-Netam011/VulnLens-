// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: a fixed, hardcoded path passed to fs.readFile. There is no
// user-controlled source in the call, so no file-read rule fires and the file
// is clean. The engine must NOT flag it (boundary: constant path = TN).
const fs = require("fs");
fs.readFile("/static/data.txt", function (err, data) {});