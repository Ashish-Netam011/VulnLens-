// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: a constant filter object with no request-derived values. The Phase 7
// object-query pass only fires on request-tainted arguments (TN).
const User = require("./user");
User.find({ status: "active" }, function (err, docs) {});
