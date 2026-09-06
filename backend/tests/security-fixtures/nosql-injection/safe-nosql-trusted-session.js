// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: the filter derives from authenticated session identity (req.user is
// deliberately NOT an attacker-controlled source in VulnLens's model), so no
// request source reaches the query (TN).
const User = require("./user");
User.findOne({ _id: req.user.id }, function (err, doc) {});
