// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: findById takes an ObjectId scalar that cannot carry MongoDB operator
// keys, so the id-lookup family is deliberately outside the object-query sink
// set (TN).
const User = require("./user");
User.findById(req.params.id, function (err, doc) {});
