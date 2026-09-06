// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-943", "ruleId": "nosql-object-query"}
// NoSQL injection: a MongoDB operator object is built from request data and
// placed in a document query. The operator keys are dynamic (parser-injected),
// so the inline `nosql-operator` regex (quoted $gt next to req.) cannot see it.
const User = require("./user");
User.find({ age: { $gt: req.query.minAge } }, function (err, docs) {});
