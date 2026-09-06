// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-943", "ruleId": "nosql-object-query"}
// NoSQL injection: a request value reaches a MongoDB-style document query
// through an object literal. With Express extended query parsing the value can
// carry MongoDB operator keys, so this is a genuine injection surface.
const User = require("./user");
User.find({ name: req.query.name }, function (err, docs) {});
