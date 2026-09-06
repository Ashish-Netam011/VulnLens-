// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-943", "ruleId": "nosql-object-query"}
// NoSQL injection: the whole request body is passed directly as the document
// query, giving the attacker full control over the filter object.
const Item = require("./item");
Item.find(req.body, function (err, docs) {});
