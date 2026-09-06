// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Shadowed-variable adversarial case. The outer `id` is user-controlled, and
// the nested function also declares a parameter named `id`.
//
// KNOWN Phase 4D limitation: the taint analyzer shares one env across nested
// function bodies (intra-function), so it CANNOT reason about shadowing. The
// outer tainted `id` bleeds into the nested function, and the analyzer
// conservatively confirms the flow. This is the safe direction (errs toward
// flagging) and is documented here rather than being silently hidden.
const id = req.query.id;
function getUser(id) {
  db.query("SELECT * FROM users WHERE id=" + id);
}
getUser(id);