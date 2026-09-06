// @expects {"case": "tricky", "flagged": true, "verdict": "POTENTIAL", "cwe": "CWE-89"}
// Tricky: a SQL sink with concatenation, but the interpolated value has NO
// user-controlled source (it is an internal parameter). The shape is suspicious
// (should be reported POTENTIAL / LOW confidence), but it is NOT a confirmed
// critical SQL injection. This is the "88% fake critical" case the current
// engine over-claims on.
function getUserById(db, id) {
  return db.query("SELECT * FROM users WHERE id=" + id);
}
