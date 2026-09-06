// Structural fixture: a function that calls a function containing a structural
// sink. Tests Phase 5B correlation for reachable sink paths (A → B → C).
// NOT a vulnerability claim — just structural metadata.

function executeQuery(q) {
  const stmt = "SELECT * FROM t WHERE id=" + q;
  return db.query(stmt);
}

function processData(data) {
  return executeQuery(data);
}

function handler() {
  const input = req.query.id;
  return processData(input);
}
