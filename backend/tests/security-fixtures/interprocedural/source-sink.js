// Structural fixture: source (user input) and sink (data-flow capability) in
// interprocedural setting. NOT a vulnerability claim — just structural metadata.

function getUser(id) {
  const q = "SELECT * FROM users WHERE id=" + id;
  return db.query(q);
}

function controller() {
  const id = req.query.id;
  return getUser(id);
}

function render() {
  const html = req.params.html;
  document.getElementById('app').innerHTML = html;
}
