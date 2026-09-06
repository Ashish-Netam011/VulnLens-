// Structural fixture: function declarations and calls (not a vulnerability).
// Tests that extractFunctions finds named functions and extractCalls finds call sites.

function findUser(id) {
  return db.users.find({ id });
}

function formatResult(user) {
  return user.name;
}

function handleRequest(id) {
  const user = findUser(id);
  return formatResult(user);
}
