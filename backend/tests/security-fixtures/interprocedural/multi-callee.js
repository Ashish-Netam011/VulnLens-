// Structural fixture: multi-callee / ambiguous dynamic calls.

const handlers = {
  user: renderUser,
  admin: renderAdmin
};

function renderUser(u) {
  return u.name;
}
function renderAdmin(u) {
  return u.role;
}

function dispatch(type, data) {
  const fn = handlers[type]; // dynamic dispatch — unresolved
  return fn(data);
}

// Same method name on different objects (ambiguity).
function run() {
  serviceA.run();
  serviceB.run();
}
