// Structural fixture: control-flow branch calls and loops.

function processUser(user, users) {
  if (user.active) {
    return sendEmail(user);
  } else {
    return logUser(user);
  }
}

function scanAll(items) {
  const results = [];
  for (const item of items) {
    results.push(scan(item));
  }
  return results;
}

function choose(a, b, cond) {
  return cond ? a() : b();
}
