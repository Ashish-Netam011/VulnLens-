// Structural fixture: shadowing and parameter/name collision handling.
// `findUser` param vs the outer function named findUser — conservative handling.

function findUser(id) {
  return db.users.find({ id });
}

function wrapper(findUser) {
  // This findUser is the parameter (shadowed), NOT the outer function.
  return findUser(1);
}

function shadowed() {
  const value = 'not a function call';
  return value;
}
