// Structural fixture: destructuring, defaults, rest, optional chaining.

function normalize({ name, age = 0 }) {
  return { name: name || '', age };
}

function sum(...nums) {
  let total = 0;
  for (const n of nums) total += n;
  return total;
}

function maybeCall(fn) {
  return fn?.();
}

function handle(req, res) {
  const id = normalize(req.query).id;
  res.send(id);
}
