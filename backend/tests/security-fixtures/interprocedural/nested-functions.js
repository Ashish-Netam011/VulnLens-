// Structural fixture: nested functions and callback patterns.

function outer(list) {
  function inner(x) {
    return transform(x);
  }

  return list.map(function (item) {
    return inner(item);
  });
}

module.exports = {
  outer
};
