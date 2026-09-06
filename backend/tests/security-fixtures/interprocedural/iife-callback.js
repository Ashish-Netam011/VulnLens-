// Structural fixture: IIFE, callbacks, and function-passing patterns.

(function () {
  console.log('boot');
})();

const timer = setTimeout(function tick() {
  console.log('tick');
}, 100);

function highOrder(fn, value) {
  return fn(value);
}

highOrder(function (v) {
  return v + 1;
}, 2);
