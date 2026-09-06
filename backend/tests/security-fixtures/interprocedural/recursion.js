// Structural fixture: recursion and recursion/cycle termination safety.

function factorial(n) {
  if (n <= 1) return 1;
  return n * factorial(n - 1);
}

function a() {
  return b();
}
function b() {
  return a();
}

function leaf() {
  return 42;
}
