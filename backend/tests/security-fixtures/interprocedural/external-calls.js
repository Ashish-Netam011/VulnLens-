// Structural fixture: external / unresolved calls.
// Sink-capable calls to libraries we cannot resolve intra-file.

function load() {
  const cp = require('child_process');
  cp.exec('echo hi');
}

function read() {
  return fs.readFileSync('/tmp/file.txt');
}

function render() {
  document.write('hello');
}
