// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Malformed / incomplete JavaScript. The parser must not crash the scanner;
// with no parseable AST, there are no taint-analyzed findings and the file is
// treated as clean for detection purposes.
function incomplet(