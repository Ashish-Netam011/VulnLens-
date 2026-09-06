// @expects {"case": "tricky", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// False positive: innerHTML is assigned a constant string with no user input.
// There is no taint, so a correct engine reports nothing. The current regex
// engine flags this as HIGH-confidence XSS — that is exactly the noise this
// corpus is designed to measure and calibrate away.
el.innerHTML = "<b>Static header</b>";
