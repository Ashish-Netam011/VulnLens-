/**
 * Rule-authored enrichment used as a deterministic fallback when no AI
 * provider is available or reachable. Keeps the app fully functional and
 * builds clear, structured explanations without an LLM.
 */
const RULE_RICH_DATA = {
  'Injection Vulnerabilities': {
    explanation:
      "User-controlled data is being combined with a command or query string rather than passed through a safe, parameterized interface. An attacker can break out of the expected syntax and change what the query or command does.",
    impact:
      "An attacker who controls part of the query/command can read, modify, or delete data they should not have access to, achieve privilege escalation, or in severe cases execute arbitrary code on the database or host.",
    remediation:
      "Use parameterized queries or prepared statements exclusively, and never build query strings by string concatenation or template interpolation. Validate and allow-list inputs as a second layer of defense.",
    secureExample:
      '// Instead of: const q = "SELECT * FROM users WHERE id=" + req.query.id;\n// Use a parameterized query:\ndb.query("SELECT * FROM users WHERE id = ?", [req.query.id]);',
  },
  'Cross-Site Scripting (XSS)': {
    explanation:
      "Application content is written into the browser DOM or an HTML response without escaping. If the value includes user input, an attacker can inject script that other users' browsers will execute.",
    impact:
      "Stored or reflected XSS lets an attacker steal session cookies, impersonate users, perform actions on their behalf, or deface the page.",
    remediation:
      "Never assign raw user input to innerHTML/dangerouslySetInnerHTML or similar sinks. Escape output at the point of use, use safe DOM-construction APIs, and apply a Content-Security-Policy.",
    secureExample:
      '// Instead of: el.innerHTML = userInput;\n// Use textContent (or escape before inserting HTML):\nel.textContent = userInput;',
  },
};
export default RULE_RICH_DATA;
