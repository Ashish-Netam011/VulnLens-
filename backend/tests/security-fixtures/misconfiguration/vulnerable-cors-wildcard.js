// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-942", "ruleId": "cors-wildcard"}
// Permissive CORS: wildcard origin allows any site to make cross-origin requests.
app.use(cors({ origin: "*" }));
