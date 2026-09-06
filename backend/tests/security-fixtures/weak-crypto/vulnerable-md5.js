// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-327", "ruleId": "md5"}
// Weak/broken cryptography: MD5 is used for a security-sensitive digest.
crypto.createHash("md5").update(data).digest("hex");
