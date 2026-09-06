// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: SHA-256 is a strong algorithm and must not be flagged.
crypto.createHash("sha256").update(data).digest("hex");
