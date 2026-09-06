// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: the multer upload config DOES declare `limits:`, so it is not
// "upload without size limits". Regression pin for the Phase 6C
// multer-no-limits rule fix.
const multer = require('multer');
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { files: 10, fileSize: 2 * 1024 * 1024 },
});