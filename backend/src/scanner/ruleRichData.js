import RULE_RICH_DATA from './richDataBase.js';

const RULE_RICH_DATA_EXTRA = {
  'Hardcoded Credentials and Secrets': {
    explanation:
      "A credential or secret value appears directly in the source code rather than being loaded from the environment or a secrets manager.",
    impact:
      "Anyone with access to the repository or a deployed bundle can read the secret and use it to access the protected systems, logs, databases, or third-party services.",
    remediation:
      "Move secrets to environment variables or a dedicated secret-management service, rotate the exposed value immediately, and keep secrets out of version control.",
    secureExample:
      '// Instead of: const key = "sk-1234567890";\n// Read from the environment:\nconst key = process.env.API_KEY;',
  },
  'Dangerous Function Usage': {
    explanation:
      "The code invokes dynamic-execution or resource-access APIs (eval, child_process, deserialization, path traversal) using values that may be derived from user input.",
    impact:
      "Uncontrolled input reaching these sinks can lead to remote code execution, arbitrary command execution, data exfiltration, or unauthenticated file access.",
    remediation:
      "Avoid eval and dynamic code execution. Use safe parsers, allow-list permissible paths/commands, validate and sanitize input, and sandbox operations where possible.",
    secureExample:
      '// Instead of: eval(userExpression);\n// Use a constrained, safe parser / allow-list of known options.',
  },
  'Sensitive Information Exposure': {
    explanation:
      "Sensitive data such as credentials, tokens, or internal objects may be written to logs or returned to clients.",
    impact:
      "Exposed secrets or internal state can be leveraged by attackers for unauthorized access or reconnaissance, and may violate compliance requirements.",
    remediation:
      "Redact secrets in logs, return only the minimal fields needed, and never log authorization headers or tokens.",
    secureExample:
      '// Instead of: console.log("token:", token);\n// Log only non-sensitive metadata:\nlogger.info({ userId, action: "login" });',
  },
  'Weak Cryptographic Practices': {
    explanation:
      "A deprecated or weak cryptographic algorithm (MD5, SHA-1, DES, RC4, ECB) is used for a security-sensitive operation.",
    impact:
      "Broken cryptography can be reversed or attacked by modern hardware/techniques, undermining confidentiality, integrity, and password storage.",
    remediation:
      "Use modern algorithms (e.g., SHA-256/384, AES-GCM, bcrypt/argon2 for passwords) with appropriate key sizes and secure modes.",
    secureExample:
      '// Instead of: crypto.createHash("md5")\n// Use a strong, purpose-appropriate algorithm:\ncrypto.scrypt(password, salt, 64) // or bcrypt for password hashing',
  },
  'Security Misconfiguration': {
    explanation:
      "A security-related setting is configured permissively or exposes debug/internal details.",
    impact:
      "Misconfigurations such as wildcard CORS or enabled debug mode can allow cross-origin data access or reveal sensitive implementation details.",
    remediation:
      "Restrict CORS to trusted origins, disable debug/stack traces in production, and apply security-header middleware.",
    secureExample:
      '// Instead of: res.set("Access-Control-Allow-Origin", "*");\n// Restrict to trusted origins:\nres.set("Access-Control-Allow-Origin", "https://app.example.com");',
  },
  'Insecure File Handling': {
    explanation:
      "File read/write operations use paths or content that may derive from user input without validation.",
    impact:
      "Attackers may be able to read arbitrary server files (path traversal) or write to unintended locations, leading to data disclosure or code execution.",
    remediation:
      "Validate and normalize all paths, reject traversal sequences (../), restrict file operations to a safe directory, and enforce upload size/type limits.",
    secureExample:
      '// Validate and resolve the path, then ensure it stays within a base directory:\nconst resolved = path.resolve(baseDir, fileName);\nif (!resolved.startsWith(baseDir)) throw new Error("Invalid path");',
  },
};

export default Object.assign({}, RULE_RICH_DATA, RULE_RICH_DATA_EXTRA);
