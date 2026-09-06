import hardcodedSecretsRule from './rules/hardcodedSecrets.js';
import sqlInjectionRule from './rules/sqlInjection.js';
import xssRule from './rules/xss.js';
import dangerousFunctionsRule from './rules/dangerousFunctions.js';
import weakCryptoRule from './rules/weakCrypto.js';
import misconfigurationRule from './rules/misconfiguration.js';
import sensitiveDataRule from './rules/sensitiveData.js';
import fileHandlingRule from './rules/fileHandling.js';

/**
 * Registry of all scanning rules. Each rule is a pure function:
 *   check(code) => Finding[]
 * Rules are deliberately modular and independently testable.
 */
export const rules = [
  { id: 'hardcoded-secrets', name: 'Hardcoded Secrets', check: hardcodedSecretsRule },
  { id: 'sql-injection', name: 'SQL/NoSQL Injection', check: sqlInjectionRule },
  { id: 'cross-site-scripting', name: 'Cross-Site Scripting', check: xssRule },
  { id: 'dangerous-functions', name: 'Dangerous Functions', check: dangerousFunctionsRule },
  { id: 'weak-crypto', name: 'Weak Cryptography', check: weakCryptoRule },
  { id: 'misconfiguration', name: 'Security Misconfiguration', check: misconfigurationRule },
  { id: 'sensitive-data', name: 'Sensitive Data Exposure', check: sensitiveDataRule },
  { id: 'file-handling', name: 'Insecure File Handling', check: fileHandlingRule },
];

export default rules;
