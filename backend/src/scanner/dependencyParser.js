/**
 * Dependency manifest parser — Node / JS first (Phase 2).
 * Extracts an inventory from package.json and package-lock.json
 * for OSV CVE lookup. Direct vs transitive is authoritative from
 * the lockfile when present; package.json is a best-effort fallback
 * for exact-pinned versions only (honest about range ambiguity).
 */
const MAX_MANIFEST_CHARS = 3_000_000;
const EXACT_VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function safeJsonParse(text) {
  if (!text || text.length > MAX_MANIFEST_CHARS) return null;
  try { return JSON.parse(text); } catch { return null; }
}
function packageNameFromLockPath(lockPath) {
  if (!lockPath || lockPath === '') return null;
  const prefix = 'node_modules/';
  if (!lockPath.startsWith(prefix)) return null;
  const rest = lockPath.slice(prefix.length);
  const innerIdx = rest.lastIndexOf('/node_modules/');
  const effective = innerIdx >= 0 ? rest.slice(innerIdx + '/node_modules/'.length) : rest;
  if (!effective || effective.includes('/node_modules/')) return null;
  if (effective.startsWith('@')) {
    const parts = effective.split('/');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
    return effective;
  }
  if (effective.includes('/')) return null;
  return effective || null;
}
function parseLockfileV2(obj, sourceFile) {
  const packages = obj.packages;
  if (!packages || typeof packages !== 'object') return [];
  const root = packages[''] || {};
  const directNames = new Set([
    ...Object.keys(root.dependencies || {}),
    ...Object.keys(root.devDependencies || {}),
    ...Object.keys(root.optionalDependencies || {}),
    ...Object.keys(root.peerDependencies || {}),
  ]);
  const out = [];
  for (const [lockPath, entry] of Object.entries(packages)) {
    if (!lockPath) continue;
    const name = packageNameFromLockPath(lockPath);
    if (!name) continue;
    if (!entry || typeof entry !== 'object') continue;
    if (entry.link) continue;
    const version = entry.version != null ? String(entry.version).trim() : '';
    if (!version) continue;
    if (version.startsWith('file:') || version.startsWith('link:') || version.startsWith('workspace:')) continue;
    out.push({ name, version, type: directNames.has(name) ? 'direct' : 'transitive', sourceFile, dev: !!entry.dev, optional: !!entry.optional });
  }
  return out;
}
function parseLockfileV1(obj, sourceFile) {
  const deps = obj.dependencies;
  if (!deps || typeof deps !== 'object') return [];
  const out = []; const seen = new Set();
  function walk(node, isDirect) {
    if (!node || typeof node !== 'object') return;
    for (const [name, info] of Object.entries(node)) {
      if (!info || typeof info !== 'object') continue;
      const version = info.version != null ? String(info.version).trim() : '';
      if (!version) continue;
      if (version.startsWith('file:') || version.startsWith('link:') || version.startsWith('workspace:')) continue;
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ name, version, type: isDirect ? 'direct' : 'transitive', sourceFile, dev: !!info.dev, optional: !!info.optional });
      }
      if (info.dependencies && typeof info.dependencies === 'object') walk(info.dependencies, false);
    }
  }
  walk(deps, true); return out;
}
function parsePackageJson(obj, sourceFile) {
  if (!obj || typeof obj !== 'object') return [];
  const buckets = [obj.dependencies || {}, obj.devDependencies || {}, obj.optionalDependencies || {}];
  const out = []; const seen = new Set();
  for (const bucket of buckets) {
    if (!bucket || typeof bucket !== 'object') continue;
    for (const [name, rangeRaw] of Object.entries(bucket)) {
      const range = String(rangeRaw || '').trim();
      if (!EXACT_VERSION_RE.test(range)) continue;
      const key = `${name}@${range}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name, version: range, type: 'direct', sourceFile, dev: false, optional: false, versionSource: 'package.json' });
    }
  }
  return out;
}
function isPackageLockPath(p) { const base = String(p || '').split('/').pop() || ''; return base === 'package-lock.json'; }
function isPackageJsonPath(p) { const base = String(p || '').split('/').pop() || ''; return base === 'package.json'; }
export function isLockfilePath(p) {
  const base = String(p || '').split('/').pop() || '';
  return base === 'package-lock.json' || base === 'npm-shrinkwrap.json' || base === 'yarn.lock' || base === 'pnpm-lock.yaml';
}

export function parseDependencyManifests(files) {
  if (!Array.isArray(files) || files.length === 0) return null;
  const lockFiles = files.filter((f) => isPackageLockPath(f.path));
  const pkgFiles = files.filter((f) => isPackageJsonPath(f.path) && !isPackageLockPath(f.path));
  let aggregated = [];
  const manifestTypes = [];
  if (lockFiles.length > 0) {
    let anyParsed = false;
    for (const lf of lockFiles) {
      const obj = safeJsonParse(lf.content);
      if (!obj) continue;
      anyParsed = true;
      let deps;
      if (obj.lockfileVersion === 2 || obj.lockfileVersion === 3 || obj.packages) {
        deps = parseLockfileV2(obj, lf.path);
        if (deps.length) manifestTypes.push('package-lock.json (v2/v3)');
        else if (Object.prototype.hasOwnProperty.call(obj, 'packages')) manifestTypes.push('package-lock.json (v2/v3)');
      } else {
        deps = parseLockfileV1(obj, lf.path);
        if (Object.prototype.hasOwnProperty.call(obj, 'dependencies')) manifestTypes.push('package-lock.json (v1)');
      }
      aggregated.push(...deps);
    }
    if (anyParsed && aggregated.length > 0) return { dependencies: dedupeDeps(aggregated), manifestTypes };
    if (anyParsed) return { dependencies: [], manifestTypes };
    // all lockfiles malformed/oversized -> fall through to package.json
  }
  for (const pf of pkgFiles) {
    const obj = safeJsonParse(pf.content);
    if (!obj) continue;
    const deps = parsePackageJson(obj, pf.path);
    if (deps.length) {
      if (!manifestTypes.includes('package.json')) manifestTypes.push('package.json');
      aggregated.push(...deps);
    }
  }
  if (aggregated.length === 0) return null;
  return { dependencies: dedupeDeps(aggregated), manifestTypes };
}
function dedupeDeps(deps) {
  const seen = new Map();
  for (const d of deps) {
    const key = `${d.name}@${d.version}`;
    if (!seen.has(key)) seen.set(key, d);
    else {
      const existing = seen.get(key);
      if (existing.type === 'transitive' && d.type === 'direct') seen.set(key, d);
    }
  }
  return [...seen.values()];
}
export const _test = { packageNameFromLockPath, parseLockfileV2, parseLockfileV1, parsePackageJson, safeJsonParse, MAX_MANIFEST_CHARS };
