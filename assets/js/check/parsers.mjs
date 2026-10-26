// Dependency file parsers. Every parser returns the same shape:
//
//   { format, ecosystem, deps: [{ name, version, exact, dev, direct }], runtime }
//
// exact  – true for lockfiles (installed version), false for manifests (a range)
// dev    – true / false, or null when the file doesn't say
// direct – true / false, or null when the file doesn't say
// runtime – { php } or { node } constraint when the file declares one (phase 4)
//
// The YAML-ish lockfiles (yarn, pnpm) are read line by line: they only need
// package keys and versions, not a YAML library.

const COMPOSER_PLATFORM = /^(php|php-64bit|hhvm|ext-.+|lib-.+|composer|composer-plugin-api|composer-runtime-api)$/i;

export const FORMATS = {
  'composer.lock': 'composer.lock',
  'package-lock.json': 'package-lock.json',
  'npm-shrinkwrap.json': 'package-lock.json',
  'yarn.lock': 'yarn.lock',
  'pnpm-lock.yaml': 'pnpm-lock.yaml',
  'composer.json': 'composer.json',
  'package.json': 'package.json',
};

/** Picks the format from the file name, falling back to the content (pasted text). */
export function detectFormat(text, filename = '') {
  const base = String(filename).split(/[\\/]/).pop().toLowerCase();
  if (FORMATS[base]) { return FORMATS[base]; }

  const t = String(text).trimStart();
  if (t.startsWith('{')) {
    let j;
    try { j = JSON.parse(t); } catch { return null; }
    if (Array.isArray(j.packages) && ('content-hash' in j || 'packages-dev' in j)) { return 'composer.lock'; }
    if ('lockfileVersion' in j) { return 'package-lock.json'; }
    if ('require' in j || 'require-dev' in j) { return 'composer.json'; }
    if ('dependencies' in j || 'devDependencies' in j || 'name' in j) { return 'package.json'; }
    return null;
  }
  if (/^lockfileVersion:/m.test(t)) { return 'pnpm-lock.yaml'; }
  if (/^# yarn lockfile v1/m.test(t) || /^__metadata:/m.test(t)) { return 'yarn.lock'; }
  return null;
}

export function parse(text, filename = '') {
  const format = detectFormat(text, filename);
  if (!format) { throw new Error('unknown-format'); }
  const result = PARSERS[format](String(text));
  return { format, ...result, deps: dedupe(result.deps) };
}

// Same name@version can appear many times in npm trees; keep one, merging flags:
// direct if any occurrence is direct, dev only if every occurrence is dev.
function dedupe(deps) {
  const map = new Map();
  for (const d of deps) {
    const key = `${d.name}@${d.version}`;
    const prev = map.get(key);
    if (!prev) { map.set(key, { ...d }); continue; }
    prev.direct = prev.direct === true || d.direct === true ? true : (prev.direct ?? d.direct);
    prev.dev = prev.dev === false || d.dev === false ? false : (prev.dev ?? d.dev);
  }
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function json(text) {
  try { return JSON.parse(text); } catch { throw new Error('invalid-json'); }
}

// ---------- composer ----------

function composerLock(text) {
  const j = json(text);
  const deps = [];
  for (const [key, dev] of [['packages', false], ['packages-dev', true]]) {
    for (const p of j[key] ?? []) {
      if (p?.name && p.version) { deps.push({ name: p.name.toLowerCase(), version: p.version, exact: true, dev, direct: null }); }
    }
  }
  const php = j.platform?.php ?? null;
  return { ecosystem: 'composer', deps, runtime: php ? { php } : null };
}

function composerJson(text) {
  const j = json(text);
  const deps = [];
  for (const [key, dev] of [['require', false], ['require-dev', true]]) {
    for (const [name, version] of Object.entries(j[key] ?? {})) {
      if (COMPOSER_PLATFORM.test(name)) { continue; }
      deps.push({ name: name.toLowerCase(), version: String(version), exact: false, dev, direct: true });
    }
  }
  const php = j.require?.php ?? null;
  return { ecosystem: 'composer', deps, runtime: php ? { php } : null };
}

// ---------- npm ----------

function packageLock(text) {
  const j = json(text);
  const deps = [];
  if (j.packages && typeof j.packages === 'object') {
    // lockfile v2/v3: flat map of install paths.
    const root = j.packages[''] ?? {};
    const directNames = new Set(Object.keys({
      ...root.dependencies, ...root.devDependencies, ...root.optionalDependencies,
    }));
    for (const [path, p] of Object.entries(j.packages)) {
      if (!path || !path.includes('node_modules/') || p.link || !p.version) { continue; }
      const name = p.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const topLevel = path === `node_modules/${name}`;
      deps.push({ name, version: p.version, exact: true, dev: Boolean(p.dev || p.devOptional), direct: topLevel && directNames.has(name) });
    }
  } else if (j.dependencies) {
    // lockfile v1: nested tree. Top level mixes direct and hoisted deps, so direct is unknown.
    const walk = tree => {
      for (const [name, p] of Object.entries(tree ?? {})) {
        if (p?.version && !/^(file|link|git)/.test(p.version)) {
          deps.push({ name, version: p.version, exact: true, dev: Boolean(p.dev), direct: null });
        }
        walk(p?.dependencies);
      }
    };
    walk(j.dependencies);
  }
  const node = j.packages?.['']?.engines?.node ?? null;
  return { ecosystem: 'npm', deps, runtime: node ? { node } : null };
}

function packageJson(text) {
  const j = json(text);
  const deps = [];
  for (const [key, dev] of [['dependencies', false], ['optionalDependencies', false], ['devDependencies', true]]) {
    for (const [name, version] of Object.entries(j[key] ?? {})) {
      deps.push({ name, version: String(version), exact: false, dev, direct: true });
    }
  }
  const node = j.engines?.node ?? null;
  return { ecosystem: 'npm', deps, runtime: node ? { node } : null };
}

// "name@range" → name. Scoped names start with "@", so the separator is the last "@" after position 0.
function specName(spec) {
  const s = spec.trim().replace(/^["']|["']$/g, '');
  const at = s.indexOf('@', 1);
  return at > 0 ? s.slice(0, at) : s;
}

function yarnLock(text) {
  const deps = [];
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) { continue; }
    if (!/^\s/.test(line)) {
      // Entry header: one or more comma-separated specs, ending with ":".
      const header = line.replace(/:\s*$/, '');
      current = header === '__metadata' ? null : { name: specName(header.split(',')[0]), header };
      continue;
    }
    if (!current) { continue; }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/);
    if (m) {
      // Workspace entries (Berry) are the project itself, not a dependency.
      if (!/@workspace:|use\.local/.test(current.header + m[1])) {
        deps.push({ name: current.name, version: m[1], exact: true, dev: null, direct: null });
      }
      current = null;
    }
  }
  return { ecosystem: 'npm', deps, runtime: null };
}

// pnpm package keys across lockfile versions:
//   v5  /name/1.2.3   /@scope/name/1.2.3_peer@1
//   v6  /name@1.2.3   /@scope/name@1.2.3(peer@1)
//   v9  name@1.2.3    '@scope/name@1.2.3'
function pnpmKey(raw) {
  let k = raw.trim().replace(/:\s*(\{\s*\})?\s*$/, '').replace(/^['"]|['"]$/g, '').replace(/\(.*$/, '');
  k = k.replace(/^\//, '');
  // v5 first: its peer suffix ("_supports-color@8.1.1") contains an "@" that
  // would fool the "name@version" split.
  const slash = k.match(/^(@[^/]+\/[^/]+|[^/@]+)\/(\d[^/]*)$/);
  if (slash) { return { name: slash[1], version: slash[2].replace(/_.*$/, '') }; }
  const at = k.match(/^(@[^/@]+\/[^@]+|[^@]+)@(\d.*)$/);
  if (at) { return { name: at[1], version: at[2] }; }
  return null;
}

function pnpmLock(text) {
  const lines = text.split(/\r?\n/);
  const pkgs = new Map();
  const direct = new Map(); // name → dev?
  let section = null;       // top-level key we're inside
  let depKind = null;       // dependencies | devDependencies | optionalDependencies, inside importers or v5/v6 root
  let depIndent = -1;
  let pkg = null;

  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) { continue; }
    const indent = line.length - line.trimStart().length;
    const key = line.trim();

    if (indent === 0) {
      section = key.replace(/:.*$/, '');
      depKind = /^(dependencies|devDependencies|optionalDependencies)$/.test(section) ? section : null;
      depIndent = depKind ? 0 : -1;
      pkg = null;
      continue;
    }

    if (section === 'importers') {
      const m = key.match(/^(dependencies|devDependencies|optionalDependencies):$/);
      if (m) { depKind = m[1]; depIndent = indent; continue; }
      if (indent <= depIndent) { depKind = null; depIndent = -1; }
    }

    // A direct dependency: "name:" (v6/v9, details below) or "name: 1.2.3" (v5).
    if (depKind && indent === depIndent + 2) {
      const name = key.replace(/:.*$/, '').replace(/^['"]|['"]$/g, '');
      direct.set(name, (direct.get(name) ?? true) && depKind === 'devDependencies');
      continue;
    }

    if (section === 'packages') {
      if (indent === 2) {
        const parsed = pnpmKey(key);
        pkg = parsed ? { ...parsed, dev: null } : null;
        if (pkg) { pkgs.set(`${pkg.name}@${pkg.version}`, pkg); }
      } else if (pkg && indent === 4) {
        const m = key.match(/^dev:\s*(true|false)$/);
        if (m) { pkg.dev = m[1] === 'true'; }
      }
    }
  }

  const deps = [...pkgs.values()].map(p => ({
    name: p.name,
    version: p.version,
    exact: true,
    dev: p.dev ?? (direct.has(p.name) ? direct.get(p.name) : null),
    direct: direct.size ? direct.has(p.name) : null,
  }));
  return { ecosystem: 'npm', deps, runtime: null };
}

const PARSERS = {
  'composer.lock': composerLock,
  'composer.json': composerJson,
  'package-lock.json': packageLock,
  'package.json': packageJson,
  'yarn.lock': yarnLock,
  'pnpm-lock.yaml': pnpmLock,
};
