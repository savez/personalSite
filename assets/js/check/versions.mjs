// Version parsing and GHSA range matching for npm (semver) and composer.
//
// GitHub normalises every vulnerable range to a comma-separated list of
// conditions: "< 1.2.3", ">= 1.0.0, < 1.2.3", "<= 2.0", "= 1.0.0".
// That is all `inRange` has to understand.

// Composer stability flags, lowest first. A plain release sits between RC and patch.
const STABILITY = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, '': 4, stable: 4, patch: 5, pl: 5, p: 5 };

/**
 * Parses a version into { nums: [n, n, n, n], pre: [...] }, or null when it
 * isn't a comparable version (dev branches, git refs, tags like "latest").
 */
export function parseVersion(input, eco) {
  let s = String(input ?? '').trim().replace(/^[=v\s]+/i, '');
  s = s.replace(/\+.*$/, ''); // build metadata never affects ordering
  if (!s || /^dev-/i.test(s)) { return null; }

  const m = s.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?(.*))?$/);
  if (!m) { return null; }
  const nums = [m[1], m[2], m[3], m[4]].map(n => Number(n ?? 0));
  const rest = (m[5] ?? '').trim();

  if (eco === 'composer') {
    if (!rest) { return { nums, pre: [STABILITY['']] }; }
    const sm = rest.toLowerCase().match(/^(dev|alpha|a|beta|b|rc|stable|patch|pl|p)[.-]?(\d*)$/);
    if (!sm) { return null; }
    return { nums, pre: [STABILITY[sm[1]], Number(sm[2] || 0)] };
  }

  // npm: semver prerelease identifiers, dot-separated.
  if (!rest) { return { nums, pre: [] }; }
  return { nums, pre: rest.split('.').map(p => (/^\d+$/.test(p) ? Number(p) : p)) };
}

function comparePre(a, b, eco) {
  if (eco === 'composer') {
    for (let i = 0; i < 2; i++) {
      const d = (a[i] ?? 0) - (b[i] ?? 0);
      if (d) { return Math.sign(d); }
    }
    return 0;
  }
  // semver: no prerelease ranks above any prerelease.
  if (!a.length || !b.length) { return a.length === b.length ? 0 : (a.length ? -1 : 1); }
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) { return -1; }
    if (b[i] === undefined) { return 1; }
    if (a[i] === b[i]) { continue; }
    const an = typeof a[i] === 'number';
    const bn = typeof b[i] === 'number';
    if (an && bn) { return Math.sign(a[i] - b[i]); }
    if (an !== bn) { return an ? -1 : 1; }
    return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

export function compare(a, b, eco) {
  for (let i = 0; i < 4; i++) {
    if (a.nums[i] !== b.nums[i]) { return Math.sign(a.nums[i] - b.nums[i]); }
  }
  return comparePre(a.pre, b.pre, eco);
}

export function compareStrings(a, b, eco) {
  const pa = parseVersion(a, eco);
  const pb = parseVersion(b, eco);
  if (!pa || !pb) { return 0; }
  return compare(pa, pb, eco);
}

/** True when `version` satisfies every condition of a GHSA range. */
export function inRange(version, range, eco) {
  const v = typeof version === 'string' ? parseVersion(version, eco) : version;
  if (!v) { return false; }
  return String(range).split(',').every(cond => {
    const m = cond.trim().match(/^(<=|>=|<|>|=)?\s*(.+)$/);
    if (!m) { return false; }
    const bound = parseVersion(m[2], eco);
    if (!bound) { return false; }
    const c = compare(v, bound, eco);
    switch (m[1] ?? '=') {
      case '<': return c < 0;
      case '<=': return c <= 0;
      case '>': return c > 0;
      case '>=': return c >= 0;
      default: return c === 0;
    }
  });
}

/**
 * Lowest version a manifest constraint allows ("^10.2" → 10.2.0), or null
 * when there is no usable lower bound ("*", "<2", git URLs, workspace:…).
 * Alternatives ("^1.0 || ^2.0") yield the lowest of their lower bounds.
 */
export function minVersion(constraint, eco) {
  const s = String(constraint ?? '').trim();
  if (!s || /^(\*|x|latest|next)$/i.test(s) || /^(workspace|file|link|git|github|http|https|npm):|\//i.test(s)) { return null; }

  let best = null;
  for (let alt of s.split(/\s*\|\|?\s*/)) {
    alt = alt.replace(/\s+as\s+.*$/i, '').replace(/@(dev|alpha|beta|rc|stable)$/i, '').trim();
    // Hyphen range "1.2.3 - 2.0.0": the left side is the bound.
    const first = alt.split(/\s+-\s+/)[0];
    // Space- or comma-separated AND: the bound is the first ">="/"^"/"~"/bare term.
    let bound = null;
    for (const term of first.split(/[\s,]+/).filter(Boolean)) {
      const m = term.match(/^(\^|~>?|>=|>|=)?v?(\d+(?:\.(?:\d+|[x*]))*(?:-[0-9A-Za-z.-]+)?)$/i);
      if (!m) { continue; }
      if (m[1] === '>') { continue; } // strict bound: no exact minimum to test
      bound = m[2].replace(/\.[x*].*$/i, '');
      break;
    }
    const v = bound ? parseVersion(bound, eco) : null;
    if (v && (!best || compare(v, best.v, eco) < 0)) { best = { v, s: bound }; }
  }
  return best ? best.s : null;
}
