/**
 * FriendsOfPHP/security-advisories — the PHP community advisory database.
 *
 * One YAML file per advisory, `vendor/name/<ID>.yaml`, always the same five keys:
 *
 *   title: 'TYPO3-EXT-SA-2026-034: SQL Injection in extension …'
 *   link: 'https://news.typo3.com/security/advisory/typo3-ext-sa-2026-034'
 *   cve: CVE-2026-112238
 *   branches:
 *       3.x:
 *           time: '2026-10-20 09:00:00'
 *           versions: ['<3.1.3']
 *   reference: 'composer://ameos/ameos_filemanager'
 *
 * The repo is read from its GitHub tarball (~160 KB) with a tiny tar reader and
 * a line parser for those keys: no YAML library, no `tar` binary.
 *
 * Merging with the GitHub dataset: same package + same CVE (or GHSA) → one
 * advisory, GitHub's severity/CVSS/title win and FriendsOfPHP adds the branches
 * GitHub lacks. No match → added on its own, with unknown severity (the
 * source has none).
 */

import { gunzipSync } from 'zlib';

export const FOP_TARBALL = 'https://codeload.github.com/FriendsOfPHP/security-advisories/tar.gz/refs/heads/master';
export const FOP_BLOB = 'https://github.com/FriendsOfPHP/security-advisories/blob/master';

// ---------- tar ----------

/** Files of a .tar.gz buffer: [{ path, text }]. Regular files only. */
export function readTarGz(buffer) {
  const tar = gunzipSync(buffer);
  const files = [];
  let longName = null;
  for (let off = 0; off + 512 <= tar.length;) {
    const header = tar.subarray(off, off + 512);
    if (header.every(b => b === 0)) { break; } // end-of-archive marker
    const str = (start, len) => header.subarray(start, start + len).toString('utf8').replace(/\0.*$/s, '');
    const size = parseInt(str(124, 12).trim() || '0', 8);
    const type = str(156, 1) || '0';
    const prefix = str(345, 155);
    let path = longName ?? (prefix ? `${prefix}/${str(0, 100)}` : str(0, 100));
    longName = null;
    const body = tar.subarray(off + 512, off + 512 + size);
    if (type === 'L') {
      longName = body.toString('utf8').replace(/\0.*$/s, ''); // GNU long name for the next entry
    } else if (type === 'x') {
      const m = body.toString('utf8').match(/\d+ path=([^\n]+)\n/); // pax extended header
      if (m) { longName = m[1]; }
    } else if (type === '0' || type === '\0') {
      files.push({ path, text: body.toString('utf8') });
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}

// ---------- YAML (the five keys) ----------

function unquote(s) {
  const v = String(s ?? '').trim();
  if (v === '~' || v === 'null' || v === '') { return null; }
  if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) {
    return v.slice(1, -1).replace(/''/g, "'");
  }
  return v;
}

function parseList(s) {
  const m = String(s).trim().match(/^\[(.*)\]$/);
  if (!m) { return null; }
  return m[1].split(',').map(unquote).filter(Boolean);
}

/**
 * Parses one advisory file. Returns null when the file isn't usable
 * (no composer reference or no branch with versions).
 */
export function parseAdvisory(text, file) {
  const out = { title: null, link: null, cve: null, reference: null, branches: [] };
  let branch = null;
  for (const raw of String(text).split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) { continue; }
    const indent = raw.length - raw.trimStart().length;
    const m = raw.trim().match(/^([^:]+):\s*(.*)$/);
    if (!m) { continue; }
    const [, key, value] = m;
    if (indent === 0) {
      branch = null;
      if (key === 'title' || key === 'link' || key === 'cve' || key === 'reference') { out[key] = unquote(value); }
    } else if (indent <= 4 && !value) {
      branch = { name: unquote(key), time: null, versions: null };
      out.branches.push(branch);
    } else if (branch && key === 'time' && /^versions:/.test(value)) {
      // A couple of files have "time: versions: [...]" on one line.
      branch.versions = parseList(value.replace(/^versions:\s*/, ''));
    } else if (branch && key === 'time') {
      branch.time = unquote(value);
    } else if (branch && key === 'versions') {
      branch.versions = parseList(value);
    }
  }

  const pkg = (out.reference ?? '').match(/^composer:\/\/(.+)$/)?.[1]?.toLowerCase();
  const branches = out.branches.filter(b => b.versions?.length);
  if (!pkg || !branches.length) { return null; }

  const base = file.split('/').pop().replace(/\.ya?ml$/, '');
  const cve = (out.cve && /^CVE-\d{4}-\d+$/i.test(out.cve) ? out.cve : null)
    ?? (/^CVE-\d{4}-\d+$/i.test(base) ? base : null);
  const ghsa = (/^GHSA-[\w-]+$/i.test(base) ? base : null) ?? out.link?.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)?.[0] ?? null;

  const times = branches.map(b => parseTime(b.time)).filter(Boolean).sort();
  return {
    pkg,
    id: cve ?? ghsa ?? `FOP-${pkg}/${base}`,
    cve: cve ?? '',
    ghsa: ghsa ?? '',
    title: out.title ?? `${pkg} security advisory`,
    link: out.link ?? '',
    file: `${pkg}/${file.split('/').pop()}`,
    published: times.length ? times[times.length - 1] : null,
    ranges: branches.map(b => [toRange(b.versions), fixedOf(b.versions)]),
  };
}

function parseTime(s) {
  if (!s) { return null; }
  const m = String(s).match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\s*([+-]\d{2}):?(\d{2}))?$/);
  if (!m) { return null; }
  const t = Date.parse(`${m[1]}T${m[2]}${m[3] ? `${m[3]}:${m[4]}` : 'Z'}`);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

// ['>=13.4.0', '<13.4.4'] → '>= 13.4.0, < 13.4.4' (the GHSA range format the matcher reads).
function toRange(versions) {
  return versions.map(v => v.replace(/^(>=|<=|>|<|=)?\s*/, (_, op) => `${op ?? '='} `).trim()).join(', ');
}

// The fix is the strict upper bound of the branch: '<13.4.4' → '13.4.4'.
// '<=X' or no upper bound means no fixed version is known.
function fixedOf(versions) {
  const lt = versions.map(v => v.trim().match(/^<\s*([^=].*)$/)).find(Boolean);
  return lt ? lt[1].trim() : null;
}

// ---------- merge into the GitHub dataset ----------

/**
 * Merges FriendsOfPHP advisories into a dataset `{ name: [advisory] }` in place.
 * GitHub entries need `id` (GHSA) and `cve`; they get `src: ['github']` if missing.
 *
 * Matching, in order:
 *   1. same package and same CVE or GHSA → merge
 *   2. no CVE/GHSA at all, but same package and an identical range → merge.
 *      Old FriendsOfPHP files (named by date) carry no identifier; when the
 *      vulnerable range and its fix are the same as a GitHub advisory, it is
 *      the same issue for every version check, so merging loses nothing.
 *   3. otherwise → add, with unknown severity. If GitHub has the same CVE
 *      under another package (symfony/symfony vs symfony/http-kernel, the
 *      Magento metapackages), severity, CVSS and title are borrowed from it.
 *
 * Returns { merged, mergedByRange, added, enriched } counts.
 */
export function mergeIntoDataset(packages, fopAdvisories) {
  const stats = { merged: 0, mergedByRange: 0, added: 0, enriched: 0 };
  const githubByCve = new Map();
  for (const list of Object.values(packages)) {
    for (const a of list) {
      if (a.cve && (a.src ?? ['github']).includes('github')) { githubByCve.set(a.cve.toUpperCase(), a); }
    }
  }

  for (const f of fopAdvisories) {
    const list = (packages[f.pkg] ??= []);
    const github = list.filter(a => (a.src ?? ['github']).includes('github'));
    let hit = github.find(a =>
      (f.cve && a.cve && a.cve.toUpperCase() === f.cve.toUpperCase()) ||
      (f.ghsa && a.id && a.id.toUpperCase() === f.ghsa.toUpperCase()));
    let byRange = false;
    if (!hit && !f.cve && !f.ghsa) {
      const mine = new Set(f.ranges.map(([r]) => norm(r)));
      hit = github.find(a => a.ranges.some(([r]) => mine.has(norm(r))));
      byRange = Boolean(hit);
    }

    if (hit) {
      // Add only branches GitHub doesn't already describe with the same range.
      const known = new Set(hit.ranges.map(([r]) => norm(r)));
      for (const r of f.ranges) { if (!known.has(norm(r[0]))) { hit.ranges.push(r); } }
      hit.src = [...new Set([...(hit.src ?? ['github']), 'friendsofphp'])];
      if (f.published && (!hit.published || f.published.slice(0, 10) < hit.published)) { hit.published = f.published.slice(0, 10); }
      hit.fop = f.file;
      stats[byRange ? 'mergedByRange' : 'merged']++;
      continue;
    }

    const twin = f.cve ? githubByCve.get(f.cve.toUpperCase()) : null;
    if (twin) { stats.enriched++; }
    const title = twin?.title ?? f.title;
    list.push({
      id: f.id,
      cve: f.cve,
      sev: twin?.sev ?? 'unknown',
      cvss: twin?.cvss ?? null,
      title: title.length > 120 ? `${title.slice(0, 119).trimEnd()}…` : title,
      published: f.published?.slice(0, 10) ?? '',
      ranges: f.ranges,
      src: ['friendsofphp'],
      link: f.link,
      fop: f.file,
    });
    stats.added++;
  }
  return stats;
}

function norm(range) {
  return String(range).replace(/\s+/g, '').toLowerCase();
}
