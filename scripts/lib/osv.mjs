/**
 * OSV.dev bulk exports — the full GitHub reviewed dataset without the GitHub API.
 *
 * OSV mirrors the GitHub Advisory Database and publishes it per ecosystem as a
 * single zip of OSV JSON files, one per advisory:
 *
 *   https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 *   https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
 *
 * One download replaces ~100 paginated, rate-limited API calls per ecosystem.
 * Only GitHub reviewed advisories (GHSA-*, github_reviewed) are kept, so the
 * dataset is the same one the API returns. The zips also carry other sources:
 * MAL-* (OpenSSF malicious packages, ~225k entries in npm) and DRUPAL-* (Drupal
 * security team). They are skipped by file name, before being inflated.
 *
 * Differences from the API, handled here:
 *   - ranges come as OSV events (introduced / fixed / last_affected) or a plain
 *     version list; they are turned back into the GHSA range strings the check
 *     page matches ("< 1.2.3", ">= 1.0.0, < 1.2.3", "<= 2.0", "= 1.0.0").
 *   - CVSS comes as a vector, not a score. Scores are computed from the vector:
 *     CVSS 4.0 with Red Hat's reference calculator (vendor/cvss40.cjs, BSD-2),
 *     CVSS 3.x with the formula below. Like the API, 4.0 wins over 3.x.
 *
 * The zip reader handles ZIP64: the npm export has more than 65535 entries.
 */

import { inflateRawSync } from 'zlib';
import cvss40 from './vendor/cvss40.cjs';

export const OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com';
export const OSV_ECOSYSTEM = { npm: 'npm', composer: 'Packagist' };

// ---------- zip ----------

const SIG_EOCD = 0x06054b50;
const SIG_Z64_LOCATOR = 0x07064b50;
const SIG_Z64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

/**
 * Files of a zip buffer whose name passes `keep(name)`: [{ path, text }].
 * Names are filtered before anything is inflated. Methods: stored and deflate.
 */
export function readZip(buf, keep = () => true) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) { throw new Error('not a zip file'); }

  let cdOffset = buf.readUInt32LE(eocd + 16);
  let total = buf.readUInt16LE(eocd + 10);
  const loc = eocd - 20;
  if (loc >= 0 && buf.readUInt32LE(loc) === SIG_Z64_LOCATOR) {
    const z64 = Number(buf.readBigUInt64LE(loc + 8));
    if (buf.readUInt32LE(z64) !== SIG_Z64_EOCD) { throw new Error('bad ZIP64 end of central directory'); }
    total = Number(buf.readBigUInt64LE(z64 + 32));
    cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
  }

  const files = [];
  let off = cdOffset;
  for (let n = 0; n < total; n++) {
    if (buf.readUInt32LE(off) !== SIG_CENTRAL) { throw new Error(`bad central directory entry at ${off}`); }
    const method = buf.readUInt16LE(off + 10);
    let compSize = buf.readUInt32LE(off + 20);
    let size = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    let localOff = buf.readUInt32LE(off + 42);
    const name = buf.subarray(off + 46, off + 46 + nameLen).toString('utf8');

    if (keep(name) && !name.endsWith('/')) {
      // ZIP64 extra field: only the values that overflowed are present, in this order.
      const extra = buf.subarray(off + 46 + nameLen, off + 46 + nameLen + extraLen);
      for (let e = 0; e + 4 <= extra.length;) {
        const id = extra.readUInt16LE(e);
        const len = extra.readUInt16LE(e + 2);
        if (id === 0x0001) {
          let p = e + 4;
          if (size === 0xffffffff) { size = Number(extra.readBigUInt64LE(p)); p += 8; }
          if (compSize === 0xffffffff) { compSize = Number(extra.readBigUInt64LE(p)); p += 8; }
          if (localOff === 0xffffffff) { localOff = Number(extra.readBigUInt64LE(p)); }
        }
        e += 4 + len;
      }
      if (buf.readUInt32LE(localOff) !== SIG_LOCAL) { throw new Error(`bad local header for ${name}`); }
      const start = localOff + 30 + buf.readUInt16LE(localOff + 26) + buf.readUInt16LE(localOff + 28);
      const data = buf.subarray(start, start + compSize);
      let body;
      if (method === 0) { body = data; }
      else if (method === 8) { body = inflateRawSync(data); }
      else { throw new Error(`unsupported compression method ${method} for ${name}`); }
      files.push({ path: name, text: body.toString('utf8') });
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

// ---------- CVSS 3.x ----------

const V3 = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

// CVSS 3.1 Roundup: smallest one-decimal number >= x, without float artefacts.
function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** Score of a CVSS 3.0/3.1 vector (temporal when it has E/RL/RC), or null when the vector is incomplete. */
export function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector ?? '').split('/').slice(1).map(p => p.split(':')));
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const [av, ac, ui] = [V3.AV[m.AV], V3.AC[m.AC], V3.UI[m.UI]];
  const [c, i, a] = [V3.CIA[m.C], V3.CIA[m.I], V3.CIA[m.A]];
  if ([av, ac, ui, pr, c, i, a].some(v => v === undefined) || !['U', 'C'].includes(m.S)) { return null; }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) { return 0; }
  const exploitability = 8.22 * av * ac * pr * ui;
  const base = roundup(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
  // Temporal metrics in the vector: GitHub shows the temporal score, so do the same.
  const e = { F: 0.97, P: 0.94, U: 0.91 }[m.E] ?? 1;
  const rl = { W: 0.97, T: 0.96, O: 0.95 }[m.RL] ?? 1;
  const rc = { R: 0.96, U: 0.92 }[m.RC] ?? 1;
  return e * rl * rc === 1 ? base : roundup(base * e * rl * rc);
}

// ---------- OSV → dataset entry ----------

/**
 * GHSA range strings of one OSV `affected` entry: [[range, fixed]].
 * Every introduced event opens a range; the next fixed / last_affected closes it.
 */
export function osvRanges(affected) {
  const out = [];
  for (const r of affected.ranges ?? []) {
    if (r.type !== 'ECOSYSTEM' && r.type !== 'SEMVER') { continue; }
    let lower = null;
    let open = false;
    for (const e of r.events ?? []) {
      if (e.introduced !== undefined) {
        if (open) { out.push([lower ?? '>= 0', null]); }
        lower = e.introduced === '0' ? null : `>= ${e.introduced}`;
        open = true;
      } else if (open && e.fixed !== undefined) {
        out.push([[lower, `< ${e.fixed}`].filter(Boolean).join(', '), e.fixed]);
        open = false;
      } else if (open && e.last_affected !== undefined) {
        out.push([[lower, `<= ${e.last_affected}`].filter(Boolean).join(', '), null]);
        open = false;
      }
    }
    if (open) { out.push([lower ?? '>= 0', null]); }
  }
  // No ranges at all: GitHub lists the exact vulnerable versions ("= 2.4.5").
  if (!out.length) {
    for (const v of affected.versions ?? []) { out.push([`= ${v}`, null]); }
  }
  return out;
}

// ---------- CVSS 4.0 ----------

/** Score of a CVSS 4.0 vector, or null when the vector is invalid. */
export function cvss4Score(vector) {
  // The calculator logs to console.error before throwing on a bad vector: keep the build log clean.
  const log = console.error;
  console.error = () => {};
  try { return new cvss40.CVSS40(String(vector ?? '')).score; }
  catch { return null; }
  finally { console.error = log; }
}

/**
 * The advisory's score, as the GitHub API gives it: CVSS 4.0 when there is
 * one, else CVSS 3.x. A score of 0 is null, as in the API.
 */
export function osvCvss(adv) {
  const best = (type, score) => {
    const scores = (adv.severity ?? []).filter(s => s.type === type).map(s => score(s.score)).filter(s => s > 0);
    return scores.length ? Math.max(...scores) : null;
  };
  return best('CVSS_V4', cvss4Score) ?? best('CVSS_V3', cvss3Score);
}

/**
 * Dataset `{ count, packages: { name: [advisory] } }` from the files of an
 * OSV ecosystem export. Same entry shape the check page reads:
 * { id, cve, sev, cvss, title, published, ranges }.
 *
 * @param files      [{ path, text }] (readZip output)
 * @param ecosystem  OSV ecosystem name ('npm', 'Packagist')
 * @param helpers    { normSeverity, oneLine } from the fetch script
 */
export function osvDataset(files, ecosystem, { normSeverity, oneLine }) {
  const packages = {};
  let count = 0;
  for (const f of files) {
    const adv = JSON.parse(f.text);
    if (!/^GHSA-/.test(adv.id ?? '') || adv.withdrawn || adv.database_specific?.github_reviewed !== true) { continue; }
    count++;
    const cvss = osvCvss(adv);
    const byPkg = new Map();
    for (const a of adv.affected ?? []) {
      const name = a.package?.name;
      if (!name || a.package.ecosystem !== ecosystem) { continue; }
      const ranges = osvRanges(a);
      if (!ranges.length) { continue; }
      if (!byPkg.has(name)) { byPkg.set(name, []); }
      byPkg.get(name).push(...ranges);
    }
    for (const [name, ranges] of byPkg) {
      (packages[name] ??= []).push({
        id: adv.id,
        cve: (adv.aliases ?? []).find(a => /^CVE-/.test(a)) ?? '',
        sev: normSeverity(adv.database_specific?.severity, cvss),
        cvss,
        title: oneLine(adv.summary || adv.id, 120),
        published: adv.published?.slice(0, 10) ?? '',
        ranges,
      });
    }
  }
  return { count, packages };
}

/** Name filter for readZip: GitHub advisories only. */
export const isGhsaFile = name => /^GHSA-[\w-]+\.json$/.test(name);
