// Matches parsed dependencies against the advisory dataset and groups the
// result by package: one entry per name@version with every advisory that
// hits it and the lowest version that fixes all of them.

import { compareStrings, inRange, minVersion, parseVersion } from './versions.mjs';

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

/**
 * @param deps     parsed dependencies ({ name, version, exact, dev, direct })
 * @param db       dataset: { packages: { name: [advisory] } }
 * @param eco      'npm' | 'composer'
 * @returns {{ findings, unverifiable, checked }}
 *   findings      – vulnerable packages, most severe first
 *   unverifiable  – deps whose version can't be compared (dev-main, git refs, "*")
 *   checked       – deps actually compared
 */
export function match(deps, db, eco) {
  const findings = [];
  const unverifiable = [];
  let checked = 0;

  for (const dep of deps) {
    // Manifests carry a range: test its lowest allowed version and flag the
    // result as "possible", since the lockfile may well have something newer.
    const tested = dep.exact ? dep.version : minVersion(dep.version, eco);
    const parsed = tested ? parseVersion(tested, eco) : null;
    if (!parsed) { unverifiable.push(dep); continue; }
    checked++;

    const hits = [];
    for (const adv of db.packages?.[dep.name] ?? []) {
      const range = adv.ranges.find(([r]) => inRange(parsed, r, eco));
      if (range) { hits.push({ ...adv, range: range[0], fixed: range[1] }); }
    }
    if (!hits.length) { continue; }

    hits.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || (b.cvss ?? 0) - (a.cvss ?? 0));
    findings.push({
      ...dep,
      tested,
      certainty: dep.exact ? 'vulnerable' : 'possible',
      severity: hits[0].sev,
      cvss: hits.reduce((m, h) => Math.max(m, h.cvss ?? 0), 0) || null,
      fixVersion: fixAll(hits, eco),
      advisories: hits,
    });
  }

  findings.sort((a, b) =>
    SEV_RANK[b.severity] - SEV_RANK[a.severity] || (b.cvss ?? 0) - (a.cvss ?? 0) || a.name.localeCompare(b.name));
  return { findings, unverifiable, checked };
}

// The lowest version that fixes every advisory is the highest of their fixes.
// One advisory without a fix means there is no safe version yet: null.
function fixAll(hits, eco) {
  let best = null;
  for (const h of hits) {
    if (!h.fixed) { return null; }
    if (!best || compareStrings(h.fixed, best, eco) > 0) { best = h.fixed; }
  }
  return best;
}

export function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of findings) { bySeverity[f.severity]++; }
  return { packages: findings.length, advisories: findings.reduce((n, f) => n + f.advisories.length, 0), bySeverity };
}

/** Markdown report, for an issue or a PR description. */
export function toMarkdown({ format, findings, checked, unverifiable, generated, pageUrl }) {
  const lines = [];
  lines.push(`## Vulnerabilità note · ${format}`, '');
  lines.push(`${checked} pacchetti controllati, ${findings.length} con vulnerabilità note` +
    (unverifiable.length ? `, ${unverifiable.length} non verificabili` : '') + '.', '');
  if (findings.length) {
    lines.push('| Gravità | Pacchetto | Versione | Aggiorna a | Advisory |', '|---|---|---|---|---|');
    for (const f of findings) {
      const advs = f.advisories.map(a => `[${a.cve || a.id}](https://github.com/advisories/${a.id})`).join(', ');
      const ver = f.exact ? f.version : `${f.version} (possibile)`;
      lines.push(`| ${f.severity}${f.cvss ? ` ${f.cvss.toFixed(1)}` : ''} | \`${f.name}\` | ${ver} | ${f.fixVersion ? `≥ ${f.fixVersion}` : 'nessuna patch'} | ${advs} |`);
    }
    lines.push('');
  }
  lines.push(`_Dataset GitHub Advisory Database del ${String(generated).slice(0, 10)} · ${pageUrl}_`);
  return lines.join('\n');
}
