// Run with: node --test 'tests/**/*.test.mjs'
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { readZip, isGhsaFile, osvDataset, osvRanges, osvCvss, cvss3Score, cvss4Score } from '../../scripts/lib/osv.mjs';
import { match } from '../../assets/js/check/match.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const zip = readFileSync(join(here, 'fixtures/osv-packagist.zip'));

const helpers = {
  normSeverity: s => ({ moderate: 'medium' })[String(s ?? '').toLowerCase()] ?? (String(s ?? '').toLowerCase() || 'unknown'),
  oneLine: (t, max) => { const s = String(t).replace(/\s+/g, ' ').trim(); return s.length > max ? `${s.slice(0, max - 1)}…` : s; },
};
const dataset = () => osvDataset(readZip(zip, isGhsaFile), 'Packagist', helpers);

test('zip reader: stored and deflated entries, name filter applied before inflating', () => {
  const all = readZip(zip).map(f => f.path).sort();
  assert.equal(all.length, 6);
  const ghsa = readZip(zip, isGhsaFile);
  assert.deepEqual(ghsa.map(f => f.path).sort(), all.filter(n => n.startsWith('GHSA-')));
  for (const f of ghsa) { assert.equal(typeof JSON.parse(f.text).id, 'string'); }
});

test('only reviewed, not withdrawn GHSA advisories: no MAL, DRUPAL, unreviewed or withdrawn', () => {
  const ds = dataset();
  assert.equal(ds.count, 2);
  assert.deepEqual(Object.keys(ds.packages).sort(), ['acme/exact', 'acme/lib', 'acme/other']);
});

test('OSV events become GHSA range strings, with the fix', () => {
  const [a] = dataset().packages['acme/lib'];
  assert.equal(a.id, 'GHSA-aaaa-bbbb-cccc');
  assert.equal(a.cve, 'CVE-2026-1111');
  assert.equal(a.sev, 'critical');
  assert.equal(a.cvss, 9.8);
  assert.equal(a.title, 'Two branches and a last_affected');
  assert.equal(a.published, '2026-08-20');
  assert.deepEqual(a.ranges, [['< 1.2.3', '1.2.3'], ['>= 2.0.0, < 2.0.5', '2.0.5'], ['>= 3.0.0, <= 3.1.0', null]]);
  assert.deepEqual(dataset().packages['acme/other'][0].ranges, [['>= 1.0', null]]);
});

test('version list without ranges: one exact range per version; CVSS 4.0 scored', () => {
  const [a] = dataset().packages['acme/exact'];
  assert.deepEqual(a.ranges, [['= 2.4.5', null], ['= 2.4.6', null]]);
  assert.equal(a.sev, 'medium');
  assert.equal(a.cvss, 9.3);
});

test('introduced "0" with no end: every version', () => {
  assert.deepEqual(osvRanges({ ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }] }), [['>= 0', null]]);
  assert.deepEqual(osvRanges({ ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }] }] }), []);
});

test('CVSS 3.x base scores', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N'), 4.9);
  assert.equal(cvss3Score('CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H'), 7.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L'), null);
  // GitHub shows the temporal score: base 5.4 × 0.97 × 0.95.
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N/E:F/RL:O/RC:C'), 5);
});

test('the check page matches the converted ranges', () => {
  const ds = dataset();
  const deps = [
    { name: 'acme/lib', version: '1.2.2', exact: true },
    { name: 'acme/lib', version: '1.2.3', exact: true },
    { name: 'acme/lib', version: '2.0.4', exact: true },
    { name: 'acme/lib', version: '3.1.0', exact: true },
    { name: 'acme/exact', version: '2.4.6', exact: true },
    { name: 'acme/exact', version: '2.4.7', exact: true },
  ];
  const { findings } = match(deps, ds, 'composer');
  assert.deepEqual(findings.map(f => `${f.name}@${f.version}:${f.fixVersion}`).sort(),
    ['acme/exact@2.4.6:null', 'acme/lib@1.2.2:1.2.3', 'acme/lib@2.0.4:2.0.5', 'acme/lib@3.1.0:null']);
});

test('CVSS 4.0 scores (reference calculator) and 4.0 over 3.x', () => {
  assert.equal(cvss4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), 9.3);
  assert.equal(cvss4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:A/MAV:A'), 8.7);
  assert.equal(cvss4Score('CVSS:4.0/AV:N/AC:L'), null);
  assert.equal(cvss4Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'), 0);
  const both = { severity: [
    { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:A/MAV:A' },
  ] };
  assert.equal(osvCvss(both), 8.7);
  assert.equal(osvCvss({ severity: [{ type: 'CVSS_V4', score: 'bad' }, both.severity[0]] }), 9.8);
  assert.equal(osvCvss({}), null);
});
