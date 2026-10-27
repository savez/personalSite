// Run with: node --test 'tests/**/*.test.mjs'
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { readTarGz, parseAdvisory, mergeIntoDataset } from '../../scripts/lib/friendsofphp.mjs';
import { match } from '../../assets/js/check/match.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const tarball = readFileSync(join(here, 'fixtures/fop.tar.gz'));

function load() {
  return readTarGz(tarball)
    .filter(f => f.path.endsWith('.yaml') && !f.path.includes('/.github/'))
    .map(f => ({ rel: f.path.split('/').slice(1).join('/'), text: f.text }));
}
const parsed = () => load().map(f => parseAdvisory(f.text, f.rel)).filter(Boolean);
const byFile = () => Object.fromEntries(parsed().map(a => [a.file, a]));

test('tar reader: yaml files, .github excluded by the caller', () => {
  const files = readTarGz(tarball).filter(f => f.path.endsWith('.yaml')).map(f => f.path.split('/').slice(1).join('/')).sort();
  assert.ok(files.includes('ameos/ameos_filemanager/CVE-2026-112238.yaml'));
  assert.ok(files.includes('.github/config.yaml'));
  assert.equal(load().length, 6);
});

test('CVE-named file', () => {
  const a = byFile()['ameos/ameos_filemanager/CVE-2026-112238.yaml'];
  assert.equal(a.pkg, 'ameos/ameos_filemanager');
  assert.equal(a.id, 'CVE-2026-112238');
  assert.equal(a.cve, 'CVE-2026-112238');
  assert.equal(a.published, '2026-10-20T09:00:00.000Z');
  assert.deepEqual(a.ranges, [['< 3.1.3', '3.1.3']]);
  assert.match(a.title, /^TYPO3-EXT-SA-2026-034: SQL Injection in extension "File manager"/);
});

test('GHSA-named file, unquoted values', () => {
  const a = byFile()['phpunit/phpunit/GHSA-9vw2-f4vp-x7gf.yaml'];
  assert.equal(a.id, 'GHSA-9vw2-f4vp-x7gf');
  assert.equal(a.ghsa, 'GHSA-9vw2-f4vp-x7gf');
  assert.equal(a.cve, '');
  assert.deepEqual(a.ranges, [['>= 13.4.0, < 13.4.4', '13.4.4']]);
});

test('date-named file: no ids, ~/null times, two branches', () => {
  const a = byFile()['laravel/framework/2014-04-11-1.yaml'];
  assert.equal(a.id, 'FOP-laravel/framework/2014-04-11-1');
  assert.equal(a.published, null);
  assert.deepEqual(a.ranges.map(r => r[1]), ['4.0.99', '4.1.26']);
});

test('inclusive upper bound has no fix; timezone offset is honoured', () => {
  const a = byFile()['laravel/framework/2015-01-01-1.yaml'];
  assert.deepEqual(a.ranges, [['<= 5.0.3', null]]);
  assert.equal(a.published, '2015-01-01T08:00:00.000Z');
});

test('"time: versions: [...]" on one line still yields the range', () => {
  const a = byFile()['typo3/cms-core/CVE-2026-1000.yaml'];
  assert.deepEqual(a.ranges, [['>= 12.0.0, < 12.4.30', '12.4.30']]);
});

test('unusable files are skipped', () => {
  assert.equal(load().length - parsed().length, 1);
  assert.equal(parseAdvisory('title: x\n', 'acme/broken/x.yaml'), null);
});

test('merge: by CVE, by GHSA, by identical range, added, enriched', () => {
  const packages = {
    'ameos/ameos_filemanager': [],
    'phpunit/phpunit': [
      { id: 'GHSA-9vw2-f4vp-x7gf', cve: '', sev: 'high', cvss: 7.3, title: 'PHPUnit tmp dir', published: '2026-10-28', ranges: [['>= 13.4.0, < 13.4.4', '13.4.4']] },
    ],
    'laravel/framework': [
      { id: 'GHSA-old1', cve: '', sev: 'medium', cvss: 5, title: 'Cookie hijack', published: '2014-04-12', ranges: [['>= 4.1.0, < 4.1.26', '4.1.26']] },
    ],
    'typo3/cms': [
      { id: 'GHSA-t3', cve: 'CVE-2026-1000', sev: 'high', cvss: 7.1, title: 'TYPO3 backend XSS', published: '2026-09-01', ranges: [['< 12.4.30', '12.4.30']] },
    ],
  };
  const stats = mergeIntoDataset(packages, parsed());
  assert.deepEqual(stats, { merged: 1, mergedByRange: 1, added: 3, enriched: 1 });

  const phpunit = packages['phpunit/phpunit'];
  assert.equal(phpunit.length, 1);
  assert.deepEqual(phpunit[0].src, ['github', 'friendsofphp']);
  assert.equal(phpunit[0].sev, 'high');
  assert.equal(phpunit[0].published, '2026-10-27', 'earliest date wins');

  const laravel = packages['laravel/framework'];
  assert.deepEqual(laravel[0].src, ['github', 'friendsofphp']);
  assert.equal(laravel[0].ranges.length, 2, 'the 4.0.x branch GitHub lacked is added');
  assert.equal(laravel.length, 2, 'the <=5.0.3 advisory has no twin and is added');

  const ameos = packages['ameos/ameos_filemanager'][0];
  assert.deepEqual(ameos.src, ['friendsofphp']);
  assert.equal(ameos.sev, 'unknown');

  const core = packages['typo3/cms-core'][0];
  assert.equal(core.sev, 'high', 'severity borrowed from the same CVE on typo3/cms');
  assert.equal(core.title, 'TYPO3 backend XSS');
});

test('merged dataset drives the version check', () => {
  const packages = { 'laravel/framework': [] };
  mergeIntoDataset(packages, parsed());
  const deps = [
    { name: 'ameos/ameos_filemanager', version: '3.1.2', exact: true, dev: false, direct: null },
    { name: 'ameos/ameos_filemanager', version: '3.1.3', exact: true, dev: false, direct: null },
    { name: 'phpunit/phpunit', version: '13.4.0', exact: true, dev: true, direct: null },
  ];
  const { findings } = match(deps, { packages }, 'composer');
  assert.deepEqual(findings.map(f => `${f.name}@${f.version}→${f.fixVersion}`).sort(),
    ['ameos/ameos_filemanager@3.1.2→3.1.3', 'phpunit/phpunit@13.4.0→13.4.4']);
});

const realDb = join(here, '../../assets/advisories-db/composer.json');
test('real dataset: ameos_filemanager 3.1.2 → CVE-2026-112238', { skip: !existsSync(realDb) }, () => {
  const db = JSON.parse(readFileSync(realDb, 'utf8'));
  const { findings } = match([{ name: 'ameos/ameos_filemanager', version: '3.1.2', exact: true, dev: false, direct: null }], db, 'composer');
  assert.ok(findings[0]?.advisories.some(a => a.cve === 'CVE-2026-112238'));
});
