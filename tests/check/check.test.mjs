// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { parseVersion, compareStrings, inRange, minVersion } from '../../assets/js/check/versions.mjs';
import { detectFormat, parse } from '../../assets/js/check/parsers.mjs';
import { match, summarize, toMarkdown } from '../../assets/js/check/match.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = name => readFileSync(join(here, 'fixtures', name), 'utf8');
const byName = deps => Object.fromEntries(deps.map(d => [d.name, d]));

// ---------- versions ----------

test('semver ordering, prereleases below the release', () => {
  assert.equal(compareStrings('1.2.3', '1.2.10', 'npm'), -1);
  assert.equal(compareStrings('1.0.0-beta.2', '1.0.0-beta.10', 'npm'), -1);
  assert.equal(compareStrings('1.0.0-rc.1', '1.0.0', 'npm'), -1);
  assert.equal(compareStrings('v2.0', '2.0.0', 'npm'), 0);
});

test('composer ordering: v-prefix, 4 segments, stability flags', () => {
  assert.equal(compareStrings('v12.30.0', '12.68.0', 'composer'), -1);
  assert.equal(compareStrings('2.0.0-beta1', '2.0.0-RC1', 'composer'), -1);
  assert.equal(compareStrings('2.0.0-RC1', '2.0.0', 'composer'), -1);
  assert.equal(compareStrings('1.2.3.4', '1.2.3', 'composer'), 1);
  assert.equal(parseVersion('dev-main', 'composer'), null);
  assert.equal(parseVersion('latest', 'npm'), null);
});

test('GHSA ranges', () => {
  assert.ok(inRange('4.17.20', '>= 4.0.0, <= 4.17.23', 'npm'));
  assert.ok(!inRange('4.18.0', '>= 4.0.0, <= 4.17.23', 'npm'));
  assert.ok(inRange('v12.30.0', '< 12.68.0', 'composer'));
  assert.ok(!inRange('13.29.0', '>= 13.0.0, < 13.29.0', 'composer'));
  assert.ok(inRange('1.0.0', '= 1.0.0', 'npm'));
  assert.ok(!inRange('6.19.0', '>= 6.23.0, < 6.29.1', 'npm'));
});

test('lower bound of manifest constraints', () => {
  assert.equal(minVersion('^12.30', 'composer'), '12.30');
  assert.equal(minVersion('~7.4.0', 'composer'), '7.4.0');
  assert.equal(minVersion('>=5.0 <6.0', 'composer'), '5.0');
  assert.equal(minVersion('^1.0 || ^2.0', 'npm'), '1.0');
  assert.equal(minVersion('^2.0 | ^1.5', 'composer'), '1.5');
  assert.equal(minVersion('1.2.x', 'npm'), '1.2');
  assert.equal(minVersion('10.*', 'composer'), '10');
  assert.equal(minVersion('1.2.3 - 2.0.0', 'npm'), '1.2.3');
  assert.equal(minVersion('dev-main', 'composer'), null);
  assert.equal(minVersion('*', 'npm'), null);
  assert.equal(minVersion('<2.0', 'npm'), null);
  assert.equal(minVersion('workspace:*', 'npm'), null);
  assert.equal(minVersion('github:user/repo#main', 'npm'), null);
});

// ---------- parsers ----------

test('format detection by name and by content', () => {
  assert.equal(detectFormat('', 'some/dir/composer.lock'), 'composer.lock');
  assert.equal(detectFormat(fixture('composer.lock')), 'composer.lock');
  assert.equal(detectFormat(fixture('composer.json')), 'composer.json');
  assert.equal(detectFormat(fixture('package-lock.json')), 'package-lock.json');
  assert.equal(detectFormat(fixture('package.json')), 'package.json');
  assert.equal(detectFormat(fixture('yarn.lock')), 'yarn.lock');
  assert.equal(detectFormat(fixture('yarn.berry.lock')), 'yarn.lock');
  assert.equal(detectFormat(fixture('pnpm-lock.v9.yaml')), 'pnpm-lock.yaml');
  assert.equal(detectFormat('hello'), null);
  assert.throws(() => parse('hello'), /unknown-format/);
});

test('composer.lock', () => {
  const r = parse(fixture('composer.lock'), 'composer.lock');
  const d = byName(r.deps);
  assert.equal(r.ecosystem, 'composer');
  assert.equal(d['laravel/framework'].version, 'v12.30.0');
  assert.equal(d['phpunit/phpunit'].dev, true);
  assert.equal(d['monolog/monolog'].dev, false);
  assert.deepEqual(r.runtime, { php: '^8.2' });
});

test('composer.json skips platform packages', () => {
  const r = parse(fixture('composer.json'), 'composer.json');
  const names = r.deps.map(d => d.name);
  assert.ok(!names.includes('php') && !names.includes('ext-json'));
  assert.equal(byName(r.deps)['laravel/framework'].exact, false);
  assert.equal(byName(r.deps)['phpunit/phpunit'].dev, true);
});

test('package-lock.json v3: direct, dev, transitive', () => {
  const r = parse(fixture('package-lock.json'), 'package-lock.json');
  const d = byName(r.deps);
  assert.equal(d.undici.version, '6.19.0');
  assert.equal(d.undici.direct, true);
  assert.equal(d.braces.dev, true);
  const transitive = r.deps.filter(x => x.direct === false);
  assert.ok(transitive.length > 5, 'babel pulls in transitive deps');
  assert.deepEqual(r.runtime, { node: '>=20' });
});

test('package-lock.json v1: nested deps, file: versions skipped', () => {
  const r = parse(fixture('package-lock.v1.json'), 'package-lock.json');
  const d = byName(r.deps);
  assert.equal(d.qs.version, '6.7.0');
  assert.equal(d.mocha.dev, true);
  assert.ok(!d['local-thing']);
});

test('yarn.lock v1 and Berry', () => {
  const v1 = byName(parse(fixture('yarn.lock'), 'yarn.lock').deps);
  assert.equal(v1.lodash.version, '4.17.20');
  assert.equal(v1['@babel/traverse'].version, '7.22.0');
  const berry = parse(fixture('yarn.berry.lock'), 'yarn.lock').deps;
  assert.deepEqual(berry.map(x => `${x.name}@${x.version}`).sort(), ['@babel/traverse@7.22.0', 'lodash@4.17.20']);
});

test('pnpm-lock v5, v6, v9', () => {
  for (const f of ['pnpm-lock.v5.yaml', 'pnpm-lock.v6.yaml', 'pnpm-lock.v9.yaml']) {
    const d = byName(parse(fixture(f), 'pnpm-lock.yaml').deps);
    assert.equal(d.lodash?.version, '4.17.20', f);
    assert.equal(d['@babel/traverse']?.version, '7.22.0', f);
    assert.equal(d.lodash.direct, true, f);
  }
  const v9 = byName(parse(fixture('pnpm-lock.v9.yaml'), 'pnpm-lock.yaml').deps);
  assert.equal(v9.braces.dev, true);
  assert.equal(v9['@babel/traverse'].direct, true);
  const v6 = byName(parse(fixture('pnpm-lock.v6.yaml'), 'pnpm-lock.yaml').deps);
  assert.equal(v6.braces.dev, true);
});

// ---------- matching ----------

const DB = {
  packages: {
    lodash: [
      { id: 'GHSA-a', cve: 'CVE-1', sev: 'high', cvss: 7.4, title: 'a', ranges: [['>= 4.0.0, <= 4.17.23', '4.18.0']] },
      { id: 'GHSA-b', cve: 'CVE-2', sev: 'critical', cvss: 9.1, title: 'b', ranges: [['< 4.17.21', '4.17.21']] },
      { id: 'GHSA-c', cve: '', sev: 'low', cvss: null, title: 'c', ranges: [['< 3.0.0', '3.0.0']] },
    ],
    'laravel/framework': [
      { id: 'GHSA-l', cve: 'CVE-2026-114509', sev: 'critical', cvss: 9.2, title: 'TokenGuard', ranges: [['>= 13.0.0, < 13.29.0', '13.29.0'], ['< 12.68.0', '12.68.0']] },
    ],
    'guzzlehttp/guzzle': [
      { id: 'GHSA-g', cve: 'CVE-3', sev: 'high', cvss: 7.5, title: 'g', ranges: [['< 7.4.5', null]] },
    ],
  },
};

test('lockfile match: grouped by package, fix = highest patch', () => {
  const r = parse(fixture('package-lock.json'), 'package-lock.json');
  const { findings } = match(r.deps, DB, 'npm');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.name, 'lodash');
  assert.equal(f.certainty, 'vulnerable');
  assert.equal(f.severity, 'critical');
  assert.deepEqual(f.advisories.map(a => a.id), ['GHSA-b', 'GHSA-a']);
  assert.equal(f.fixVersion, '4.18.0');
});

test('composer.lock match: dev-main is unverifiable, missing patch → null fix', () => {
  const r = parse(fixture('composer.lock'), 'composer.lock');
  const { findings, unverifiable, checked } = match(r.deps, DB, 'composer');
  assert.deepEqual(findings.map(f => f.name), ['laravel/framework', 'guzzlehttp/guzzle']);
  assert.equal(findings[0].advisories[0].fixed, '12.68.0');
  assert.equal(findings[1].fixVersion, null);
  assert.deepEqual(unverifiable.map(d => d.name), ['acme/private-lib']);
  assert.equal(checked, 4);
  assert.deepEqual(summarize(findings).bySeverity, { critical: 1, high: 1, medium: 0, low: 0, unknown: 0 });
});

test('manifest match is only "possible"', () => {
  const r = parse(fixture('composer.json'), 'composer.json');
  const { findings } = match(r.deps, DB, 'composer');
  const l = findings.find(f => f.name === 'laravel/framework');
  assert.equal(l.certainty, 'possible');
  assert.equal(l.tested, '12.30');
});

test('markdown report', () => {
  const r = parse(fixture('composer.lock'), 'composer.lock');
  const m = match(r.deps, DB, 'composer');
  const md = toMarkdown({ format: r.format, ...m, generated: '2026-10-26T00:00:00Z', pageUrl: 'https://smzstudio.it/advisories/check/' });
  assert.match(md, /\| critical 9\.2 \| `laravel\/framework` \| v12\.30\.0 \| ≥ 12\.68\.0 \|/);
  assert.match(md, /nessuna patch/);
});

// ---------- real dataset (only when a local fetch produced it) ----------

const realDb = join(here, '../../assets/advisories-db/composer.json');
test('real dataset finds CVE-2026-114509 in laravel 12.30.0', { skip: !existsSync(realDb) }, () => {
  const db = JSON.parse(readFileSync(realDb, 'utf8'));
  const { findings } = match(parse(fixture('composer.lock'), 'composer.lock').deps, db, 'composer');
  const laravel = findings.find(f => f.name === 'laravel/framework');
  assert.ok(laravel.advisories.some(a => a.cve === 'CVE-2026-114509'));
});
