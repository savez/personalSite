#!/usr/bin/env node
/**
 * fetch-advisories.mjs — builds the data behind /advisories.
 *
 * Writes two files that Hugo loads as site.Data.vulns and site.Data.alerts:
 *
 *   data/vulns.json   vulnerabilities, tagged by category
 *                     (npm, composer, actions, nodejs, php, laravel)
 *   data/alerts.json  CERT-EU + CSIRT Italia bulletins of the last ALERT_HOURS
 *
 * Sources:
 *   - GitHub Advisory DB, reviewed: one page per ecosystem + the Laravel packages
 *   - GitHub Advisory DB, unreviewed: every advisory published in the last
 *     UNREVIEWED_DAYS, kept only when a reference points at a tracked repo
 *     (php/php-src, nodejs/node, laravel/*). Unreviewed advisories carry no
 *     package, so the references are the only reliable signal: matching the
 *     text would tag every WordPress plugin CVE that mentions "file.php".
 *     The DB gets ~450 unreviewed a day, so keep the window short: 90 days
 *     meant ~400 pages and 6+ minutes per build for ~20 matches.
 *   - php/php-src repository advisories (PHP runtime). The global DB does not
 *     import them: CVE-2026-109618 and friends are only here.
 *   - nodejs/security-wg vuln/core/index.json (Node.js core)
 *   - CERT-EU and CSIRT Italia (ACN) RSS feeds
 *
 * Every source is isolated: a failure is logged, recorded in `sources` with
 * ok:false, and the build goes on with whatever the other sources returned.
 *
 * Environment variables:
 *   GH_TOKEN / GITHUB_TOKEN – GitHub token (optional locally, raises rate limits)
 *   UNREVIEWED_DAYS         – unreviewed scan window in days   (default: 7)
 *   ALERT_HOURS             – alert window in hours            (default: 72)
 *   ADVISORIES_OUT_DIR      – output directory                 (default: data)
 *
 * Requires Node.js 22+ (native fetch). CI pins Node 24.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { resolve }                  from 'path';

const TOKEN           = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN ?? '';
const UNREVIEWED_DAYS = Number(process.env.UNREVIEWED_DAYS ?? 7);
const ALERT_HOURS     = Number(process.env.ALERT_HOURS ?? 72);
const OUT_DIR         = resolve(process.env.ADVISORIES_OUT_DIR ?? 'data');

const GH_API  = 'https://api.github.com';
const NODE_WG = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json';
const NODE_WG_LIMIT = 100;

const FEEDS = {
  'cert-eu': { label: 'CERT-EU',       url: 'https://cert.europa.eu/publications/security-advisories-rss' },
  'acn':     { label: 'CSIRT Italia',  url: 'https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192' },
};

const LARAVEL_PACKAGES = [
  'laravel/framework', 'laravel/laravel', 'laravel/sanctum', 'laravel/passport',
  'laravel/fortify', 'laravel/jetstream', 'laravel/socialite', 'laravel/horizon',
  'laravel/nova', 'laravel/cashier', 'laravel/breeze', 'laravel/telescope',
  'livewire/livewire',
];
const LARAVEL_PKG_RE = /^(laravel|illuminate|livewire)\//;

// Unreviewed advisory → category, matched on its references. The capture group
// becomes the "package" shown in the row.
const REF_RULES = [
  { cat: 'php',     re: /github\.com\/(php\/php-src)\b/i },
  { cat: 'nodejs',  re: /github\.com\/(nodejs\/node)(?:[/#?]|$)/i },
  { cat: 'nodejs',  re: /nodejs\.org\/[a-z-]*\/?blog\/vulnerability/i, pkg: 'nodejs/node' },
  { cat: 'laravel', re: /github\.com\/(laravel\/[\w.-]+)/i },
];

// Alert → category, matched on title + description (bulletins are free text).
const ALERT_RULES = [
  // Not after a dot: "file.php" in a bulletin about some CMS is not PHP itself.
  { cat: 'php',     re: /(?<!\.)\bphp(?![a-z])/i },
  { cat: 'nodejs',  re: /\bnode\.?js\b/i },
  { cat: 'npm',     re: /\bnpm\b/i },
  { cat: 'composer', re: /\bcomposer\b/i },
  { cat: 'laravel', re: /\blaravel\b/i },
  { cat: 'actions', re: /\bgithub actions?\b/i },
];

const SOURCE_RANK = { 'github-reviewed': 4, 'php-src': 3, 'nodejs-wg': 2, 'github-unreviewed': 1 };

const sources = {};

// ---------- helpers ----------

async function getJSON(url, { github = false } = {}) {
  const headers = { 'User-Agent': 'smzstudio-advisories' };
  if (github) {
    headers.Accept = 'application/vnd.github+json';
    headers['X-GitHub-Api-Version'] = '2022-11-28';
    if (TOKEN) { headers.Authorization = `Bearer ${TOKEN}`; }
  }
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) { throw new Error(`${res.status} ${res.statusText} — ${url}`); }
  return { body: await res.json(), link: res.headers.get('link') ?? '' };
}

function nextLink(link) {
  const m = link.match(/<([^>]+)>;\s*rel="next"/);
  return m ? m[1] : null;
}

async function track(name, fn) {
  try {
    const items = await fn();
    sources[name] = { ok: true, count: items.length };
    console.log(`✓ ${name}: ${items.length}`);
    return items;
  } catch (err) {
    sources[name] = { ok: false, error: String(err.message ?? err) };
    console.warn(`⚠ ${name}: ${err.message ?? err}`);
    return [];
  }
}

function sevFromScore(score) {
  if (score == null) { return 'unknown'; }
  if (score >= 9) { return 'critical'; }
  if (score >= 7) { return 'high'; }
  if (score >= 4) { return 'medium'; }
  if (score > 0)  { return 'low'; }
  return 'unknown';
}

function normSeverity(sev, score) {
  const s = String(sev ?? '').toLowerCase();
  if (s === 'moderate') { return 'medium'; }
  if (['critical', 'high', 'medium', 'low'].includes(s)) { return s; }
  return sevFromScore(score);
}

function cvssScore(cvss) {
  const v4 = cvss?.cvss_v4?.score;
  const v3 = cvss?.cvss_v3?.score;
  if (v4 > 0) { return v4; }
  if (v3 > 0) { return v3; }
  return null;
}

function oneLine(text, max = 240) {
  const s = String(text ?? '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

// ---------- GitHub Advisory DB ----------

function fromGithub(adv, source, categories, pkg) {
  const score = cvssScore(adv.cvss_severities);
  const patched = [...new Set((adv.vulnerabilities ?? [])
    .map(v => v.first_patched_version ?? v.patched_versions).filter(Boolean))];
  return {
    id: adv.cve_id || adv.ghsa_id,
    title: oneLine(adv.summary),
    pkg,
    categories,
    severity: normSeverity(adv.severity, score),
    cvss: score,
    published: adv.published_at,
    url: adv.html_url,
    cve: adv.cve_id || '',
    ghsa: adv.ghsa_id || '',
    patched: patched.join(', '),
    source,
  };
}

function reviewedCategories(adv, eco) {
  const cats = new Set([eco]);
  for (const v of adv.vulnerabilities ?? []) {
    if (v.package?.ecosystem === 'composer' && LARAVEL_PKG_RE.test(v.package.name ?? '')) {
      cats.add('laravel');
    }
  }
  return [...cats];
}

async function reviewed(eco, extra = '') {
  const url = `${GH_API}/advisories?type=reviewed&ecosystem=${eco}${extra}&per_page=100&sort=published&direction=desc`;
  const { body } = await getJSON(url, { github: true });
  return body.map(adv => fromGithub(adv, 'github-reviewed',
    reviewedCategories(adv, eco), adv.vulnerabilities?.[0]?.package?.name ?? ''));
}

async function unreviewed() {
  const to = new Date();
  const from = new Date(to.getTime() - UNREVIEWED_DAYS * 86_400_000);
  const day = d => d.toISOString().slice(0, 10);
  let url = `${GH_API}/advisories?type=unreviewed&published=${day(from)}..${day(to)}&per_page=100&sort=published&direction=desc`;
  const out = [];
  let pages = 0;
  while (url) {
    const { body, link } = await getJSON(url, { github: true });
    pages++;
    for (const adv of body) {
      const cats = new Set();
      let pkg = '';
      for (const ref of adv.references ?? []) {
        for (const rule of REF_RULES) {
          const m = ref.match(rule.re);
          if (m) {
            cats.add(rule.cat);
            pkg ||= rule.pkg ?? m[1].toLowerCase();
          }
        }
      }
      if (cats.size) { out.push(fromGithub(adv, 'github-unreviewed', [...cats], pkg)); }
    }
    url = nextLink(link);
  }
  console.log(`  unreviewed: ${pages} pages scanned`);
  return out;
}

async function phpSrc() {
  const url = `${GH_API}/repos/php/php-src/security-advisories?state=published&per_page=100&sort=published&direction=desc`;
  const { body } = await getJSON(url, { github: true });
  return body.map(adv => fromGithub(adv, 'php-src', ['php'], 'php/php-src'));
}

// ---------- nodejs/security-wg ----------

const MONTHS = ['january', 'february', 'march', 'april', 'may', 'june', 'july',
  'august', 'september', 'october', 'november', 'december'];

// Most entries have no date: the security release they belong to is named
// after its month in `ref` (".../july-2026-security-releases"), so that's the
// best date available. Rows show it as the first of the month.
function nodeWgDate(entry) {
  if (entry.publish_date) { return new Date(entry.publish_date).toISOString(); }
  const m = String(entry.ref ?? '').match(/\/([a-z]+)-(\d{4})-security-releases/i);
  if (m) {
    const month = MONTHS.indexOf(m[1].toLowerCase());
    if (month >= 0) { return new Date(Date.UTC(Number(m[2]), month, 1)).toISOString(); }
  }
  return null;
}

async function nodeWg() {
  const { body } = await getJSON(NODE_WG);
  return Object.entries(body)
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .slice(-NODE_WG_LIMIT)
    .map(([key, e]) => {
      const cve = (e.cve ?? [])[0] ?? '';
      const score = typeof e.cvss_score === 'number' ? e.cvss_score : null;
      return {
        id: cve || `nodejs-wg-${key}`,
        title: oneLine(e.description || e.overview),
        pkg: 'nodejs/node',
        categories: ['nodejs'],
        severity: normSeverity(e.severity, score),
        cvss: score,
        published: nodeWgDate(e),
        approx_date: !e.publish_date,
        url: e.ref || `https://github.com/nodejs/security-wg/blob/main/vuln/core/${key}.json`,
        cve,
        ghsa: '',
        patched: e.patched ?? '',
        source: 'nodejs-wg',
      };
    })
    .filter(it => it.published);
}

// ---------- merge ----------

function merge(lists) {
  const byId = new Map();
  for (const it of lists.flat()) {
    const prev = byId.get(it.id);
    if (!prev) { byId.set(it.id, it); continue; }
    const [hi, lo] = SOURCE_RANK[it.source] > SOURCE_RANK[prev.source] ? [it, prev] : [prev, it];
    byId.set(it.id, {
      ...hi,
      categories: [...new Set([...hi.categories, ...lo.categories])],
      cvss: hi.cvss ?? lo.cvss,
      severity: hi.severity === 'unknown' ? lo.severity : hi.severity,
      // An exact GitHub timestamp beats the month-only date from security-wg.
      ...(hi.approx_date && lo.published && !lo.approx_date
        ? { published: lo.published, approx_date: false } : {}),
      ghsa: hi.ghsa || lo.ghsa,
      patched: hi.patched || lo.patched,
    });
  }
  return [...byId.values()].sort((a, b) => String(b.published).localeCompare(String(a.published)));
}

// ---------- RSS alerts ----------

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decode(s) {
  return String(s ?? '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
      if (e[0] === '#') {
        const code = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : m;
      }
      return ENTITIES[e.toLowerCase()] ?? m;
    });
}

function stripTags(s) {
  return decode(s).replace(/<[^>]+>/g, ' ');
}

function tag(xml, name) {
  const m = xml.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
  return m ? m[1].trim() : '';
}

// RSS pubDate uses RFC 822 zone names that Date.parse doesn't know (CEST).
const ZONES = { CET: '+0100', CEST: '+0200', GMT: '+0000', UTC: '+0000', UT: '+0000' };

function parseDate(s) {
  const fixed = String(s ?? '').trim().replace(/\b(CEST|CET|GMT|UTC|UT)$/, z => ZONES[z]);
  const t = Date.parse(fixed);
  return Number.isNaN(t) ? null : new Date(t);
}

async function feed(key) {
  const { label, url } = FEEDS[key];
  const res = await fetch(url, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; smzstudio-advisories)' },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) { throw new Error(`${res.status} ${res.statusText} — ${url}`); }
  const xml = await res.text();
  const items = [...xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)].map(m => m[1]);
  if (!items.length && !/<rss\b/i.test(xml)) { throw new Error(`not an RSS feed — ${url}`); }
  const since = Date.now() - ALERT_HOURS * 3_600_000;
  return items.map(x => {
    const date = parseDate(tag(x, 'dc:date')) ?? parseDate(tag(x, 'pubDate'));
    const title = oneLine(stripTags(tag(x, 'title')), 200);
    const description = oneLine(stripTags(tag(x, 'description')), 400);
    const text = `${title} ${description}`;
    return {
      title,
      description,
      url: decode(tag(x, 'link')).trim(),
      published: date?.toISOString() ?? null,
      source: label,
      categories: [...new Set(ALERT_RULES.filter(r => r.re.test(text)).map(r => r.cat))],
    };
  }).filter(a => a.published && Date.parse(a.published) >= since);
}

// ---------- main ----------

const lists = await Promise.all([
  track('github-reviewed:npm',      () => reviewed('npm')),
  track('github-reviewed:composer', () => reviewed('composer')),
  track('github-reviewed:actions',  () => reviewed('actions')),
  track('github-reviewed:laravel',  () => reviewed('composer', `&affects=${LARAVEL_PACKAGES.join(',')}`)),
  track('php-src',                  () => phpSrc()),
  track('nodejs-wg',                () => nodeWg()),
  track('github-unreviewed',        () => unreviewed()),
]);
const vulns = merge(lists);

const alertLists = await Promise.all(Object.keys(FEEDS).map(k => track(`rss:${k}`, () => feed(k))));
const alerts = alertLists.flat().sort((a, b) => b.published.localeCompare(a.published));

const generated = new Date().toISOString();
const vulnSources = Object.fromEntries(Object.entries(sources).filter(([k]) => !k.startsWith('rss:')));
const alertSources = Object.fromEntries(Object.entries(sources).filter(([k]) => k.startsWith('rss:')));

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(resolve(OUT_DIR, 'vulns.json'),
  JSON.stringify({ generated, window_days: UNREVIEWED_DAYS, sources: vulnSources, items: vulns }));
writeFileSync(resolve(OUT_DIR, 'alerts.json'),
  JSON.stringify({ generated, window_hours: ALERT_HOURS, sources: alertSources, items: alerts }));

const perCat = {};
for (const v of vulns) { for (const c of v.categories) { perCat[c] = (perCat[c] ?? 0) + 1; } }
console.log(`→ ${vulns.length} vulns`, perCat);
console.log(`→ ${alerts.length} alerts (${alerts.filter(a => a.categories.length).length} relevant)`);
