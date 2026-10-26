// /advisories/check/ — reads a dependency file in the browser and matches it
// against the advisory dataset. Nothing the visitor provides leaves the page:
// the only network request is the dataset JSON, from this same site.
//
// Every string that comes from the visitor's file (package names, versions)
// is written with textContent, never innerHTML.

import { parse } from './parsers.mjs';
import { match, summarize, toMarkdown } from './match.mjs';

const root = document.getElementById('chk');
if (root) { init(root); }

const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' };
const ERRORS = {
  'unknown-format': 'Formato non riconosciuto. Supportati: composer.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, composer.json, package.json.',
  'invalid-json': 'Il file non è un JSON valido: controlla di averlo copiato per intero.',
  'no-deps': 'Nel file non ho trovato dipendenze da controllare.',
  'db-missing': 'Il dataset delle advisory per questo ecosistema non è disponibile in questo momento. Riprova più tardi.',
};

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) { continue; }
    if (k === 'class') { n.className = v; } else if (k === 'text') { n.textContent = v; } else { n.setAttribute(k, v); }
  }
  for (const c of children.flat()) { if (c != null) { n.append(c); } }
  return n;
}

function init(root) {
  const $ = sel => root.querySelector(sel);
  const form = $('.chk-input');
  const drop = $('.chk-drop');
  const fileInput = $('#chk-file');
  const textarea = $('#chk-text');
  const status = $('.chk-status');
  const results = $('.chk-results');
  const list = $('.chk-list');
  const empty = $('.chk-empty');
  const unver = $('.chk-unverifiable');
  const eyebrowFile = document.querySelector('.chk-eyebrow-file');
  const toggles = {
    direct: root.querySelector('[data-filter="direct"]'),
    dev: root.querySelector('[data-filter="dev"]'),
  };

  const dbCache = {};
  let state = null; // { parsed, result, generated }

  function setStatus(msg, kind = '') {
    status.hidden = !msg;
    status.textContent = msg || '';
    status.className = `chk-status mono${kind ? ` is-${kind}` : ''}`;
  }

  async function loadDb(eco) {
    if (dbCache[eco]) { return dbCache[eco]; }
    const url = root.dataset[`db${eco[0].toUpperCase()}${eco.slice(1)}`];
    if (!url) { throw new Error('db-missing'); }
    const res = await fetch(url);
    if (!res.ok) { throw new Error('db-missing'); }
    dbCache[eco] = await res.json();
    return dbCache[eco];
  }

  async function run(text, filename) {
    results.hidden = true;
    let parsed;
    try {
      parsed = parse(text, filename);
      if (!parsed.deps.length) { throw new Error('no-deps'); }
    } catch (err) {
      setStatus(ERRORS[err.message] ?? ERRORS['unknown-format'], 'error');
      return;
    }
    if (eyebrowFile) { eyebrowFile.textContent = `./${parsed.format}`; }
    setStatus(`${parsed.format} · ${parsed.deps.length} pacchetti · carico il dataset ${parsed.ecosystem}…`);

    let db;
    try {
      db = await loadDb(parsed.ecosystem);
    } catch {
      setStatus(ERRORS['db-missing'], 'error');
      return;
    }
    const result = match(parsed.deps, db, parsed.ecosystem);
    state = { parsed, result, generated: db.generated };
    setStatus('');
    render();
    // On a phone the results start below the fold: bring them up.
    const smooth = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    results.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
  }

  function visible() {
    const { parsed, result } = state;
    const onlyDirect = toggles.direct.querySelector('input').checked;
    const withDev = toggles.dev.querySelector('input').checked;
    const keep = d => (!onlyDirect || d.direct === true) && (withDev || d.dev !== true);
    return {
      findings: result.findings.filter(keep),
      unverifiable: result.unverifiable.filter(keep),
      checked: parsed.deps.filter(keep).length - result.unverifiable.filter(keep).length,
    };
  }

  function render() {
    const { parsed } = state;
    // Filters only make sense when the file says who is direct / dev.
    toggles.direct.hidden = !parsed.deps.some(d => d.direct === true);
    toggles.dev.hidden = !parsed.deps.some(d => d.dev === true);

    const { findings, unverifiable, checked } = visible();
    const sum = summarize(findings);

    $('.chk-summary-line').textContent =
      `${parsed.format} · ${checked} pacchetti controllati · ${findings.length} ${findings.length === 1 ? 'vulnerabile' : 'vulnerabili'}` +
      (parsed.deps.some(d => !d.exact) ? ' · range: risultati possibili' : '');
    const sevBox = $('.chk-summary-sev');
    sevBox.replaceChildren(...Object.entries(sum.bySeverity).filter(([, n]) => n).map(([s, n]) =>
      el('span', { class: `chk-sev-count sev-${s}` }, el('span', { class: 'adv-dot', 'aria-hidden': 'true' }), `${n} ${s}`)));

    list.replaceChildren(...findings.map(renderFinding));
    empty.hidden = findings.length > 0;
    empty.textContent = `Nessuna advisory nota per queste versioni (dataset del ${String(state.generated).slice(0, 10)}).`;

    unver.hidden = !unverifiable.length;
    unver.querySelector('summary').textContent = `${unverifiable.length} ${unverifiable.length === 1 ? 'pacchetto non verificabile' : 'pacchetti non verificabili'}`;
    unver.querySelector('ul').replaceChildren(...unverifiable.map(d => el('li', { text: `${d.name} ${d.version}` })));

    results.hidden = false;
  }

  function renderFinding(f) {
    const tags = [];
    if (f.certainty === 'possible') { tags.push(el('span', { class: 'chk-tag is-possible', text: 'possibile', title: `range ${f.version}: controllata la versione minima ${f.tested}` })); }
    if (f.direct === false) { tags.push(el('span', { class: 'chk-tag', text: 'indiretta' })); }
    if (f.dev === true) { tags.push(el('span', { class: 'chk-tag', text: 'dev' })); }

    const fix = f.fixVersion
      ? el('span', { class: 'chk-fix' }, '→ aggiorna a ', el('strong', { text: `≥ ${f.fixVersion}` }))
      : el('span', { class: 'chk-fix is-none', text: '→ nessuna versione corretta disponibile' });

    return el('article', { class: 'adv-row chk-row' },
      el('div', { class: `adv-sev sev-${f.severity}` },
        el('span', { class: 'adv-badge mono' }, el('span', { class: 'adv-dot', 'aria-hidden': 'true' }), ` ${SEV_LABEL[f.severity]}`),
        el('span', { class: 'adv-cvss mono', title: 'CVSS massimo', text: f.cvss ? f.cvss.toFixed(1) : '—' }),
        el('span', { class: 'adv-date mono', text: `${f.advisories.length} advisory` })),
      el('div', { class: 'adv-body' },
        el('div', { class: 'chk-head' },
          el('span', { class: 'adv-pkg mono', text: f.name }),
          el('span', { class: 'chk-version mono', text: f.version }),
          ...tags),
        el('p', { class: 'chk-fixline mono' }, fix),
        el('ul', { class: 'chk-advs' }, ...f.advisories.map(renderAdvisory))));
  }

  function renderAdvisory(a) {
    const links = [
      el('a', { href: `https://github.com/advisories/${a.id}`, target: '_blank', rel: 'noopener', text: a.id }),
    ];
    if (a.cve) { links.push(el('a', { href: `https://nvd.nist.gov/vuln/detail/${a.cve}`, target: '_blank', rel: 'noopener', text: a.cve })); }
    links.push(el('span', { class: 'adv-fix', text: a.fixed ? `fix ≥ ${a.fixed}` : 'nessuna patch' }));
    if (a.mitig?.length) {
      links.push(el('span', { class: 'adv-mitig' }, 'mitigazione: ',
        ...a.mitig.flatMap((m, i) => [i ? ' · ' : null,
          el('a', { href: m.url, target: '_blank', rel: 'noopener', text: `${m.src === 'CSIRT Italia' ? 'ACN' : m.src} ${m.date.slice(8, 10)}/${m.date.slice(5, 7)} ↗` })])));
    }
    return el('li', { class: `chk-adv sev-${a.sev}` },
      el('span', { class: 'adv-dot', 'aria-hidden': 'true', title: a.sev }),
      el('div', {},
        el('p', { class: 'chk-adv-title', text: a.title }),
        el('div', { class: 'adv-meta mono' }, ...links)));
  }

  function reset() {
    state = null;
    results.hidden = true;
    setStatus('');
    textarea.value = '';
    fileInput.value = '';
    if (eyebrowFile) { eyebrowFile.textContent = './composer.lock'; }
    drop.focus?.();
  }

  // ---------- input ----------

  function readFile(file) {
    if (!file) { return; }
    if (file.size > 20 * 1024 * 1024) { setStatus('File troppo grande (oltre 20 MB).', 'error'); return; }
    const reader = new FileReader();
    reader.onload = () => run(String(reader.result), file.name);
    reader.onerror = () => setStatus('Non riesco a leggere il file.', 'error');
    reader.readAsText(file);
  }

  fileInput.addEventListener('change', () => readFile(fileInput.files[0]));

  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault();
    drop.classList.add('is-over');
  }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault();
    drop.classList.remove('is-over');
  }));
  drop.addEventListener('drop', e => readFile(e.dataTransfer?.files?.[0]));

  form.addEventListener('submit', e => {
    e.preventDefault();
    if (textarea.value.trim()) { run(textarea.value, ''); }
  });

  Object.values(toggles).forEach(t => t.querySelector('input').addEventListener('change', () => { if (state) { render(); } }));

  root.querySelector('.chk-reset').addEventListener('click', reset);

  root.querySelector('.chk-copy').addEventListener('click', async e => {
    if (!state) { return; }
    const v = visible();
    const md = toMarkdown({ format: state.parsed.format, ...v, generated: state.generated, pageUrl: root.dataset.pageUrl });
    const btn = e.currentTarget;
    try {
      await navigator.clipboard.writeText(md);
      btn.textContent = 'report copiato';
    } catch {
      btn.textContent = 'copia non riuscita';
    }
    setTimeout(() => { btn.textContent = 'copia report markdown'; }, 2000);
  });
}
