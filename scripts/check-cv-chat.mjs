import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createContext, runInContext } from 'node:vm';

const source = readFileSync(new URL('../assets/js/cv-chat.js', import.meta.url), 'utf8')
  .replace(/^import .* from "__WEBLLM__";$/m, '')
  .replace('if (root && corpusEl) {', 'if (false) {');

class Element {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.listeners = {};
    this.textContent = '';
    this.value = '';
  }
  append(...nodes) {
    for (const node of nodes) {
      if (typeof node === 'object') node.parentElement = this;
      this.children.push(node);
    }
  }
  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }
  setAttribute() {}
  addEventListener(type, listener) { this.listeners[type] = listener; }
  focus() { this.focused = true; }
}

function setup({ failures = [], resetFailure, loadFailure } = {}) {
  const root = new Element('div');
  root.dataset.worker = '/worker.js';
  const badge = new Element('p');
  const corpus = { textContent: JSON.stringify('Saverio lavora con il cloud.') };
  const workers = [];
  const engines = [];
  const context = createContext({
    document: {
      querySelector: () => root,
      getElementById: (id) => id === 'cv-corpus' ? corpus : badge,
      createElement: (tag) => new Element(tag),
    },
    navigator: { userAgent: 'Chrome Android' },
    console: { error() {}, warn() {} },
    Worker: class {
      constructor() { workers.push(this); }
      addEventListener() {}
      terminate() { this.terminated = true; }
    },
    CreateWebWorkerMLCEngine: async () => {
      if (loadFailure) throw loadFailure;
      const engine = {
        calls: [],
        resets: 0,
        resetChat: async () => {
          engine.resets++;
          if (resetFailure) throw resetFailure;
        },
        chat: { completions: { create: async (options) => {
          engine.calls.push(options);
          const failure = failures.shift();
          return (async function* () {
            yield { choices: [{ delta: { content: 'Saverio ' } }] };
            if (failure) throw failure;
            yield { choices: [{ delta: { content: 'lavora con il cloud.' } }] };
          })();
        } } },
      };
      engines.push(engine);
      return engine;
    },
  });
  function evaluate(code) { return runInContext(code, context); }
  runInContext(source, context);
  async function submit(question = 'Che esperienza ha con il cloud?') {
    const [, ask] = root.children;
    ask.children[0].value = question;
    await ask.children[1].listeners.click();
  }
  return { root, workers, engines, evaluate, submit };
}

for (const message of [
  "AbortError: Failed to execute 'mapAsync' on 'GPUBuffer': Buffer was unmapped before mapping was resolved.",
  'The current Object has already been disposed',
  'Device was lost',
]) {
  test(`un errore GPU ferma il motore e Riprova crea un nuovo worker: ${message}`, async () => {
    const chat = setup({ failures: [new Error(message)] });
    await chat.evaluate('start()');
    const oldInput = chat.root.children[1].children[0];
    oldInput.focused = false;
    await chat.submit();

    assert.equal(chat.root.dataset.state, 'error');
    assert.equal(chat.workers[0].terminated, true);
    assert.equal(chat.evaluate('engine'), null);
    assert.equal(chat.engines[0].resets, 0);
    assert.equal(chat.engines[0].calls.length, 1);
    assert.equal(oldInput.focused, false);
    assert.ok(chat.root.children[1].children[1].textContent.includes(message));

    await chat.root.children[2].listeners.click();
    assert.equal(chat.root.dataset.state, 'ready');
    assert.equal(chat.workers.length, 2);
    await chat.submit();
    assert.equal(chat.engines[1].calls.length, 1);
    assert.equal(chat.engines[1].calls[0].messages.length, 2);
  });
}

test('gli errori non GPU consentono ancora un solo tentativo con parametri minimi', async () => {
  const chat = setup({ failures: [new Error('parametro non supportato')] });
  await chat.evaluate('start()');
  await chat.submit();
  assert.equal(chat.root.dataset.state, 'ready');
  assert.equal(chat.engines[0].resets, 1);
  assert.equal(chat.engines[0].calls.length, 2);
  assert.equal(chat.engines[0].calls[1].frequency_penalty, undefined);
  assert.ok(!chat.workers[0].terminated);
});

test('un errore GPU nel reset conserva entrambi gli errori e non ritenta', async () => {
  const chat = setup({
    failures: [new Error('parametro non supportato')],
    resetFailure: new Error('The current Object has already been disposed'),
  });
  await chat.evaluate('start()');
  await chat.submit();
  assert.equal(chat.root.dataset.state, 'error');
  assert.equal(chat.engines[0].calls.length, 1);
  const diagnostics = chat.root.children[1].children[1].textContent;
  assert.ok(diagnostics.includes('parametro non supportato'));
  assert.ok(diagnostics.includes('already been disposed'));
});

test('gli errori GPU serializzati dal worker sono riconosciuti come fatali', async () => {
  for (const message of [
    "AbortError: Failed to execute 'mapAsync' on 'GPUBuffer'",
    'Error: The current Object has already been disposed',
    'Error: Device was lost',
  ]) {
    const chat = setup({ failures: [message] });
    await chat.evaluate('start()');
    await chat.submit();
    assert.equal(chat.root.dataset.state, 'error');
    assert.equal(chat.engines[0].resets, 0);
    assert.equal(chat.engines[0].calls.length, 1);
    assert.equal(chat.workers[0].terminated, true);
  }
});

test('un errore GPU nel secondo tentativo termina il worker', async () => {
  const chat = setup({ failures: [new Error('parametro non supportato'), new Error('GPUBuffer')] });
  await chat.evaluate('start()');
  await chat.submit();
  assert.equal(chat.root.dataset.state, 'error');
  assert.equal(chat.engines[0].calls.length, 2);
  assert.equal(chat.workers[0].terminated, true);
});

test('un caricamento fallito termina il worker', async () => {
  const chat = setup({ loadFailure: new Error('download fallito') });
  await chat.evaluate('start()');
  assert.equal(chat.root.dataset.state, 'error');
  assert.equal(chat.workers[0].terminated, true);
  assert.equal(chat.evaluate('engine'), null);
});

test('due avvii simultanei non creano due worker', async () => {
  const chat = setup();
  await chat.evaluate('Promise.all([start(), start()])');
  assert.equal(chat.workers.length, 1);
  assert.equal(chat.root.dataset.state, 'ready');
});

test('un errore di contesto non elimina il motore e svuota la cronologia', async () => {
  const chat = setup({ failures: [null, new Error('context window size exceeded')] });
  await chat.evaluate('start()');
  await chat.submit();
  await chat.submit();
  assert.equal(chat.root.dataset.state, 'ready');
  assert.equal(chat.engines[0].resets, 0);
  assert.ok(!chat.workers[0].terminated);
  await chat.submit();
  assert.equal(chat.engines[0].calls[2].messages.length, 2);
});

test('le domande fuori tema non arrivano al modello', async () => {
  const chat = setup();
  await chat.evaluate('start()');
  await chat.submit('Scrivimi una poesia');
  assert.equal(chat.engines[0].calls.length, 0);
  assert.equal(chat.root.dataset.state, 'ready');
});

test('gli errori di contesto serializzati non fanno ritentare la generazione', async () => {
  const chat = setup({ failures: ['Error: context window size exceeded'] });
  await chat.evaluate('start()');
  await chat.submit();
  assert.equal(chat.root.dataset.state, 'ready');
  assert.equal(chat.engines[0].calls.length, 1);
  assert.equal(chat.engines[0].resets, 0);
  assert.ok(!chat.workers[0].terminated);
});
