import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert';

// Il modello gira con una finestra di 4096 token. Il corpus entra per intero nel system
// prompt, quindi ciò che occupa lo toglie alla conversazione: sopra i 1500 token la chat
// inizia a sollevare ContextWindowSizeExceededError invece di degradare.
// Stima prudente per l'italiano: ~1.9 token per parola.
const MAX_TOKENS = 1500;
const TOKENS_PER_WORD = 1.9;

const corpus = () =>
  readFileSync(new URL('../assets/data/cv.md', import.meta.url), 'utf8');

test('il corpus del CV sta nel budget di contesto', () => {
  const words = corpus().trim().split(/\s+/).length;
  const estimated = Math.round(words * TOKENS_PER_WORD);
  assert.ok(
    estimated <= MAX_TOKENS,
    `corpus stimato ${estimated} token (${words} parole), budget ${MAX_TOKENS}`,
  );
});

test('il corpus non contiene artefatti di impaginazione', () => {
  assert.ok(!/Page \d+ of \d+/.test(corpus()), 'residui di impaginazione del PDF');
});

test('il corpus contiene i riferimenti di contatto', () => {
  const text = corpus();
  for (const ref of ['linkedin.com/in/saveriomenin', 'github.com/savez',
                     'medium.com/@savezzo', 'app.daily.dev/savez']) {
    assert.ok(text.includes(ref), `manca il riferimento ${ref}`);
  }
});
