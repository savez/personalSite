// Chat sul CV, interamente nel browser.
// Il modello viene scaricato sul dispositivo del visitatore ed eseguito lì: nessuna domanda
// esce dalla pagina. Il corpus del CV è nel tag <script id="cv-corpus"> e finisce per intero
// nel system prompt, che con una finestra da 4096 token è il vincolo che governa tutto.

// La libreria è vendorizzata: vedi assets/js/vendor/. Il percorso lo riscrive Hugo.
import { CreateWebWorkerMLCEngine, hasModelInCache } from "__WEBLLM__";

const MODEL_ID = "Qwen3-1.7B-q4f32_1-MLC";
const MODEL_MB = 985;
const MODEL_LABEL = "Qwen3 1.7B";
const MODEL_QUANT = "quantizzato a 4 bit";
const MODEL_CARD = "https://huggingface.co/Qwen/Qwen3-1.7B";
const LINKEDIN = "https://www.linkedin.com/in/saveriomenin/";

// Finestra da 4096 token: il corpus ne occupa ~950, il resto è la conversazione.
const MAX_TURNS = 3; // coppie domanda/risposta tenute vive
const MAX_QUESTION_CHARS = 400;

const REFUSAL =
  "Questa informazione non è nel CV di Saverio. Posso rispondere su esperienze, ruoli, tecnologie, formazione e contatti.";

const BLOCKED_REASONS = {
  "no-webgpu":
    "Questa chat ha bisogno di WebGPU, che il tuo browser non espone. Funziona su Chrome, Edge e Safari recenti da computer.",
  firefox:
    "Su Firefox WebGPU c'è, ma l'inferenza è circa cinquanta volte più lenta che su Chrome: la chat sarebbe inutilizzabile, quindi preferisco non avviarla.",
  ios: "Su iPhone e iPad la memoria che Safari concede a una scheda non basta a caricare il modello.",
  "no-adapter":
    "Il browser espone WebGPU ma non riesce ad aprire una scheda grafica utilizzabile.",
  "small-gpu":
    "La scheda grafica di questo dispositivo non ha abbastanza memoria per il modello.",
};

const EXAMPLES = [
  "Di cosa si occupa oggi?",
  "Che esperienza ha con il cloud?",
  "Come posso contattarlo?",
];

const root = document.querySelector(".cv-chat");
const corpusEl = document.getElementById("cv-corpus");

// ---------------------------------------------------------------- supporto

async function checkSupport() {
  const ua = navigator.userAgent;
  // Firefox e iOS sono esclusi di proposito, non per mancanza di WebGPU: su Firefox
  // l'inferenza gira a ~1 token/secondo contro ~52 su Chrome, e su iOS la memoria per
  // scheda sta sotto i 500 MB mentre WebLLM materializza il modello nell'heap JS.
  if (/firefox/i.test(ua)) return { ok: false, reason: "firefox" };
  if (/iPhone|iPad|iPod/.test(ua)) return { ok: false, reason: "ios" };
  if (!navigator.gpu) return { ok: false, reason: "no-webgpu" };

  const adapter = await navigator.gpu.requestAdapter().catch(() => null);
  if (!adapter) return { ok: false, reason: "no-adapter" };
  if (adapter.limits.maxStorageBufferBindingSize < 1 << 30) {
    return { ok: false, reason: "small-gpu" };
  }
  return { ok: true };
}

// ------------------------------------------------------------------- stati

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function setState(state, nodes) {
  root.dataset.state = state;
  root.replaceChildren(...nodes);
}

// Il modello in esecuzione resta sempre dichiarato, in ogni stato: chi legge deve poter
// sapere cosa gli sta girando nel browser senza aprire gli strumenti da sviluppatore.
const MODEL_STATUS = {
  checking: "controllo del dispositivo in corso",
  idle: "non ancora caricato",
  loading: "caricamento in corso",
  ready: "in esecuzione nel tuo browser",
  error: "caricamento non riuscito",
  blocked: "non avviabile su questo dispositivo",
};

function setModelBadge(state) {
  const badge = document.getElementById("cv-model");
  if (!badge) return;
  badge.replaceChildren();
  badge.append("modello: ");
  const link = el("a", null, MODEL_LABEL);
  link.href = MODEL_CARD;
  link.target = "_blank";
  link.rel = "noopener";
  badge.append(link, ` (${MODEL_QUANT}) · ${MODEL_STATUS[state] || state}`);
  badge.dataset.modelState = state;
}

function linkedinLine() {
  const p = el("p", "cv-fallback");
  p.append("Il curriculum completo è su ");
  const a = el("a", null, "LinkedIn");
  a.href = LINKEDIN;
  a.target = "_blank";
  a.rel = "noopener";
  p.append(a, ".");
  return p;
}

function showBlocked(reason) {
  setModelBadge("blocked");
  setState("blocked", [
    el("p", "cv-blocked", BLOCKED_REASONS[reason] || BLOCKED_REASONS["no-webgpu"]),
    linkedinLine(),
  ]);
}

async function showWelcome() {
  const cached = await hasModelInCache(MODEL_ID).catch(() => false);

  const nodes = [
    el("p", "cv-intro-title mono", "// tutto nel tuo browser"),
    el(
      "p",
      null,
      "Questa chat risponde a domande sul mio curriculum: esperienze, ruoli, tecnologie, formazione, contatti. Fuori da lì non risponde.",
    ),
    el(
      "p",
      null,
      "Il modello — Qwen3, 0,6 miliardi di parametri — viene scaricato sul tuo dispositivo ed eseguito lì. Le domande non escono dal browser: non arrivano a un server, nemmeno al mio, e nessuno le registra.",
    ),
  ];

  if (!cached) {
    nodes.push(
      el(
        "p",
        "cv-note",
        `Al primo avvio scarica circa ${MODEL_MB} MB, poi resta in cache e le volte successive parte subito.`,
      ),
    );
  } else {
    nodes.push(el("p", "cv-note", "Il modello è già sul tuo dispositivo: parte subito."));
  }

  const button = el(
    "button",
    "cv-start",
    cached ? "Avvia la chat" : `Avvia la chat — scarica ~${MODEL_MB} MB`,
  );
  button.type = "button";
  button.addEventListener("click", () => start());
  nodes.push(button);

  setModelBadge("idle");
  setState("idle", nodes);
}

function showLoading() {
  const fill = el("span");
  const bar = el("div", "cv-bar");
  bar.append(fill);
  const status = el("p", "cv-progress", "Preparo il modello…");
  status.setAttribute("aria-live", "polite");

  setModelBadge("loading");
  setState("loading", [
    bar,
    status,
    el("p", "cv-note", "Succede solo la prima volta: dalla prossima visita parte subito."),
  ]);

  return (report) => {
    // report.text della libreria è in inglese: su una pagina in italiano stona, e i
    // suoi dettagli ("Fetching param cache[3/9]") non dicono niente a chi legge.
    const pct =
      typeof report.progress === "number" && report.progress > 0
        ? Math.round(report.progress * 100)
        : null;
    if (pct !== null) fill.style.width = `${pct}%`;
    status.textContent =
      pct === null
        ? "Preparo il modello…"
        : pct < 100
          ? `Scarico il modello… ${pct}%`
          : "Ci siamo, preparo il modello…";
  };
}

function showError(message, retry) {
  const button = el("button", "cv-start", "Riprova");
  button.type = "button";
  button.addEventListener("click", retry);
  setModelBadge("error");
  setState("error", [el("p", "cv-blocked", message), button, linkedinLine()]);
}

// -------------------------------------------------------------- avvio motore

let engine = null;

async function start() {
  const onProgress = showLoading();
  try {
    const worker = new Worker(root.dataset.worker, { type: "module" });

    // Se il worker muore (CSP, WebAssembly bloccata, import fallito) nessuno rifiuta la
    // promise: il main thread resterebbe in attesa per sempre. Lo trasformiamo in errore.
    const workerDied = new Promise((_, reject) => {
      worker.addEventListener("error", (event) =>
        reject(new Error(`worker: ${event.message || "caricamento fallito"}`)),
      );
    });

    engine = await Promise.race([
      CreateWebWorkerMLCEngine(worker, MODEL_ID, { initProgressCallback: onProgress }),
      workerDied,
    ]);
    // Best effort: su Chrome e Firefox tiene la cache al riparo dagli sfratti,
    // su Safari una pagina normale non ottiene la persistenza.
    if (navigator.storage && navigator.storage.persist) {
      navigator.storage.persist().catch(() => {});
    }
    showConversation();
  } catch (err) {
    console.error(err);
    showError(
      "Il caricamento del modello non è riuscito. Può succedere se la connessione si è interrotta a metà.",
      () => start(),
    );
  }
}

// ------------------------------------------------------------ conversazione

// ------------------------------------------------------- perimetro (nel codice)

// Il prompt di sistema chiede al modello di rifiutare fuori tema, ma è una richiesta, non un
// vincolo: alla prova ha scritto poesie e ha dichiarato che la capitale della Francia è Parma.
// Questo filtro decide PRIMA di interpellare il modello, quindi il rifiuto non dipende dalla
// sua buona volontà. È una euristica lessicale: può rifiutare una domanda legittima formulata
// con parole che non compaiono nel CV, ed è il verso giusto in cui sbagliare.

const STOPWORDS = new Set([
  "come", "cosa", "quale", "quali", "quando", "dove", "chi", "perche", "perché", "quanto",
  "quanti", "quante", "della", "delle", "degli", "dello", "nella", "nelle", "negli", "sono",
  "essere", "avere", "fare", "puoi", "potresti", "dimmi", "parlami", "vorrei", "sapere",
  "questo", "questa", "quello", "quella", "anche", "molto", "tutto", "tutti", "oggi",
]);

// Richieste che non riguardano il CV anche quando contengono una parola che c'è nel CV:
// "che tempo fa a Milano" ha "Milano" dentro, ma non è una domanda sul curriculum.
const OFF_TOPIC = /\b(poesi\w*|poem\w*|raccont\w*|romanz\w*|barzellett\w*|ricett\w*|meteo|previsioni|che tempo fa|capitale|traduc\w*|calcol\w*|risolv\w*|scriv\w+mi|inventa|immagina|gioc\w*|canzon\w*|film|ristorant\w*|oroscop\w*)\b/i;

// Parole con cui si parla di un curriculum ma che nel CV possono non comparire:
// senza questo elenco "di cosa si occupa?" verrebbe rifiutata, ed è una delle domande
// di esempio che la pagina stessa suggerisce.
const CV_TERMS = [
  "occupa", "occupato", "occupazione", "mansione", "mansioni", "incarico", "incarichi",
  "carriera", "percorso", "curriculum", "profilo", "assunto", "datore", "colleghi",
  "seniority", "background", "skill", "skills", "capacita", "capacità", "bravo",
];

function buildVocabulary(corpus) {
  const words = corpus.toLowerCase().match(/[a-zàèéìòù0-9]{4,}/g) || [];
  return new Set([...words, ...CV_TERMS]);
}

// Domande che riguardano il CV per forza, ma che possono non contenere nessuna parola
// del CV: "chi sono?" è fatta di due parole corte e finiva rifiutata.
const ALWAYS_OK =
  /\b(chi (sono|sei|e|è)|chi e |presentati|parlami|raccontami|dimmi di|di cosa si occupa|cosa fa|che fa|cosa sa fare|punti di forza|in sintesi|riassumi|curriculum|\bcv\b)/i;

function isAboutCv(question, vocabulary) {
  if (OFF_TOPIC.test(question)) return false;
  if (ALWAYS_OK.test(question)) return true;
  const words = (question.toLowerCase().match(/[a-zàèéìòù0-9]{3,}/g) || [])
    .filter((w) => !STOPWORDS.has(w));
  if (!words.length) return false;
  // Basta una parola piena in comune col CV: chiedere "che lingue parla?" deve passare.
  return words.some((w) => vocabulary.has(w) || [...vocabulary].some((v) => v.startsWith(w.slice(0, 5))));
}


function buildSystemPrompt(corpus) {
  // Questa stringa non deve cambiare tra un turno e l'altro: WebLLM riusa la KV cache
  // del system prompt solo se resta identica, altrimenti riprefilla tutto il CV.
  return `Sei l'assistente del curriculum di Saverio Menin. Il tuo unico compito è rispondere a
domande sul CV riportato qui sotto.

REGOLE:
1. Usa solo le informazioni scritte nel CV. Non aggiungere niente di tuo.
2. Se la domanda non riguarda il CV di Saverio, rispondi SOLO con questa frase, senza aggiungere
   altro: "${REFUSAL}"
3. Non scrivere poesie, racconti, codice, ricette o testi creativi. Non rispondere a domande di
   cultura generale, meteo, attualità o opinioni. Per tutte queste richieste usa la frase della
   regola 2.
4. Non calcolare date né durate: se una durata ti serve, è già scritta nel CV. Copiala.
5. Rispondi sempre in italiano, in due o tre frasi al massimo.
6. Parla di Saverio in terza persona ("Saverio ha...", "ha lavorato..."), mai in prima.
7. Se ti chiedono le esperienze, i lavori o i contatti, elencali TUTTI, uno per riga, con i
   dati completi. Non riassumere e non fermarti al primo.
8. Se la domanda contiene "altre", "altri", "ancora" o "prima", cita solo le aziende che non
   hai ancora nominato nella conversazione. Se le hai nominate tutte, dillo.

--- CV ---
${corpus}
--- FINE CV ---`;
}

// Se il modello ragiona comunque ad alta voce, il ragionamento non deve arrivare in pagina.
// E il Markdown che produce va reso leggibile senza costruire HTML: il testo arriva da un
// modello, quindi resta testo, e la formattazione la fa il CSS con white-space: pre-wrap.
function visible(text) {
  return text
    .replace(/<think>[\s\S]*?<\/think>/g, "")
    .replace(/<think>[\s\S]*$/g, "")
    .replace(/\s+-\s+(?=\S)/g, "\n· ")
    .replace(/^\s*[-*]\s+/gm, "· ")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/\*/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function showConversation() {
  const log = el("div", "cv-log");
  log.setAttribute("aria-live", "polite");

  const input = el("input", null);
  input.type = "text";
  input.placeholder = "Fai una domanda sul CV…";
  input.setAttribute("aria-label", "Fai una domanda sul CV");
  input.maxLength = MAX_QUESTION_CHARS;

  const send = el("button", "cv-send", "Invia");
  send.type = "button";

  const ask = el("div", "cv-ask");
  ask.append(input, send);

  const examples = el("div", "cv-examples");
  for (const text of EXAMPLES) {
    const button = el("button", "cv-example", text);
    button.type = "button";
    button.addEventListener("click", () => {
      input.value = text;
      submit();
    });
    examples.append(button);
  }

  setModelBadge("ready");
  setState("ready", [log, ask, examples]);

  const corpus = JSON.parse(corpusEl.textContent);
  const system = buildSystemPrompt(corpus);
  const vocabulary = buildVocabulary(corpus);
  let history = [];
  let busy = false;

  function addMessage(role, text) {
    const msg = el("div", role === "user" ? "cv-msg is-user" : "cv-msg");
    msg.append(el("span", "who", role === "user" ? ">" : "·"));
    const body = el("div", "text");
    const p = el("p", null, text);
    body.append(p);
    msg.append(body);
    log.append(msg);
    log.scrollTop = log.scrollHeight;
    return p;
  }

  async function submit() {
    const question = input.value.trim().slice(0, MAX_QUESTION_CHARS);
    if (!question || busy) return;

    input.value = "";
    addMessage("user", question);

    // Il perimetro si applica prima del modello: quello che non riguarda il CV non
    // arriva nemmeno a essere generato.
    if (!isAboutCv(question, vocabulary)) {
      addMessage("assistant", REFUSAL);
      input.focus();
      return;
    }

    busy = true;
    send.disabled = true;
    const target = addMessage("assistant", "…");

    try {
      await answer(question, target);
    } catch (err) {
      if (String(err && err.name).includes("ContextWindowSizeExceeded")) {
        history = [];
        target.textContent =
          "La conversazione è diventata troppo lunga: riparto da capo, riprova la domanda.";
      } else {
        console.error(err);
        target.textContent = "Qualcosa è andato storto nella generazione. Riprova.";
      }
    } finally {
      busy = false;
      send.disabled = false;
      input.focus();
    }
  }

  async function answer(question, target) {
    const messages = [
      { role: "system", content: system },
      ...history.slice(-MAX_TURNS * 2),
      { role: "user", content: question },
    ];

    const stream = await engine.chat.completions.create({
      messages,
      stream: true,
      temperature: 0.1,
      max_tokens: 300,
      // Il modello entrava in loop sugli elenchi, ripetendo la stessa riga a oltranza.
      frequency_penalty: 0.6,
      presence_penalty: 0.3,
      // Qwen3 ragiona ad alta voce per default: i blocchi <think> finivano in pagina e
      // si mangiavano il poco contesto rimasto, troncando la risposta vera.
      extra_body: { enable_thinking: false },
    });

    let text = "";
    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content || "";
      if (!delta) continue;
      text += delta;
      target.textContent = visible(text);
      log.scrollTop = log.scrollHeight;
    }

    text = visible(text);
    target.textContent = text || REFUSAL;
    if (!text) text = REFUSAL;
    history.push({ role: "user", content: question });
    history.push({ role: "assistant", content: text });
  }

  send.addEventListener("click", submit);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submit();
  });
  input.focus();
}

// ------------------------------------------------------------------- avvio

async function init() {
  setModelBadge("checking");
  const support = await checkSupport();
  if (!support.ok) {
    showBlocked(support.reason);
    return;
  }
  await showWelcome();
}

// L'avvio sta in fondo di proposito: init() usa costanti dichiarate sotto la sua definizione,
// e chiamarlo prima le trova nella zona morta temporale.
if (root && corpusEl) {
  init().catch((err) => {
    console.error(err);
    showBlocked("no-adapter");
  });
}
