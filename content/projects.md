+++
title = "Projects"
slug = "projects"
description = "Progetti open source di Saverio Menin"
eyebrow = "$ ls -F ~/projects"
+++

<h1 class="sr-only">Projects</h1>

<p class="lead">Progetti open source che sviluppo nel tempo libero. Molti nascono con l'aiuto dell'AI, alcuni quasi interamente in vibe coding, altri meno, ma sicurezza e architettura le controllo sempre io. Codice su GitHub, contributi benvenuti.</p>

<nav class="proj-index mono" aria-label="Sezioni">
  <a href="#altro">altro/</a> <span class="n">1</span>
  <a href="#software">software/</a> <span class="n">7</span>
</nav>

<h2 class="proj-section mono" id="altro">altro/ <span>cataloghi e materiale da copiare</span></h2>

{{< project
    name="my-skills"
    mark="drawer"
    kind="catalogo"
    stack="Markdown · HTML"
    license="MIT"
    repo="https://github.com/savez/my-skills" >}}
Non è software da installare: è un catalogo di skill, prompt e guide per agenti AI come Claude Code e Hermes, scritti in italiano e provati su casi reali. Copi una cartella e il tuo agente impara un mestiere nuovo, per esempio formattare un post LinkedIn o tenere un second brain sul modello LLM-Wiki di Karpathy.

Ci sono anche pagine HTML per scegliere tra modelli LLM e framework di spec-driven development, che si aprono direttamente nel browser. Dove serve codice, usa solo la libreria standard.
{{< /project >}}

<h2 class="proj-section mono" id="software">software/ <span>da installare o da usare nel browser</span></h2>

{{< project
    name="Devvami"
    mark="terminal"
    kind="cli"
    stack="Node.js · oclif"
    license="MIT"
    cmd="npm install -g devvami"
    repo="https://github.com/savez/devvami"
    npm="https://www.npmjs.com/package/devvami" >}}
CLI per la developer experience di sviluppatori e team: pull request, pipeline CI/CD, repository, costi AWS, task, log CloudWatch e scansione CVE delle dipendenze, tutto da un unico comando **dvmi**.

Include un TUI per sincronizzare le configurazioni degli strumenti AI (server MCP, prompt, regole, skill, agent) su 10 ambienti diversi. Le credenziali restano nel keychain di sistema, mai in chiaro.
{{< /project >}}

{{< project
    name="Fidelity Card"
    mark="card"
    kind="pwa"
    stack="Vue 3 · IndexedDB"
    license="MIT"
    repo="https://github.com/savez/fidality-card"
    page="https://savez.github.io/fidality-card/"
    demo="https://fidelity-card.onrender.com" >}}
PWA per salvare, organizzare e condividere le tessere fedeltà. Scansione di barcode e QR dalla fotocamera, inserimento manuale, brand italiani pronti all'uso, condivisione via QR o link e backup in JSON.

Nessun login e nessun backend: le card restano sul dispositivo in IndexedDB e l'app si installa sul telefono, anche offline.
{{< /project >}}

{{< project
    name="Bacco"
    mark="glass"
    kind="pwa"
    stack="Vue 3 · Dexie · Leaflet"
    license="MIT"
    repo="https://github.com/savez/bacco"
    page="https://bacco.smzstudio.it/" >}}
Il diario dei vini e delle birre che bevi: foto dell'etichetta, voto, analisi organolettica, con cosa l'hai abbinato e dove eri. Si registra in pochi secondi con la bottiglia ancora sul tavolo, e i dettagli si aggiungono dopo se vuoi.

Lettura del barcode con i dati di Open Food Facts, ricerca e filtri per tipo e periodo, mappa dei posti su OpenStreetMap, card da condividere sui social e backup in JSON o CSV. Nessun server e nessun tracciamento: tutto resta nel browser in IndexedDB e l'app si installa sul telefono, anche offline.
{{< /project >}}

{{< project
    name="Officino"
    mark="sheet"
    kind="webapp"
    stack="Fastify · Vue 3 · PostgreSQL"
    license="MIT"
    cmd="make prod"
    repo="https://github.com/savez/officino"
    page="https://savez.github.io/officino/" >}}
Gestionale per officine meccaniche: si registra il lavoro svolto, se ne misura il costo e se ne ricava il documento da consegnare al cliente. Al centro c'è il rapportino — ore, materiali e costi di una lavorazione su un macchinario — che confluisce nelle note di lavorazione e nei PDF per il cliente.

Include preventivi con numerazione progressiva, catalogo ricambi con lettura dei codici a barre, dashboard delle ore per operaio e per cliente, ruoli e permessi. Si auto-ospita con Docker Compose.
{{< /project >}}

{{< project
    name="NonAbbocco"
    mark="urlbar"
    kind="extension"
    stack="Manifest V3 · Chrome · Firefox"
    license="MIT"
    repo="https://github.com/savez/nonAbbocco"
    page="https://savez.github.io/nonAbbocco/" >}}
Estensione contro il phishing per Chrome e Firefox: legge l'indirizzo e il contenuto di ogni pagina, assegna un rischio da 1 a 5 e mette un interstiziale prima che tu digiti le credenziali. Riconosce marchi infilati nel sottodominio altrui, typosquatting, omografi in alfabeti misti e login in chiaro, su 50 marchi italiani e internazionali.

Il rank non è una somma di punti: quattro categorie — identità, credenziali, trasporto, reputazione — si combinano, e le credenziali da sole non bastano mai. Tutta l'analisi resta nel browser, senza telemetria. Nella pagina di progetto c'è un simulatore che gira sullo stesso motore dell'estensione.
{{< /project >}}

{{< project
    name="Hermes Agent per Home Assistant"
    mark="panel"
    kind="add-on"
    stack="Home Assistant OS · Docker · s6"
    license="MIT"
    repo="https://github.com/savez/hermes-agent-addon-ha" >}}
Add-on che fa girare Hermes Agent — l'agente AI di NousResearch — dentro Home Assistant OS, come pannello nella sidebar e dietro il login di Home Assistant. Profili separati con memoria, skill e bot propri, canali di messaggistica come Telegram, accesso alle entità esposte ad Assist tramite il server MCP di Core e una CLI via SSH.

Il punto è farlo stando dentro i canoni di Home Assistant invece di aggirarli: Ingress come unico ingresso, tutto il resto in ascolto su loopback, processo non privilegiato, immagine costruita sul dispositivo e nessun pacchetto installato a runtime. I compromessi accettati sono dichiarati uno per uno in SECURITY.md, a partire dal fatto che la dashboard non ha una password propria.
{{< /project >}}

{{< project
    name="LinkedinFormatter"
    mark="post"
    kind="pwa"
    stack="JavaScript · Manifest V3"
    license="MIT"
    repo="https://github.com/savez/linkedin-formatter"
    page="https://linkedinformatter.smzstudio.it/" >}}
Grassetto, corsivo, sottolineato ed elenchi nei post LinkedIn, che non li supporta: le lettere diventano caratteri Unicode che sembrano formattati. Scrivi con gli asterischi come in Markdown, vedi l'anteprima con il conteggio sul limite dei 3000 caratteri e copi il testo pronto. Link, hashtag e menzioni restano cliccabili e le lettere accentate funzionano come le altre.

C'è come app installabile, anche offline, e come estensione per Chrome e Firefox con il clic destro *Formatta per LinkedIn*. Le estensioni sono generate dalla stessa PWA a ogni rilascio, quindi si comportano in modo identico. Nessun server e nessun tracciamento: la bozza resta nel browser.
{{< /project >}}
