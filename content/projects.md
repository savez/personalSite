+++
title = "Projects"
slug = "projects"
description = "Progetti open source di Saverio Menin"
eyebrow = "$ ls ~/projects"
+++

<h1 class="sr-only">Projects</h1>

<p class="lead">Progetti open source che sviluppo nel tempo libero. Molti nascono con l'aiuto dell'AI, alcuni quasi interamente in vibe coding, altri meno, ma sicurezza e architettura le controllo sempre io. Codice su GitHub, contributi benvenuti.</p>

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
