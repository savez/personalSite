+++
title = "Projects"
slug = "projects"
description = "Progetti open source di Saverio Menin"
eyebrow = "$ ls ~/projects"
+++

<h1 class="sr-only">Projects</h1>

<p class="lead">Progetti open source che sviluppo nel tempo libero. Codice su GitHub, licenza MIT, contributi benvenuti.</p>

{{< project
    name="Devvami"
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
    kind="pwa"
    stack="Vue 3 · IndexedDB"
    license="MIT"
    repo="https://github.com/savez/fidality-card"
    page="https://savez.github.io/fidality-card/"
    demo="https://fidelity-card.onrender.com" >}}
PWA per salvare, organizzare e condividere le tessere fedeltà. Scansione di barcode e QR dalla fotocamera, inserimento manuale, brand italiani pronti all'uso, condivisione via QR o link e backup in JSON.

Nessun login e nessun backend: le card restano sul dispositivo in IndexedDB e l'app si installa sul telefono, anche offline.
{{< /project >}}
