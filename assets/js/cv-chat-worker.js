// Worker della chat del CV.
// WebLLM non crea worker da sé: questo file è il worker, servito dal nostro dominio.
// La libreria è vendorizzata in assets/js/vendor/: importarla da CDN dentro un worker
// viene bloccato dalla CSP, e averla in casa toglie anche una dipendenza a runtime.
// Il percorso viene riscritto da Hugo in fase di build (vedi layouts/_default/cv.html).
import { WebWorkerMLCEngineHandler } from "__WEBLLM__";

const handler = new WebWorkerMLCEngineHandler();
self.onmessage = (msg) => handler.onmessage(msg);
