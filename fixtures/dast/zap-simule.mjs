#!/usr/bin/env node
// zap-simule — ZAP SIMULÉ du self-test d'oracle-dast (TF-2444). Il n'émet RIEN vers aucune cible :
// il enregistre la ligne de commande qu'oracle-dast lui a passée (une ligne JSON ajoutée au fichier
// WEBSEC_DAST_SIMULE_TRACE) et dépose, à l'endroit demandé par -J ou -quickout, une copie du rapport
// ZAP désigné par WEBSEC_DAST_SIMULE_RAPPORT. Le self-test en fait trois copies nommées comme les
// vraies commandes (zap-baseline.mjs, zap-full-scan.mjs, zap.mjs), car oracle-dast lit la FORME d'un
// ZAP de son nom.
import fs from "node:fs";
import path from "node:path";

//
// TF-2486 : WEBSEC_DAST_SIMULE_ATTENTE_MS le fait durer AVANT de déposer son rapport (un balayage
// long) ; WEBSEC_DAST_SIMULE_FIN nomme un fichier qu'il écrit en finissant. Si ce fichier existe après
// un délai dépassé, l'oracle n'a pas arrêté l'arbre de processus : le balayage aurait continué.
// La trace porte aussi le dossier courant (TF-2485 : zap.bat exige celui de ZAP).
const argv = process.argv.slice(2);
const trace = process.env.WEBSEC_DAST_SIMULE_TRACE;
if (trace) fs.appendFileSync(trace, JSON.stringify({ script: path.basename(process.argv[1]), argv, cwd: process.cwd() }) + "\n");
const attente = Number(process.env.WEBSEC_DAST_SIMULE_ATTENTE_MS || 0);
if (attente > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, attente);
// TF-2498 : WEBSEC_DAST_SIMULE_ORIGINE désigne une origine LOCALE du banc (jamais une cible réelle). Le ZAP simulé y joue alors
// l'araignée de ZAP, selon les deux réglages que l'oracle lui passe : il lit la page « / », et pour chaque formulaire trouvé
// l'envoie (corps identifiant=ZAP&secret=ZAP, valeurs choisies comme ZAP l'a fait le 13/11/2026) — sauf si `spider.processform=false`
// (aucun formulaire traité) ou, pour un formulaire en POST, `spider.postform=false`. C'est la lecture des réglages que le banc prouve ;
// que le vrai ZAP les lit de même se prouve par scripts/preuve-dast-passif.mjs.
const origine = process.env.WEBSEC_DAST_SIMULE_ORIGINE;
if (origine) {
  const reglages = argv.join(" ");
  const traite = !/spider\.processform=false/.test(reglages);
  const poste = !/spider\.postform=false/.test(reglages);
  // l'araignée : la page « / » puis les liens relatifs qu'elle porte, un seul niveau
  const lire = async (chemin) => (await fetch(`${origine}${chemin}`)).text();
  const accueil = await lire("/");
  const chemins = ["/", ...[...accueil.matchAll(/<a\b[^>]*href\s*=\s*["']?(\/[^"'\s>]*)/gi)].map((m) => m[1])];
  for (const chemin of chemins) {
    const page = chemin === "/" ? accueil : await lire(chemin);
    for (const m of page.matchAll(/<form\b([^>]*)>/gi)) {
      const methode = ((/method\s*=\s*["']?(\w+)/i.exec(m[1]) || [])[1] || "get").toUpperCase();
      const action = (/action\s*=\s*["']?([^"'\s>]+)/i.exec(m[1]) || [])[1] || chemin;
      if (!traite || (methode === "POST" && !poste)) continue;
      await fetch(`${origine}${action}`, { method: methode, headers: { "content-type": "application/x-www-form-urlencoded" }, body: "identifiant=ZAP&secret=ZAP" });
    }
  }
}
const i = argv.findIndex((a) => a === "-J" || a === "-quickout");
if (i >= 0 && argv[i + 1] && process.env.WEBSEC_DAST_SIMULE_RAPPORT) {
  fs.copyFileSync(process.env.WEBSEC_DAST_SIMULE_RAPPORT, argv[i + 1]);
}
if (process.env.WEBSEC_DAST_SIMULE_FIN) fs.writeFileSync(process.env.WEBSEC_DAST_SIMULE_FIN, "fini\n");
