#!/usr/bin/env node
// zap-simule — ZAP SIMULÉ du self-test d'oracle-dast (TF-2444). Il n'émet RIEN vers aucune cible :
// il enregistre la ligne de commande qu'oracle-dast lui a passée (une ligne JSON ajoutée au fichier
// WEBSEC_DAST_SIMULE_TRACE) et dépose, à l'endroit demandé par -J ou -quickout, une copie du rapport
// ZAP désigné par WEBSEC_DAST_SIMULE_RAPPORT. Le self-test en fait trois copies nommées comme les
// vraies commandes (zap-baseline.mjs, zap-full-scan.mjs, zap.mjs), car oracle-dast lit la FORME d'un
// ZAP de son nom.
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const trace = process.env.WEBSEC_DAST_SIMULE_TRACE;
if (trace) fs.appendFileSync(trace, JSON.stringify({ script: path.basename(process.argv[1]), argv }) + "\n");
const i = argv.findIndex((a) => a === "-J" || a === "-quickout");
if (i >= 0 && argv[i + 1] && process.env.WEBSEC_DAST_SIMULE_RAPPORT) {
  fs.copyFileSync(process.env.WEBSEC_DAST_SIMULE_RAPPORT, argv[i + 1]);
}
