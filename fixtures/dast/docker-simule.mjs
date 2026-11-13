#!/usr/bin/env node
// docker-simule — DOCKER SIMULÉ du self-test d'oracle-dast (TF-2477). Il n'a pas de moteur de conteneurs
// et n'émet RIEN vers aucune cible. oracle-dast le joue à la place de `docker` quand WEBSEC_DAST_DOCKER le
// désigne (un script .mjs est joué par node). Deux sous-commandes :
//   image inspect <référence> [--format …] : rend 0 et imprime un identifiant fictif si la référence figure
//       dans WEBSEC_DAST_SIMULE_IMAGES (références séparées par des virgules), sinon rend 1 comme un docker
//       qui ne trouve pas l'image — rien n'est jamais tiré ;
//   run … : enregistre sa ligne de commande (une ligne JSON ajoutée à WEBSEC_DAST_SIMULE_TRACE) et dépose
//       dans le dossier monté sur /zap/wrk le rapport nommé par -J, copie du fichier désigné par
//       WEBSEC_DAST_SIMULE_RAPPORT.
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const trace = process.env.WEBSEC_DAST_SIMULE_TRACE;
if (trace) fs.appendFileSync(trace, JSON.stringify({ script: path.basename(process.argv[1]), argv }) + "\n");

if (argv[0] === "image" && argv[1] === "inspect") {
  const presentes = String(process.env.WEBSEC_DAST_SIMULE_IMAGES || "").split(",").filter(Boolean);
  if (presentes.includes(argv[2])) { process.stdout.write("sha256:" + "0".repeat(63) + "1\n"); process.exit(0); }
  process.stderr.write(`Error: No such image: ${argv[2]}\n`);
  process.exit(1);
}
if (argv[0] === "run") {
  const v = argv.indexOf("-v");
  const j = argv.indexOf("-J");
  const montage = v >= 0 ? argv[v + 1] : "";
  const dossier = montage.replace(/:\/zap\/wrk(:\w+)?$/, "");
  if (dossier && j >= 0 && argv[j + 1] && process.env.WEBSEC_DAST_SIMULE_RAPPORT) {
    fs.copyFileSync(process.env.WEBSEC_DAST_SIMULE_RAPPORT, path.join(dossier, argv[j + 1]));
  }
  process.exit(0);
}
process.exit(2);
