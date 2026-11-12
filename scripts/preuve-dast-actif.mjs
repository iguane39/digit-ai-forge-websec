#!/usr/bin/env node
// preuve-dast-actif — preuve RÉELLE du mode actif d'oracle-dast (TF-2444), hors self-test : le
// self-test ne lance jamais de scan, fût-il autorisé (CLAUDE.md). Ce banc lance le vrai ZAP (image
// Docker déjà présente, jamais téléchargée) contre UNE cible : fixtures/dast/cible-locale.mjs, démarrée
// ici sur 127.0.0.1, joignable du conteneur par host.docker.internal. Aucune autre cible n'existe dans ce
// script ; aucun service tiers n'est visé. La preuve se lit au JOURNAL DE LA CIBLE (ce qu'elle a
// réellement reçu), pas au rapport de ZAP.
//
// Trois balayages, chacun contre une cible neuve :
//   A  passif, autorisation avec toutes les options → aucune sonde active, rien d'exclu reçu, en-tête présent
//   B  actif, autorisation SANS option (témoin)      → sondes actives reçues, route exclue atteinte, aucun
//                                                       en-tête, débit libre au-dessus de la borne
//   C  actif, autorisation AVEC options              → sondes actives reçues, route exclue jamais atteinte,
//                                                       en-tête sur toute requête, débit sous la borne
// A et B ensemble prouvent que « actif » et « passif » ne lancent pas la même passe ; B et C que chaque
// option change ce que la cible reçoit.
//
// Usage : node scripts/preuve-dast-actif.mjs [--oracle <oracle-dast.mjs>] [--debit 10] [--scenarios A,B,C]
// Le rapport JSON sort sur stdout, l'avancement (une ligne par minute de balayage) sur stderr.
// Exit 0 = toutes les assertions tiennent · 1 = une assertion échoue · 2 = SKIP motivé (Docker ou image absents).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (nom, defaut) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : defaut; };
const ORACLE = path.resolve(opt("--oracle", path.join(ICI, "..", "oracles", "oracle-dast.mjs")));
const CIBLE = path.join(ICI, "..", "fixtures", "dast", "cible-locale.mjs");
const DEBIT = Number(opt("--debit", "10"));
const SCENARIOS = opt("--scenarios", "A,B,C").split(",");
const IMAGE = process.env.WEBSEC_DAST_IMAGE || "ghcr.io/zaproxy/zaproxy:stable";
const log = (m) => process.stderr.write(`[${new Date().toISOString().slice(11, 19)}] ${m}\n`);

const docker = spawnSync("docker", ["image", "inspect", IMAGE], { encoding: "utf8", timeout: 30000 });
if (docker.error || docker.status !== 0) {
  process.stdout.write(JSON.stringify({ verdict: "SKIP", motif: `Docker ou image ${IMAGE} absents du poste — la preuve réelle ne s'installe rien` }) + "\n");
  process.exit(2);
}

const travail = fs.mkdtempSync(path.join(os.tmpdir(), "preuve-dast-"));
// Valeur d'en-tête fictive assemblée à l'exécution, jamais écrite dans un fichier du dépôt.
const ACCES = ["Bearer", ["jeton", "de", "preuve", Math.random().toString(36).slice(2, 10)].join("-")].join(" ");

const lireJournal = (f) => (fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const CONNUES = new Set(["/", "/recherche?q=a", "/donnees?id=1", "/prive", "/deconnexion", "/robots.txt", "/sitemap.xml", "/favicon.ico"]);
function fenetreMax(entrees, ms) {
  let max = 0, j = 0;
  for (let i = 0; i < entrees.length; i++) {
    while (entrees[i].t - entrees[j].t >= ms) j++;
    max = Math.max(max, i - j + 1);
  }
  return max;
}
function mesurer(entrees) {
  const prive = entrees.filter((e) => e.url.split("?")[0] === "/prive");
  return {
    requetes: entrees.length,
    duree_s: entrees.length ? Math.round((entrees.at(-1).t - entrees[0].t) / 100) / 10 : 0,
    sondes_actives: entrees.filter((e) => !CONNUES.has(e.url)).length,
    requetes_route_exclue: entrees.filter((e) => e.url.split("?")[0] === "/deconnexion").length,
    requetes_privees: prive.length,
    requetes_privees_avec_en_tete: prive.filter((e) => e.acces).length,
    pic_requetes_par_seconde: fenetreMax(entrees, 1000),
  };
}

async function demarrerCible(journal) {
  const p = spawn(process.execPath, [CIBLE, "--journal", journal, "--valeur", ACCES], { stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise((ok, ko) => {
    p.stdout.once("data", (d) => ok(JSON.parse(String(d)).port));
    p.once("error", ko);
    p.once("exit", (c) => ko(new Error(`cible-locale sortie prématurément (${c})`)));
  });
  return { p, port };
}

function balayer(mode, autorisationPath, port, journal) {
  return new Promise((ok) => {
    const sortie = [];
    const p = spawn(process.execPath, [ORACLE, "--cible", `http://host.docker.internal:${port}`, "--autorisation", autorisationPath, "--mode", mode, "--json-only"],
      { env: { ...process.env, WEBSEC_DAST_AUTORISATION: "", WEBSEC_PREUVE_ACCES: ACCES }, stdio: ["ignore", "pipe", "pipe"] });
    p.stdout.on("data", (d) => sortie.push(d));
    p.stderr.on("data", (d) => sortie.push(d));
    const debut = Date.now();
    const minuteur = setInterval(() => log(`  balayage ${mode} en cours : ${Math.round((Date.now() - debut) / 1000)} s, ${lireJournal(journal).length} requête(s) reçues par la cible`), 60000);
    p.on("exit", (code) => { clearInterval(minuteur); ok({ code, texte: Buffer.concat(sortie).toString("utf8"), duree_s: Math.round((Date.now() - debut) / 1000) }); });
  });
}

const base = {
  autorisation_ecrite: true, mandat: "TF-2444 — preuve réelle, cible de fixture locale", proprietaire: "banc local (propriétaire fictif)",
  environnement: "recette", fenetre: { debut: "2026-01-01", fin: "2099-12-31" }, actif_autorise: true,
};
const options = {
  en_tete_acces: { nom: "Authorization", valeur_env: "WEBSEC_PREUVE_ACCES" },
  debit_max_requetes_par_seconde: DEBIT,
  exclusions: ["/deconnexion"],
};
const PLAN = {
  A: { mode: "passif", options: true },
  B: { mode: "actif", options: false },
  C: { mode: "actif", options: true },
};

const resultats = {};
for (const nom of SCENARIOS) {
  const plan = PLAN[nom];
  const journal = path.join(travail, `cible-${nom}.jsonl`);
  const { p, port } = await demarrerCible(journal);
  const autorisationPath = path.join(travail, `autorisation-${nom}.json`);
  fs.writeFileSync(autorisationPath, JSON.stringify({ ...base, cibles: [`http://host.docker.internal:${port}`], ...(plan.options ? options : {}) }, null, 2));
  log(`scénario ${nom} (${plan.mode}, options ${plan.options ? "oui" : "non"}) : cible locale sur 127.0.0.1:${port}`);
  const b = await balayer(plan.mode, autorisationPath, port, journal);
  p.kill();
  let verdict = null, synthese = null;
  try { const j = JSON.parse(b.texte); verdict = j.verdict; synthese = j.synthese; } catch { /* sortie illisible, dite plus bas */ }
  resultats[nom] = { ...plan, oracle_exit: b.code, oracle_duree_s: b.duree_s, verdict, forme: synthese && synthese.balayage && synthese.balayage.forme, valeur_en_tete_dans_la_sortie: b.texte.includes(ACCES), cible: mesurer(lireJournal(journal)) };
  log(`scénario ${nom} fini en ${b.duree_s} s : verdict ${verdict}, ${JSON.stringify(resultats[nom].cible)}`);
}

const assertions = [];
const ok = (cond, texte) => assertions.push({ ok: Boolean(cond), texte });
const A = resultats.A?.cible, B = resultats.B?.cible, C = resultats.C?.cible;
for (const nom of Object.keys(resultats)) ok(!resultats[nom].valeur_en_tete_dans_la_sortie, `${nom} : la valeur de l'en-tête n'apparaît pas dans la sortie de l'oracle`);
if (A) {
  ok(A.requetes > 0, "A passif : la cible a reçu la passe d'araignée");
  ok(A.sondes_actives === 0, `A passif : aucune sonde active reçue (obtenu ${A.sondes_actives})`);
  ok(A.requetes_route_exclue === 0, `A passif : la route exclue n'a reçu aucune requête (obtenu ${A.requetes_route_exclue})`);
  ok(A.requetes_privees > 0 && A.requetes_privees === A.requetes_privees_avec_en_tete, `A passif : toute requête vers la route privée porte l'en-tête (${A.requetes_privees_avec_en_tete}/${A.requetes_privees})`);
}
if (B) {
  ok(B.sondes_actives > 0, `B actif sans option : des sondes actives reçues (obtenu ${B.sondes_actives})`);
  ok(B.requetes_route_exclue > 0, `B actif sans exclusion : la route est atteinte (obtenu ${B.requetes_route_exclue}) — témoin de C`);
  ok(B.requetes_privees_avec_en_tete === 0, `B actif sans en-tête : aucune requête n'en porte (obtenu ${B.requetes_privees_avec_en_tete}) — témoin de C`);
  ok(B.pic_requetes_par_seconde > DEBIT, `B actif sans débit : le pic dépasse la borne de ${DEBIT}/s (obtenu ${B.pic_requetes_par_seconde}) — témoin de C`);
}
if (C) {
  ok(C.sondes_actives > 0, `C actif avec options : des sondes actives reçues (obtenu ${C.sondes_actives})`);
  ok(C.requetes_route_exclue === 0, `C actif avec exclusion : la route exclue n'a reçu aucune requête (obtenu ${C.requetes_route_exclue})`);
  ok(C.requetes_privees > 0 && C.requetes_privees === C.requetes_privees_avec_en_tete, `C actif avec en-tête : toute requête vers la route privée le porte (${C.requetes_privees_avec_en_tete}/${C.requetes_privees})`);
  ok(C.pic_requetes_par_seconde <= DEBIT, `C actif avec débit : le pic reste sous la borne de ${DEBIT}/s (obtenu ${C.pic_requetes_par_seconde})`);
}
if (A && C) ok(C.sondes_actives > A.sondes_actives, `actif ≠ passif : ${C.sondes_actives} sondes en actif contre ${A.sondes_actives} en passif`);

for (const a of assertions) log(`${a.ok ? "PASS" : "FAIL"} · ${a.texte}`);
const echecs = assertions.filter((a) => !a.ok).length;
fs.rmSync(travail, { recursive: true, force: true });
process.stdout.write(JSON.stringify({ oracle: ORACLE, debit_borne: DEBIT, resultats, assertions, pass: assertions.length - echecs, fail: echecs }, null, 2) + "\n");
process.exit(echecs ? 1 : 0);
