#!/usr/bin/env node
// oracle-dast — Domaine « Scan dynamique (DAST) : OWASP ZAP enveloppé en verdict machine
// normalisé » (zéro dépendance propre — délègue à l'outillage DÉJÀ présent sur le poste, ne
// l'installe jamais). Lève la dette D-W1 du README (« Pas de DAST… ZAP consigné en v1 »),
// mandat TF-0187.
//
// ════════════════════════════════════════════════════════════════════════════════════════
// GARDE-FOU DUAL-USE — FAIL-CLOSED, NON CONTOURNABLE
// ════════════════════════════════════════════════════════════════════════════════════════
// Un scan dynamique sollicite réellement une cible : c'est une capacité à double usage. Cet
// oracle REFUSE de faire quoi que ce soit tant que la cible n'est pas nommément déclarée
// autorisée par écrit. Le refus est un FAIL bruyant (exit 1), jamais un SKIP discret, pour
// qu'une erreur de frappe dans `--cible` ne parte JAMAIS en scan.
//
// Il faut, cumulativement (transposition des six garde-fous de l'étude du 14/08/2026) :
//   1. `--cible <url>` explicite, absolue, en http(s) — pas de cible par défaut, jamais ;
//   2. une autorisation écrite : `--autorisation <fichier.json>` ou la variable
//      d'environnement WEBSEC_DAST_AUTORISATION pointant ce fichier ;
//   3. dans ce fichier : `autorisation_ecrite: true`, `mandat`, `proprietaire`,
//      `environnement`, `cibles` (liste d'origines) et `fenetre {debut, fin}` ;
//   4. l'ORIGINE de `--cible` doit figurer À L'IDENTIQUE dans `cibles` — comparaison exacte
//      d'origine (schéma + hôte + port), aucun joker, aucun sous-domaine implicite, aucune
//      correspondance partielle : une faute de frappe est un refus, pas une approximation ;
//   5. la date du jour doit tomber dans `fenetre` — une autorisation périmée ne vaut plus ;
//   6. `environnement: "production"` exige en plus `autorisation_production_distincte: true`
//      (garde-fou n°3 : instance dédiée par défaut) ;
//   7. le mode actif (au-delà de la passe passive) exige `actif_autorise: true`.
// Le garde-fou s'applique AUSSI en lecture de rapport (`--rapport`) : un constat de sécurité
// ne se produit pas sur une cible anonyme, même sans rien émettre vers elle.
// Ce que l'oracle ne peut PAS faire : vérifier que l'autorisation est sincère. Il vérifie une
// déclaration écrite et traçable, pas un consentement réel (cf. `non_juge`).
// ════════════════════════════════════════════════════════════════════════════════════════
//
// Deux voies, une fois le garde-fou franchi :
//   --rapport <f.json> : juge un rapport ZAP DÉJÀ produit (aucune émission vers la cible) ;
//   sinon              : cherche ZAP sur le poste (WEBSEC_DAST_ZAP, puis zap-baseline.py /
//                        zap.sh / zap.bat dans le PATH) et lance une passe BASELINE (passive).
// ZAP absent du poste → verdict SKIP MOTIVÉ (exit 2), jamais un PASS de complaisance : c'est
// le chemin nominal sur un poste non équipé, et il est prouvé par fixture au self-test.
//
// Seuils par défaut : high=0, medium=0 (low/informational comptés en synthèse, non bloquants).
// Contrat : JSON {oracle, version, artefact, verdict, findings, non_juge, synthese,
// seuils_appliques} · exit 0 (PASS) / 1 (FAIL — refus du garde-fou, rapport illisible ou
// alertes au-delà des seuils) / 2 (SKIP — rien n'a pu être jugé : pas de cible, ou ZAP absent).
// Usage : node oracle-dast.mjs --cible <url> [--autorisation <f.json>] [--rapport <f.json>]
//                              [--seuils <f.json>] [--mode passif|actif] [--json-only]
import fs from "node:fs";
import { spawnSync } from "node:child_process";

const VERSION = "0.1.0";
const ORACLE = "oracle-dast";
// `domaine` : champ du contrat d'oracle générique du pilot ; les deux oracles antérieurs de
// cette forge (exposition, sca) le précèdent et ne le portent pas encore.
const DOMAINE = "sécurité du produit web livré — scan dynamique (DAST) délégué à OWASP ZAP";
const NON_JUGE = [
  "la sincérité de l'autorisation : l'oracle vérifie une déclaration écrite et traçable, jamais le consentement réel du propriétaire de la cible",
  "tout ce qu'une passe passive ne voit pas : logique métier, autorisation/IDOR, chaînes d'exploitation multi-étapes, 0-day — une absence d'alerte n'est pas une absence de vulnérabilité",
  "la couverture réelle du parcours : les endpoints non atteints par le spider ZAP ne sont pas jugés (une cible authentifiée non configurée est explorée en surface seulement)",
  "l'exploitabilité et le tri des faux positifs : une alerte ZAP est un signal à qualifier par un humain, jamais un verdict d'exploitation",
  "la fraîcheur des règles ZAP du poste (version des add-ons, base de règles) — non interrogée par cet oracle",
  "la couche TLS (versions, suites, chaîne de certificat) — hors périmètre, cf. README §Limites",
  "la correction des alertes signalées — un constat, jamais un geste automatique",
  "l'exécution réelle de ZAP sur ce poste : la branche d'exécution n'est pas prouvée par fixture faute de ZAP installé (cf. README §Limites, D-W1 requalifiée)",
];

const args = process.argv.slice(2);
const jsonOnly = args.includes("--json-only");
const opt = (nom) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : null; };
const cible = opt("--cible");
const autorisationPath = opt("--autorisation") || process.env.WEBSEC_DAST_AUTORISATION || null;
const rapportPath = opt("--rapport");
const seuilsPath = opt("--seuils");
const mode = opt("--mode") || "passif";

const F = [];
const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where });
const synthese = {};

const SEUILS_DEFAUT = { high: 0, medium: 0 };
let seuils = SEUILS_DEFAUT;
let seuilsSource = "défaut embarqué (high=0, medium=0 ; low et informational comptés, non bloquants)";

function sortir(verdict, code) {
  process.stdout.write(JSON.stringify({
    oracle: ORACLE, domaine: DOMAINE, version: VERSION, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucune alerte au-delà des seuils appliqués", where: cible }],
    synthese, seuils_appliques: { source: seuilsSource, ...seuils },
    non_juge: NON_JUGE,
  }, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

// ── 1. Cible explicite ───────────────────────────────────────────────────────
// Pas de cible = rien à juger : SKIP motivé (aucune émission, aucun refus à instruire).
if (!cible || cible.startsWith("--")) {
  add("info", "DAST-USAGE", "aucune cible : `--cible <url>` est obligatoire, il n'existe aucune cible par défaut. Rien n'a été jugé, rien n'a été émis.", null);
  add("info", "DAST-USAGE", "usage : node oracle-dast.mjs --cible <url> --autorisation <fichier.json> [--rapport <zap.json>] [--seuils <f.json>]", null);
  sortir("SKIP", 2);
}

let origineCible = null;
try {
  const u = new URL(cible);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("schéma non http(s)");
  origineCible = u.origin;
} catch (e) {
  add("bloquant", "DAST-AUTZ-CIBLE", `cible inexploitable (« ${cible} ») : une URL absolue en http(s) est exigée — ${e.message}. Refus : une cible mal formée ne peut pas être rattachée à une autorisation.`, cible);
  sortir("FAIL", 1);
}

// ── 2. Autorisation écrite présente ──────────────────────────────────────────
if (!autorisationPath) {
  add("bloquant", "DAST-AUTZ-ABSENTE", "aucune autorisation déclarée : un scan dynamique n'est jamais lancé sans périmètre autorisé par écrit. Fournir `--autorisation <fichier.json>` ou la variable WEBSEC_DAST_AUTORISATION. Refus fail-closed, rien n'a été émis vers la cible.", origineCible);
  sortir("FAIL", 1);
}
if (!fs.existsSync(autorisationPath)) {
  add("bloquant", "DAST-AUTZ-ABSENTE", `fichier d'autorisation introuvable : ${autorisationPath}. Refus net — aucune autorisation implicite, aucun défaut permissif.`, autorisationPath);
  sortir("FAIL", 1);
}
let autz = null;
try { autz = JSON.parse(fs.readFileSync(autorisationPath, "utf8")); }
catch (e) {
  add("bloquant", "DAST-AUTZ-CHAMPS", `autorisation illisible (JSON invalide) : ${e.message}. Refus net.`, autorisationPath);
  sortir("FAIL", 1);
}

// ── 3. Champs obligatoires ───────────────────────────────────────────────────
const manquants = [];
for (const champ of ["mandat", "proprietaire", "environnement", "cibles", "fenetre"]) {
  if (autz[champ] === undefined || autz[champ] === null || autz[champ] === "") manquants.push(champ);
}
if (autz.autorisation_ecrite !== true) manquants.push("autorisation_ecrite (doit valoir exactement true)");
if (autz.fenetre && (!autz.fenetre.debut || !autz.fenetre.fin)) manquants.push("fenetre.debut / fenetre.fin");
if (autz.cibles !== undefined && !Array.isArray(autz.cibles)) manquants.push("cibles (liste d'origines attendue)");
if (manquants.length) {
  add("bloquant", "DAST-AUTZ-CHAMPS", `autorisation incomplète — champ(s) manquant(s) ou invalide(s) : ${manquants.join(", ")}. Une autorisation partielle n'autorise rien.`, autorisationPath);
  sortir("FAIL", 1);
}

// ── 4. Cible nommément listée (comparaison exacte d'origine) ─────────────────
const originesAutorisees = [];
for (const c of autz.cibles) {
  try { originesAutorisees.push(new URL(String(c)).origin); }
  catch { add("majeur", "DAST-AUTZ-CHAMPS", `entrée de « cibles » inexploitable, ignorée : « ${c} »`, autorisationPath); }
}
if (!originesAutorisees.includes(origineCible)) {
  add("bloquant", "DAST-AUTZ-CIBLE", `cible NON autorisée : l'origine « ${origineCible} » ne figure pas dans les cibles déclarées [${originesAutorisees.join(", ") || "aucune exploitable"}] du mandat « ${autz.mandat} ». Comparaison exacte d'origine, sans joker : une faute de frappe est un refus. Rien n'a été émis vers la cible.`, origineCible);
  sortir("FAIL", 1);
}

// ── 5. Fenêtre d'autorisation ────────────────────────────────────────────────
const maintenant = new Date();
const debut = new Date(autz.fenetre.debut);
const fin = new Date(autz.fenetre.fin);
if (Number.isNaN(debut.getTime()) || Number.isNaN(fin.getTime())) {
  add("bloquant", "DAST-AUTZ-FENETRE", `fenêtre d'autorisation illisible (debut=« ${autz.fenetre.debut} », fin=« ${autz.fenetre.fin} ») — dates ISO attendues. Refus net.`, autorisationPath);
  sortir("FAIL", 1);
}
if (maintenant < debut || maintenant > fin) {
  add("bloquant", "DAST-AUTZ-FENETRE", `autorisation hors fenêtre : ${maintenant.toISOString().slice(0, 10)} n'est pas compris entre ${autz.fenetre.debut} et ${autz.fenetre.fin}. Une autorisation périmée ou non encore ouverte ne vaut pas autorisation.`, autorisationPath);
  sortir("FAIL", 1);
}

// ── 6. Production : autorisation distincte exigée ────────────────────────────
if (String(autz.environnement).toLowerCase() === "production" && autz.autorisation_production_distincte !== true) {
  add("bloquant", "DAST-AUTZ-PROD", "cible déclarée en PRODUCTION sans `autorisation_production_distincte: true` : par défaut le test actif vit sur instance dédiée (recette), jamais sur un service rendant un vrai service à de vrais utilisateurs. Refus.", autorisationPath);
  sortir("FAIL", 1);
}

// ── 7. Mode actif : autorisation explicite exigée ────────────────────────────
if (mode !== "passif" && mode !== "actif") {
  add("bloquant", "DAST-AUTZ-MODE", `mode inconnu « ${mode} » — valeurs admises : passif | actif. Refus (aucune interprétation permissive).`, autorisationPath);
  sortir("FAIL", 1);
}
if (mode === "actif" && autz.actif_autorise !== true) {
  add("bloquant", "DAST-AUTZ-MODE", "mode « actif » demandé sans `actif_autorise: true` dans l'autorisation : la passe passive est le défaut, l'attaque active se déclare explicitement. Refus.", autorisationPath);
  sortir("FAIL", 1);
}

synthese.autorisation = {
  mandat: autz.mandat, proprietaire: autz.proprietaire, environnement: autz.environnement,
  fenetre: autz.fenetre, origine_autorisee: origineCible, mode, source: autorisationPath,
};

// ── Seuils ───────────────────────────────────────────────────────────────────
if (seuilsPath) {
  if (!fs.existsSync(seuilsPath)) {
    add("bloquant", "DAST-SEUILS", `fichier de seuils introuvable : ${seuilsPath}. Refus net, aucun défaut implicite.`, seuilsPath);
    sortir("FAIL", 1);
  }
  try {
    const perso = JSON.parse(fs.readFileSync(seuilsPath, "utf8"));
    seuils = { ...SEUILS_DEFAUT, ...perso };
    seuilsSource = seuilsPath;
  } catch (e) {
    add("bloquant", "DAST-SEUILS", `fichier de seuils illisible (JSON invalide) : ${e.message}`, seuilsPath);
    sortir("FAIL", 1);
  }
}

// ── Obtention du rapport ZAP ─────────────────────────────────────────────────
const RISQUE = { 3: "high", 2: "medium", 1: "low", 0: "informational" };
const SEV = { high: "bloquant", medium: "majeur", low: "mineur", informational: "info" };

function lireRapport(chemin) {
  let brut;
  try { brut = JSON.parse(fs.readFileSync(chemin, "utf8")); }
  catch (e) {
    add("bloquant", "DAST-RAPPORT", `rapport ZAP illisible (JSON invalide) : ${e.message}`, chemin);
    sortir("FAIL", 1);
  }
  const sites = Array.isArray(brut.site) ? brut.site : (Array.isArray(brut.Site) ? brut.Site : null);
  if (!sites) {
    add("bloquant", "DAST-RAPPORT", "rapport ZAP non reconnu : tableau `site[]` attendu (format JSON de zap-baseline.py / ZAP report). Refus net — un rapport non compris n'est jamais un PASS.", chemin);
    sortir("FAIL", 1);
  }
  return sites;
}

function jugerRapport(chemin, provenance) {
  const sites = lireRapport(chemin);
  const compte = { high: 0, medium: 0, low: 0, informational: 0 };
  const alertes = [];
  for (const s of sites) {
    for (const a of (Array.isArray(s.alerts) ? s.alerts : [])) {
      const niveau = RISQUE[Number(a.riskcode)] ?? "informational";
      compte[niveau]++;
      alertes.push({ niveau, nom: a.alert || a.name || "(sans nom)", site: s["@name"] || chemin, instances: Number(a.count) || (Array.isArray(a.instances) ? a.instances.length : 0) });
    }
  }
  synthese.zap = { provenance, rapport: chemin, sites: sites.length, alertes: compte };
  for (const niveau of ["high", "medium", "low"]) {
    const seuil = seuils[niveau];
    if (typeof seuil !== "number") continue;
    if (compte[niveau] > seuil) {
      for (const al of alertes.filter((x) => x.niveau === niveau)) {
        add(SEV[niveau], "DAST-SEUIL", `ZAP : alerte « ${al.nom} » de risque ${niveau} (${al.instances} instance(s)) — ${compte[niveau]} alerte(s) ${niveau} > seuil ${seuil}`, al.site);
      }
    }
  }
  const durs = F.filter((f) => f.sev === "bloquant" || f.sev === "majeur");
  sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0);
}

// Voie A — rapport déjà produit : aucune émission vers la cible.
if (rapportPath) {
  if (!fs.existsSync(rapportPath)) {
    add("bloquant", "DAST-RAPPORT", `rapport ZAP introuvable : ${rapportPath}. Refus net — aucun verdict sans artefact.`, rapportPath);
    sortir("FAIL", 1);
  }
  jugerRapport(rapportPath, "rapport fourni (--rapport) — aucun scan lancé par cet oracle");
}

// Voie B — exécution ZAP sur le poste.
// La détection RÉSOUT la commande dans le PATH, elle ne l'exécute jamais « pour voir » : sur
// Windows, une commande inexistante sort en 1 avec un message sur stderr, indiscernable d'un
// `-h` qui sort en 1 — sonder par exécution produirait un faux positif (défaut constaté puis
// corrigé le 14/08/2026). `where` (win32) / `command -v` (posix) tranchent sans rien lancer.
function resoudreZap() {
  const force = process.env.WEBSEC_DAST_ZAP;
  const candidats = force ? [force] : ["zap-baseline.py", "zap.sh", "zap.bat"];
  for (const cmd of candidats) {
    try {
      if (cmd.includes("/") || cmd.includes("\\")) { if (fs.existsSync(cmd)) return cmd; continue; }
      const r = process.platform === "win32"
        ? spawnSync("where", [cmd], { encoding: "utf8", timeout: 10000 })
        : spawnSync("sh", ["-c", `command -v ${JSON.stringify(cmd)}`], { encoding: "utf8", timeout: 10000 });
      if (r.error === undefined && r.status === 0 && String(r.stdout || "").trim().length > 0) return cmd;
    } catch { /* candidat suivant */ }
  }
  return null;
}

const zapCmd = resoudreZap();
if (!zapCmd) {
  const ou = process.env.WEBSEC_DAST_ZAP ? `commande déclarée dans WEBSEC_DAST_ZAP (« ${process.env.WEBSEC_DAST_ZAP} ») injouable` : "aucun de zap-baseline.py / zap.sh / zap.bat dans le PATH";
  add("info", "DAST-SKIP", `OWASP ZAP absent de ce poste — ${ou}. Aucun scan lancé, aucun verdict rendu : SKIP motivé, jamais un PASS par défaut. Cet oracle n'installe jamais ZAP ; installer ZAP puis relancer, ou juger un rapport déjà produit avec --rapport <fichier.json>.`, origineCible);
  synthese.zap = { provenance: "aucune — ZAP introuvable sur le poste", rapport: null };
  sortir("SKIP", 2);
}

// ZAP présent : passe baseline (passive) contre la cible AUTORISÉE, rapport JSON en sortie.
const sortieRapport = `${process.env.TEMP || process.env.TMPDIR || "."}/zap-rapport-${Date.now()}.json`;
const argv = zapCmd.endsWith(".py")
  ? ["-t", cible, "-J", sortieRapport, "-I"]
  : ["-cmd", "-quickurl", cible, "-quickout", sortieRapport];
const r = spawnSync(zapCmd, argv, { encoding: "utf8", timeout: 900000, shell: process.platform === "win32" });
if (!fs.existsSync(sortieRapport)) {
  const extrait = String(r.stderr || r.stdout || "").slice(0, 300).trim();
  add("info", "DAST-SKIP", `ZAP (« ${zapCmd} ») lancé mais aucun rapport exploitable produit : ${extrait || "sortie vide"}. SKIP motivé — jamais un PASS faute de preuve.`, origineCible);
  synthese.zap = { provenance: `exécution ${zapCmd} en échec`, rapport: null };
  sortir("SKIP", 2);
}
jugerRapport(sortieRapport, `exécution ${zapCmd} (mode ${mode}) sur cible autorisée`);
