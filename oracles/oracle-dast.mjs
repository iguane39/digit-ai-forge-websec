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
//   sinon              : cherche ZAP sur le poste et lance le balayage du MODE demandé :
//     passif (défaut) → zap-baseline.py (araignée + règles passives, aucune attaque, AUCUN formulaire
//                       traité ni envoyé : `spider.processform=false` et `spider.postform=false`, TF-2498) ;
//     actif           → zap-full-scan.py (araignée + attaque active des URL trouvées), ou
//                       zap.sh / zap.bat (balayage rapide, qui attaque aussi) ; jamais baseline.
//   Un mode ne se rabat JAMAIS sur l'autre : un ZAP qui ne sait que baseline ne rend pas un
//   « actif » passif, un ZAP qui ne sait que le balayage rapide ne rend pas un « passif » qui
//   attaque — SKIP motivé dans les deux cas (TF-2444 : le mode actif lançait la passe passive).
// Point de départ d'une API (TF-2853) : `--openapi-fichier <définition.json|.yaml>` donne à ZAP la définition OpenAPI (3.0,
//   3.1 ou Swagger 2.0, en JSON ou en YAML) d'une API que l'araignée ne sait pas explorer (racine en 404, sans lien). Les deux
//   modes passent alors par zap-api-scan.py (image épinglée, WEBSEC_DAST_ZAP ou PATH) : `-f openapi`, et en passif `-S`, le mode
//   sûr qui saute l'attaque active (lu dans le script de l'image le 25/11/2026). L'import envoie UNE requête par opération, à sa
//   méthode, vers les serveurs que la définition écrit. Le garde-fou juge donc la définition AVANT tout lancement, fail-closed
//   (FAIL, rien n'est émis, chaque défaut nommé) : chaque serveur est une URL absolue en http(s), sans variable ni identifiant,
//   dont l'ORIGINE figure à l'identique dans `cibles` ; aucune URL serveur + chemin ne tombe sous une `exclusions` (la même
//   expression que celle que ZAP reçoit) ; un chemin à segment variable ({id}) est refusé dès que le mandat déclare une
//   exclusion ; toute référence `$ref` est interne (#/…) ; en mode passif, seules GET et HEAD sont admises. Le texte jugé est
//   celui que ZAP reçoit, copié dans le dossier de travail ; `-O` (remplacer le serveur) n'est pas passé, ZAP part des serveurs jugés.
// Options de balayage portées par le FICHIER d'autorisation (mêmes limites dans les deux modes) :
//   `en_tete_acces` {nom, valeur | valeur_env, jeton_service_access?} : en-tête ajouté à toute requête vers
//                     l'origine autorisée (la valeur ne sort jamais dans le verdict). Pour une cible derrière
//                     Cloudflare Access dont le jeton de service tient en UN en-tête, `jeton_service_access: true`
//                     déclare ce cas : le nom ne peut alors être que « Authorization » (l'API d'Access refuse tout
//                     autre nom) et la valeur est un objet JSON {"cf-access-client-id":"…","cf-access-client-secret":"…"}
//                     (TF-2649) ;
//   `debit_max_requetes_par_seconde` : un fil, un délai de ceil(1000/n) ms entre deux requêtes ;
//   `exclusions` : chemins (« /deconnexion ») dont aucune requête ne part, préfixe compris ;
//   `duree_max_minutes` : durée au-delà de laquelle ZAP est arrêté (TF-2486) ;
//   `plafond_requetes` : avec un débit, le nombre de requêtes dont la durée se déduit (défaut 1000).
// Une option présente et mal formée est un refus (FAIL), jamais un balayage sans la limite.
// Image ZAP épinglée (TF-2477) : la voie Docker lance une image désignée par son EMPREINTE (IMAGE_DEFAUT),
// jamais par l'étiquette mobile `stable`, qui change de règles sans que le référentiel le sache ; et elle
// passe `-silent` à ZAP, que zap-baseline.py et zap-full-scan.py lisent pour NE PAS lancer `-addonupdate` ni
// installer pscanrulesBeta / ascanrulesBeta depuis le réseau. Les règles qui tournent sont alors celles de
// l'image, listées dans referentiels/zap-regles.json ; une alerte dont le nom n'y figure pas est signalée
// (DAST-REGLE-HORS-IMAGE, info). Une image désignée par WEBSEC_DAST_IMAGE sans empreinte ni version est dite
// mobile au verdict (DAST-IMAGE-MOBILE) ; la mise à jour des modules d'un ZAP natif n'est pas maîtrisée, et
// le verdict le consigne (synthese.balayage.maj_modules). Même code pour un ZAP natif de forme baseline, complet ou
// api (TF-2884) : zap-baseline.py, zap-full-scan.py et zap-api-scan.py tirent eux-mêmes l'image ghcr.io/zaproxy/zaproxy:weekly
// hors d'un conteneur, sans option pour en désigner une autre ; le verdict le dit (synthese.balayage.image_tiree_par_le_script)
// et renvoie à la voie Docker de l'oracle. Les règles bêta que `-silent` ne laisse plus
// s'installer sont nommées au verdict (synthese.balayage.regles_beta, TF-2499) et cas par cas dans
// referentiels/wstg-cas.md ; aucune n'est réactivée par le réseau.
// Délai de ZAP (TF-2486) : `duree_max_minutes` s'il est déclaré ; sinon, avec un débit, le temps de
// `plafond_requetes` requêtes au délai imposé plus 5 min de démarrage, jamais moins de 30 min ; sinon
// 30 min. Il est toujours borné par la fin de la fenêtre d'autorisation. Quand il coupe ZAP, l'arbre
// de processus entier est arrêté (cmd.exe, java ; le conteneur Docker est retiré) et le SKIP le dit.
// Lancement sur Windows (TF-2485) : Node refuse de lancer un `.bat` ou un `.cmd` sans shell (EINVAL).
// L'oracle le passe à `cmd.exe /d /v:off /s /c` sur une ligne où chaque argument est entre guillemets,
// et refuse (SKIP) un argument qui porte `"` ou `%`, que cmd.exe interpréterait. ZAP natif tourne dans
// son propre dossier (`cwd`), avec `-dir` vers un dossier de travail jetable.
// ZAP absent du poste → verdict SKIP MOTIVÉ (exit 2), jamais un PASS de complaisance : c'est
// le chemin nominal sur un poste non équipé, et il est prouvé par fixture au self-test.
//
// Seuils par défaut : high=0, medium=0 (low/informational comptés en synthèse, non bloquants).
// Contrat : JSON {oracle, version, artefact, verdict, findings, non_juge, synthese,
// seuils_appliques} · exit 0 (PASS) / 1 (FAIL — refus du garde-fou, rapport illisible ou
// alertes au-delà des seuils) / 2 (SKIP — rien n'a pu être jugé : pas de cible, ou ZAP absent).
// Usage : node oracle-dast.mjs --cible <url> [--autorisation <f.json>] [--rapport <f.json>]
//                              [--seuils <f.json>] [--mode passif|actif] [--openapi-fichier <définition.json|.yaml>] [--json-only]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const VERSION = "0.5.1";
const ORACLE = "oracle-dast";
// `domaine` : champ du contrat d'oracle générique du pilot ; les deux oracles antérieurs de
// cette forge (exposition, sca) le précèdent et ne le portent pas encore.
const DOMAINE = "sécurité du produit web livré — scan dynamique (DAST) délégué à OWASP ZAP";
const NON_JUGE = [
  "la sincérité de l'autorisation : l'oracle vérifie une déclaration écrite et traçable, jamais le consentement réel du propriétaire de la cible",
  "tout ce qu'une passe passive ne voit pas : logique métier, autorisation/IDOR, chaînes d'exploitation multi-étapes, 0-day — une absence d'alerte n'est pas une absence de vulnérabilité",
  "la couverture réelle du parcours : les endpoints non atteints par le spider ZAP ne sont pas jugés (une cible authentifiée non configurée est explorée en surface seulement)",
  "la couverture d'une API : sans `--openapi-fichier`, l'araignée part de la racine et une API sans lien n'est pas explorée (un rapport à 0 site rend SKIP, DAST-RIEN-EXPLORE) ; avec `--openapi-fichier`, seules les opérations que la définition écrit sont importées, et ce qu'elle omet n'est pas balayé. Un rapport à 1 site est jugé comme tel, et le nombre de requêtes n'est pas dans le rapport JSON de ZAP, donc aucun seuil de requêtes n'est appliqué",
  "la définition OpenAPI au-delà de ce que le garde-fou en lit : serveurs, chemins, méthodes, références, rappels et webhooks sont jugés ; les schémas, les paramètres et les valeurs que ZAP leur donne (valeurs par défaut, selon l'aide de l'add-on openapi de l'image) ne le sont pas — c'est pourquoi un chemin à segment variable ({id}) est refusé dès que le mandat déclare une exclusion",
  "une définition OpenAPI distante (URL, `-openapiurl`) : non prise en charge, la définition se fournit en fichier local (`--openapi-fichier`), lu et jugé avant tout lancement ; `-O` de zap-api-scan.py (remplacer le serveur de la définition) n'est pas passé, ZAP part des serveurs que le garde-fou a jugés",
  "une graine d'URL (`--graine`) : non prise en charge ; zap-baseline.py et zap-full-scan.py ne prennent qu'une URL de départ (-t), et une liste demanderait un crochet (--hook) ou un plan d'automatisation, non éprouvés contre l'image épinglée — la voie `--openapi-fichier` couvre le cas qui bloquait, une API sans lien",
  "zap-baseline.py, zap-full-scan.py et zap-api-scan.py lancés hors d'un conteneur (PATH ou WEBSEC_DAST_ZAP) : chacun des trois scripts de l'image 2.17.0 lance alors lui-même l'image ghcr.io/zaproxy/zaproxy:weekly (docker pull), une étiquette mobile que l'oracle n'épingle pas et dont les règles ne sont pas lues par referentiels/zap-regles.json ; aucune de leurs options ne désigne une autre image, donc l'oracle ne peut pas leur passer l'image épinglée et le dit au verdict (DAST-IMAGE-MOBILE, TF-2884) ; seule la voie Docker de l'oracle lance l'image épinglée. Un script au nom inconnu (forme « script-inconnu ») n'est pas lu : l'oracle ne sait pas s'il tire une image",
  "l'exploitabilité et le tri des faux positifs : une alerte ZAP est un signal à qualifier par un humain, jamais un verdict d'exploitation",
  "la fraîcheur des règles d'un ZAP natif du poste (version des add-ons, base de règles) — non interrogée par cet oracle, qui ne coupe pas non plus sa mise à jour au lancement ; seule l'image Docker est épinglée et sans mise à jour (TF-2477)",
  "les règles bêta (pscanrulesBeta, ascanrulesBeta) sur la voie Docker : elles ne sont pas dans l'image épinglée et la mise à jour qui les installait est coupée, elles ne tournent donc pas",
  "la liste des règles de l'image (referentiels/zap-regles.json) : un surensemble des noms d'alerte, lu dans l'image par scripts/lire-regles-zap.mjs ; une alerte hors liste est signalée, une alerte dans la liste n'est pas pour autant prouvée émise par l'image",
  "la couche TLS (versions, suites, chaîne de certificat) — hors périmètre, cf. README §Limites",
  "la correction des alertes signalées — un constat, jamais un geste automatique",
  "l'exécution réelle sur une application riche et authentifiée : la preuve réelle (scripts/preuve-dast-actif.mjs) vise une cible de fixture locale de quelques routes, par l'image Docker de ZAP ; la voie OpenAPI (zap-api-scan.py de l'image) une fois, le 25/11/2026, contre la cible de fixture passive, par un banc non versionné (CHANGELOG.md) ; les formes natives (zap-baseline.py, zap-full-scan.py, zap-api-scan.py, zap.sh, zap.bat) ne sont prouvées que par un ZAP simulé qui enregistre sa ligne de commande — zap.bat et zap.sh par un vrai script qui l'enveloppe, jamais par le vrai ZAP natif (cf. README §Limites)",
  "la durée réelle d'un balayage : le délai déduit du débit suppose un plafond de requêtes (déclaré, ou 1000 par défaut) ; une cible plus vaste que ce plafond est coupée, et le SKIP le dit",
  "le débit tenu au millième près : la borne est un fil et un délai entre requêtes côté ZAP, pas un limiteur réseau ; une règle active qui émet plusieurs requêtes d'affilée reste soumise au même délai, mais le débit instantané n'est pas mesuré par cet oracle",
  "la discrétion de l'en-tête d'accès : sa valeur ne sort jamais du verdict, mais elle figure dans la ligne de commande du processus ZAP (ou docker) le temps du balayage, lisible dans la liste des processus du poste",
];

const args = process.argv.slice(2);
const jsonOnly = args.includes("--json-only");
const opt = (nom) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : null; };
const cible = opt("--cible");
const autorisationPath = opt("--autorisation") || process.env.WEBSEC_DAST_AUTORISATION || null;
const rapportPath = opt("--rapport");
const seuilsPath = opt("--seuils");
const mode = opt("--mode") || "passif";
// TF-2853 : définition OpenAPI locale, point de départ d'une API que l'araignée n'explore pas.
const openapiDemande = args.includes("--openapi-fichier");
const openapiChemin = opt("--openapi-fichier");

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
  add("info", "DAST-USAGE", "usage : node oracle-dast.mjs --cible <url> --autorisation <fichier.json> [--rapport <zap.json>] [--seuils <f.json>] [--mode passif|actif] [--openapi-fichier <définition.json|.yaml>]", null);
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
// Un BOM en tête n'est PAS du contenu : sur Windows, tout fichier écrit par le défaut de
// PowerShell (`Out-File -Encoding utf8`) en porte un, et `JSON.parse` le refuse. Constaté le
// 14/08 en écrivant un vrai mandat : l'autorisation était rejetée pour un caractère invisible,
// avec un message incompréhensible. Le retirer ne relâche RIEN — le reste du contrôle est
// inchangé, et un JSON réellement invalide est toujours refusé net.
const lireJson = (chemin) => JSON.parse(fs.readFileSync(chemin, "utf8").replace(/^﻿/, ""));

let autz = null;
try { autz = lireJson(autorisationPath); }
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

// Règles de l'image épinglée (TF-2477) : referentiels/zap-regles.json, lu dans l'image par
// scripts/lire-regles-zap.mjs. Un nom d'alerte absent de la liste n'est jamais une règle de cette image ;
// « Nom (variante) » est admis quand « Nom » est listé (ZAP ajoute parfois une précision entre parenthèses).
const REGLES_IMAGE = process.env.WEBSEC_DAST_REGLES || path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "referentiels", "zap-regles.json");
// TF-2853 : zap-api-scan.py charge deux scripts de l'image (/home/zap/.ZAP_D/scripts/scripts/httpsender/AlertOnHttpResponseCodeErrors.js
// et AlertOnUnexpectedContentTypes.js, lus le 25/11/2026). Leurs trois alertes ne sont la règle d'aucun add-on, donc absentes de la liste,
// et viennent pourtant de l'image : le balayage réel du 25/11/2026 sur la cible de fixture les a levées en mode actif. Elles ne sont pas
// signalées hors image quand le balayage part d'une définition OpenAPI, et seulement alors (zap-baseline.py et zap-full-scan.py ne les chargent pas).
const ALERTES_SCRIPTS_API = ["A Client Error response code was returned by the server", "A Server Error response code was returned by the server", "Unexpected Content-Type was returned"];
function chargerReglesImage() {
  try {
    const j = JSON.parse(fs.readFileSync(REGLES_IMAGE, "utf8").replace(/^﻿/, ""));
    const noms = new Set([j.actives, j.passives, j.autres].flatMap((g) => Object.values(g || {}).flat()));
    if (!noms.size) return { erreur: "aucun nom de règle dans le fichier" };
    return { image: j.image, noms };
  } catch (e) { return { erreur: e.message }; }
}
function signalerReglesHorsImage(alertes, contexte) {
  const liste = chargerReglesImage();
  if (liste.erreur) {
    add("info", "DAST-REGLES-ILLISIBLES", `liste des règles de l'image épinglée illisible (${REGLES_IMAGE} : ${liste.erreur}) : aucune alerte comparée, une règle levée hors de l'image ne serait pas signalée.`, REGLES_IMAGE);
    synthese.zap.regles_image = { comparees: false, motif: liste.erreur };
    return;
  }
  const parScriptApi = (nom) => Boolean(contexte.openapi) && ALERTES_SCRIPTS_API.includes(nom);
  const connue = (nom) => liste.noms.has(nom) || parScriptApi(nom) || [...liste.noms].some((n) => n.length >= 8 && nom.startsWith(`${n} (`));
  const hors = [...new Set(alertes.map((a) => a.nom))].filter((nom) => !connue(nom)).sort();
  const cause = contexte.imageEpinglee
    ? "l'image épinglée ne porte pas cette règle : un module a été chargé hors de l'image, ou l'image qui a tourné n'est pas celle qui est listée"
    : "ce rapport ne vient pas, ou pas avec certitude, de l'image épinglée (rapport fourni, ZAP natif ou autre image) : sa liste de règles peut différer";
  for (const nom of hors) {
    add("info", "DAST-REGLE-HORS-IMAGE", `alerte « ${nom} » absente de la liste des règles de l'image ZAP épinglée (${liste.image.zap}, ${liste.image.empreinte.slice(0, 19)}…) : ${cause}.`, REGLES_IMAGE);
  }
  synthese.zap.regles_image = { image: liste.image.reference, zap: liste.image.zap, comparees: true, alertes_comparees: new Set(alertes.map((a) => a.nom)).size, hors_liste: hors };
  if (contexte.openapi) synthese.zap.regles_image.alertes_des_scripts_de_zap_api_scan = [...new Set(alertes.map((a) => a.nom))].filter(parScriptApi).sort();
}

function jugerRapport(chemin, provenance, contexte = {}) {
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
  // TF-2655 : un rapport à 0 site n'est pas un rapport propre, c'est un balayage qui n'a rien exploré (mesuré le 13/11/2026 chez un
  // produit : API balayée depuis sa racine, 404 sans lien, ZAP termine en 60 s, 0 site, 0 alerte, et l'oracle rendait PASS).
  if (sites.length === 0) {
    // TF-2853 : le message dit la voie d'une API, `--openapi-fichier` ; parti d'une définition, il dit que ses opérations n'ont rien donné.
    add("info", "DAST-RIEN-EXPLORE", contexte.openapi
      ? "rapport ZAP à 0 site alors que ZAP partait de la définition OpenAPI fournie (--openapi-fichier) : aucune de ses opérations n'a abouti (serveurs injoignables depuis ZAP, ou réponses refusées), donc l'absence d'alerte ne dit rien de la cible. SKIP motivé — jamais un PASS sur 0 site balayé."
      : "rapport ZAP à 0 site : ZAP n'a rien exploré de la cible (racine sans lien, API sans page à suivre, ou cible injoignable), donc l'absence d'alerte ne dit rien de la cible. SKIP motivé — jamais un PASS sur 0 site balayé. Pour une API, l'araignée n'a pas de page d'où partir : fournir sa définition OpenAPI en fichier local par `--openapi-fichier <définition.json|.yaml>`, que zap-api-scan.py importe une fois chacun de ses serveurs et de ses chemins contrôlé contre l'autorisation.", chemin);
    sortir("SKIP", 2);
  }
  signalerReglesHorsImage(alertes, contexte);
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

// TF-2853 : la définition OpenAPI est une entrée du balayage ; la voie --rapport n'en lance aucun, les deux s'excluent.
if (openapiDemande && rapportPath) {
  add("bloquant", "DAST-OPENAPI-USAGE", "`--openapi-fichier` et `--rapport` s'excluent : la voie --rapport juge un rapport déjà produit et ne lance pas ZAP, la définition n'y servirait à rien. Refus net — retirer l'une des deux options.", openapiChemin || null);
  sortir("FAIL", 1);
}

// Voie A — rapport déjà produit : aucune émission vers la cible.
if (rapportPath) {
  if (!fs.existsSync(rapportPath)) {
    add("bloquant", "DAST-RAPPORT", `rapport ZAP introuvable : ${rapportPath}. Refus net — aucun verdict sans artefact.`, rapportPath);
    sortir("FAIL", 1);
  }
  jugerRapport(rapportPath, "rapport fourni (--rapport) — aucun scan lancé par cet oracle");
}

// ── Options de balayage de l'autorisation (TF-2444) ──────────────────────────
// Lues APRÈS la voie rapport (rien n'est émis, donc rien à limiter) et AVANT toute émission : une
// option présente et mal formée refuse le balayage, elle ne l'autorise pas sans sa limite. Aucun
// message ne cite la valeur de l'en-tête.
const invalides = [];
let enTeteAcces = null;
let debit = null;
let exclusions = [];
if (autz.en_tete_acces !== undefined) {
  const ea = autz.en_tete_acces;
  const nom = ea && typeof ea === "object" ? ea.nom : undefined;
  if (typeof nom !== "string" || !/^[A-Za-z0-9-]+$/.test(nom)) {
    invalides.push("en_tete_acces.nom (nom d'en-tête HTTP attendu : lettres, chiffres et tirets)");
  } else if (ea.jeton_service_access !== undefined && typeof ea.jeton_service_access !== "boolean") {
    invalides.push("en_tete_acces.jeton_service_access (booléen attendu : true pour une cible derrière Cloudflare Access)");
  } else if (ea.jeton_service_access === true && nom.toLowerCase() !== "authorization") {
    // TF-2649 : l'API de Cloudflare refuse tout autre nom (« read_service_tokens_from_header must be one of [Authorization] »),
    // et sa documentation ne le dit pas. Un autre nom ne passerait pas Access : le balayage n'aurait rien exploré de la cible.
    invalides.push(`en_tete_acces.nom (« ${nom} » refusé pour un jeton de service Cloudflare Access en un seul en-tête : Access ne lit ce jeton que dans « Authorization », et sa valeur est un objet JSON {"cf-access-client-id":"…","cf-access-client-secret":"…"})`);
  } else {
    const aValeur = typeof ea.valeur === "string" && ea.valeur !== "";
    const aEnv = typeof ea.valeur_env === "string" && ea.valeur_env !== "";
    if (aValeur === aEnv) {
      invalides.push("en_tete_acces (exactement un de `valeur` ou `valeur_env` est attendu)");
    } else {
      const valeur = aValeur ? ea.valeur : process.env[ea.valeur_env];
      if (!valeur) invalides.push(`en_tete_acces.valeur_env (variable « ${ea.valeur_env} » absente ou vide : un balayage authentifié ne part pas sans son en-tête)`);
      else if (/[\x00-\x1f\x7f]/.test(valeur)) invalides.push("en_tete_acces (la valeur porte un caractère de contrôle)");
      else enTeteAcces = { nom, valeur, source: aValeur ? "fichier d'autorisation" : `variable ${ea.valeur_env}` };
    }
  }
}
if (autz.debit_max_requetes_par_seconde !== undefined) {
  const d = autz.debit_max_requetes_par_seconde;
  if (typeof d !== "number" || !Number.isFinite(d) || d <= 0 || d > 1000) invalides.push("debit_max_requetes_par_seconde (nombre supérieur à 0 et au plus 1000)");
  else debit = { max_requetes_par_seconde: d, delai_ms: Math.ceil(1000 / d) };
}
if (autz.exclusions !== undefined) {
  if (!Array.isArray(autz.exclusions) || autz.exclusions.some((e) => typeof e !== "string" || !e.startsWith("/") || /\s/.test(e))) {
    invalides.push("exclusions (liste de chemins commençant par « / », sans espace)");
  } else exclusions = autz.exclusions;
}
let dureeMaxMinutes = null;
if (autz.duree_max_minutes !== undefined) {
  const d = autz.duree_max_minutes;
  if (typeof d !== "number" || !Number.isFinite(d) || d <= 0 || d > 1440) invalides.push("duree_max_minutes (nombre supérieur à 0 et au plus 1440, soit 24 h)");
  else dureeMaxMinutes = d;
}
let plafondRequetes = null;
if (autz.plafond_requetes !== undefined) {
  const p = autz.plafond_requetes;
  if (!Number.isInteger(p) || p < 1 || p > 1000000) invalides.push("plafond_requetes (entier de 1 à 1 000 000)");
  else if (autz.debit_max_requetes_par_seconde === undefined) invalides.push("plafond_requetes (sans debit_max_requetes_par_seconde, aucune durée ne s'en déduit : déclarer le débit, ou duree_max_minutes)");
  else plafondRequetes = p;
}
if (invalides.length) {
  add("bloquant", "DAST-AUTZ-CHAMPS", `option(s) de balayage invalide(s) : ${invalides.join(" ; ")}. Refus net — un balayage ne part jamais sans une limite que le mandat avait posée.`, autorisationPath);
  sortir("FAIL", 1);
}

// ── Définition OpenAPI (TF-2853) ─────────────────────────────────────────────
// RP-74 (25/11/2026) : sur une API dont la racine rend 404 sans lien, l'araignée n'a rien à suivre et chaque balayage rendait SKIP
// (DAST-RIEN-EXPLORE). zap-api-scan.py importe la définition et envoie une requête par opération, à sa méthode, vers les serveurs
// qu'elle écrit (script et aide de l'add-on openapi 57 lus dans l'image épinglée le 25/11/2026, sans réseau). La définition se juge
// donc ici, après les options du mandat (ses exclusions) et avant tout lancement : un seul défaut refuse tout, chaque défaut est
// nommé, et rien n'est émis.
// L'expression d'une exclusion sur une origine est la même pour ZAP (globalexcludeurl, plus bas) et pour ce garde-fou.
const echapperRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const regexExclusion = (origine, chemin) => `^${echapperRegex(origine)}${echapperRegex(chemin)}.*`;
const METHODES_HTTP = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
// Le mode passif n'envoie aucune requête qui agit (TF-2498) ; l'import enverrait chaque opération telle quelle.
const METHODES_PASSIF = new Set(["GET", "HEAD"]);
const CLES_ELEMENT_DE_CHEMIN = new Set(["parameters", "servers", "summary", "description"]);
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
// Un chemin se lit à la lettre : rien que ZAP, Java ou le serveur pourraient réécrire autrement que l'oracle ne le lit.
function defautDeChemin(p) {
  if (typeof p !== "string" || !p.startsWith("/")) return "ne commence pas par « / »";
  if (/[\s\\?#%]/.test(p)) return "porte une espace, « \\ », « ? », « # » ou « % »";
  if (p.includes("//")) return "porte « // »";
  if (/(^|\/)\.\.?(\/|$)/.test(p)) return "porte un segment « . » ou « .. »";
  if (/[^A-Za-z0-9\-._~!$&'()*+,;=:@/{}]/.test(p)) return "porte un caractère hors de l'alphabet d'un chemin d'URL";
  if (/[{}]/.test(p.replace(/\{[^{}/]+\}/g, ""))) return "porte une accolade hors d'un segment variable {nom}";
  return null;
}
// Un serveur : URL absolue en http(s), « hôte[:port] » seul dans l'autorité, chemin lu à la lettre, sans variable.
function lireServeur(url) {
  if (typeof url !== "string" || url === "") return { defaut: "URL absente" };
  if (/[{}]/.test(url)) return { defaut: "URL à variables ({…}) : écrire l'URL résolue" };
  const m = /^(https?):\/\/([^/?#]*)(\/[^?#]*)?$/i.exec(url);
  if (!m) return { defaut: "URL relative, hors http(s), ou qui porte « ? » ou « # » : une définition lue d'un fichier n'a pas d'origine d'où la résoudre" };
  if (!/^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?$/.test(m[2])) return { defaut: "autorité qui n'est pas « hôte[:port] » (identifiant, « @ », « \\ » ou caractère inattendu)" };
  const chemin = m[3] || "";
  const d = chemin && chemin !== "/" ? defautDeChemin(chemin) : null;
  if (d) return { defaut: `chemin de serveur qui ${d}` };
  let u;
  try { u = new URL(url); } catch (e) { return { defaut: `URL illisible (${e.message})` }; }
  return { origine: u.origin, chemin };
}

let definition = null;
let originesBalayees = [origineCible];
if (openapiDemande) {
  const fichierDef = openapiChemin && !openapiChemin.startsWith("--") ? openapiChemin : null;
  const illisible = (motif) => {
    add("bloquant", "DAST-OPENAPI-ILLISIBLE", `définition OpenAPI ${motif}. Refus net — aucun balayage ne part d'une définition que l'oracle n'a pas pu juger, rien n'a été émis vers la cible.`, fichierDef);
    synthese.openapi = { fichier: fichierDef, verdict: "refusée" };
    sortir("FAIL", 1);
  };
  if (!fichierDef) illisible("non désignée : `--openapi-fichier <fichier>` attend le chemin d'un fichier local, en JSON ou en YAML");
  if (!fs.existsSync(fichierDef)) illisible(`introuvable : ${fichierDef}`);
  let texte = "";
  try { texte = fs.readFileSync(fichierDef, "utf8").replace(/^﻿/, ""); }
  catch (e) { illisible(`illisible (${e.code || e.message}) : ${fichierDef}`); }
  const format = texte.trimStart().startsWith("{") ? "json" : "yaml";
  let doc = null;
  if (format === "json") {
    try { doc = JSON.parse(texte); } catch (e) { illisible(`en JSON invalide (${e.message}) : ${fichierDef}`); }
  } else {
    // Le lecteur YAML natif d'oracle-workflows, sans dépendance : il refuse ancres, alias, étiquettes, clés complexes et clés en
    // double, que ZAP lirait peut-être autrement que lui. Chargé ici seulement : une définition JSON n'en dépend pas.
    const { lireYaml } = await import("./oracle-workflows.mjs");
    try { doc = lireYaml(texte).valeur; } catch (e) { illisible(`en YAML que le lecteur de l'oracle refuse (${e.message}${e.ligne ? `, ligne ${e.ligne}` : ""}) : ${fichierDef}`); }
  }
  if (!estObjet(doc)) illisible(`sans objet à sa racine : ${fichierDef}`);
  const version = typeof doc.openapi === "string" && /^3\.[01](\.\d+)?$/.test(doc.openapi) ? doc.openapi : (doc.swagger === "2.0" ? "2.0" : null);
  if (!version) illisible(`de version non prise en charge (« openapi » 3.0 ou 3.1, ou « swagger » "2.0", attendus ; lu ${JSON.stringify(doc.openapi ?? doc.swagger ?? doc.swaggerVersion ?? null)}) : ${fichierDef}`);
  if (!estObjet(doc.paths) || !Object.keys(doc.paths).length) illisible(`sans chemin (« paths » vide ou absent) : ZAP n'aurait rien à importer — ${fichierDef}`);

  const refus = [];
  const refuser = (regle, msg, where) => { if (!refus.some((x) => x.msg === msg)) refus.push({ regle, msg, where }); };
  const structure = (msg) => refuser("DAST-OPENAPI-ILLISIBLE", msg, fichierDef);
  const hors = (msg, where) => refuser("DAST-OPENAPI-HORS-PERIMETRE", msg, where);
  // Références internes seulement : swagger-parser chargerait une référence externe depuis le disque ou le réseau, hors du garde-fou.
  for (const pile = [doc]; pile.length;) {
    const v = pile.pop();
    if (Array.isArray(v)) { pile.push(...v); continue; }
    if (!estObjet(v)) continue;
    for (const [cle, x] of Object.entries(v)) {
      if (cle === "$ref" && !(typeof x === "string" && x.startsWith("#"))) {
        const ref = typeof x === "string" ? x : JSON.stringify(x);
        hors(`référence « ${ref} » qui n'est pas interne (#/…) : ZAP la chargerait depuis le disque ou le réseau, hors du garde-fou ; recopier ce qu'elle désigne dans la définition`, ref);
      }
      pile.push(x);
    }
  }
  if (doc.webhooks !== undefined) hors("« webhooks » : le garde-fou ne sait pas où ZAP les enverrait, il ne les admet pas ; les retirer de la définition", fichierDef);
  // Serveurs : de la racine, d'un élément de chemin ou d'une opération (OpenAPI 3) ; host, basePath et schemes (Swagger 2.0).
  const serveurs = new Map();
  const serveur = (url) => {
    const cle = typeof url === "string" ? url : JSON.stringify(url ?? null);
    if (!serveurs.has(cle)) serveurs.set(cle, lireServeur(url));
    return serveurs.get(cle);
  };
  const declares = (liste) => (Array.isArray(liste) && liste.length ? liste : null);
  let basePath = "";
  if (version === "2.0") {
    if (typeof doc.host !== "string" || doc.host === "") hors("Swagger 2.0 sans « host » : une définition lue d'un fichier n'a pas d'hôte d'où la résoudre ; écrire l'hôte d'une des cibles autorisées", fichierDef);
    const dbp = doc.basePath === undefined || doc.basePath === "/" ? null : defautDeChemin(doc.basePath);
    if (dbp) hors(`« basePath » « ${doc.basePath} » qui ${dbp}`, fichierDef);
    else if (doc.basePath !== undefined && doc.basePath !== "/") basePath = doc.basePath;
  }
  const urlsDe = (element, op) => {
    if (version !== "2.0") return (declares(op.servers) || declares(element.servers) || declares(doc.servers) || []).map((s) => (estObjet(s) ? s.url : undefined));
    if (typeof doc.host !== "string" || doc.host === "") return [];
    return (declares(op.schemes) || declares(doc.schemes) || []).map((s) => `${s}://${doc.host}${basePath}`);
  };
  const operations = [];
  for (const [chemin, element] of Object.entries(doc.paths)) {
    const dc = defautDeChemin(chemin);
    if (dc) { hors(`chemin « ${chemin} » qui ${dc} : le garde-fou ne peut pas prouver l'URL que ZAP en tirerait`, chemin); continue; }
    if (!estObjet(element)) { structure(`l'élément du chemin « ${chemin} » n'est pas un objet`); continue; }
    if (element.$ref !== undefined) { hors(`chemin « ${chemin} » décrit par référence (« $ref ») : le garde-fou ne suit pas les références d'éléments de chemin, écrire ses opérations en clair`, chemin); continue; }
    for (const [cle, op] of Object.entries(element)) {
      if (CLES_ELEMENT_DE_CHEMIN.has(cle) || cle.startsWith("x-")) continue;
      if (!METHODES_HTTP.includes(cle)) { structure(`clé « ${cle} » inattendue dans le chemin « ${chemin} » : une méthode s'écrit en minuscules (${METHODES_HTTP.join(", ")})`); continue; }
      const methode = cle.toUpperCase();
      if (!estObjet(op)) { structure(`l'opération ${methode} ${chemin} n'est pas un objet`); continue; }
      if (op.callbacks !== undefined) hors(`l'opération ${methode} ${chemin} déclare des rappels (« callbacks ») : le garde-fou ne sait pas où ZAP les enverrait, il ne les admet pas ; les retirer de la définition`, chemin);
      operations.push({ methode, chemin, serveurs: urlsDe(element, op).map((u) => ({ url: u, ...serveur(u) })) });
    }
  }
  if (!operations.length && !refus.length) structure("sans opération (get, post…) sous « paths » : ZAP n'aurait rien à importer");
  for (const [url, s] of serveurs) {
    if (s.defaut) { hors(`serveur « ${url} » : ${s.defaut}`, url); continue; }
    if (!originesAutorisees.includes(s.origine)) { hors(`serveur « ${url} » : son origine « ${s.origine} » ne figure pas dans les cibles déclarées [${originesAutorisees.join(", ")}] du mandat « ${autz.mandat} » (comparaison exacte d'origine, sans joker)`, url); continue; }
    const e = exclusions.find((x) => new RegExp(regexExclusion(s.origine, x)).test(`${s.origine}${s.chemin}`));
    if (e) hors(`serveur « ${url} » : il tombe sous l'exclusion « ${e} » du mandat, aucune requête ne doit partir vers lui`, url);
  }
  for (const op of operations) {
    if (!op.serveurs.length) { hors(`${op.methode} ${op.chemin} : aucun serveur déclaré (« servers » en OpenAPI 3, « host » et « schemes » en Swagger 2.0) ; une définition lue d'un fichier n'a pas d'origine d'où la résoudre`, op.chemin); continue; }
    const valides = op.serveurs.filter((s) => !s.defaut && originesAutorisees.includes(s.origine));
    const urlDe = (s) => `${s.origine}${s.chemin.replace(/\/+$/, "")}${op.chemin}`;
    for (const s of valides) {
      if (op.chemin.includes("{") && exclusions.length) {
        hors(`${op.methode} ${urlDe(s)} : chemin à segment variable alors que le mandat déclare des exclusions (${exclusions.join(", ")}) ; la valeur que ZAP donnera au segment n'est pas connue du garde-fou, qui ne peut pas prouver que l'URL les évite. Écrire le chemin avec sa valeur, ou retirer l'opération`, urlDe(s));
        continue;
      }
      // l'URL normalisée et l'URL telle qu'écrite (barre finale du serveur comprise) : l'une ou l'autre sous une exclusion suffit à refuser
      const formes = [urlDe(s), `${s.origine}${s.chemin}${op.chemin}`];
      const e = exclusions.find((x) => formes.some((f) => new RegExp(regexExclusion(s.origine, x)).test(f)));
      if (e) hors(`${op.methode} ${urlDe(s)} tombe sous l'exclusion « ${e} » du mandat : aucune requête ne doit partir vers ce chemin. Retirer l'opération de la définition`, urlDe(s));
    }
    if (mode === "passif" && !METHODES_PASSIF.has(op.methode)) {
      const url = valides.length ? urlDe(valides[0]) : op.chemin;
      refuser("DAST-OPENAPI-METHODE", `${op.methode} ${url} en mode passif : l'import de la définition enverrait cette requête telle quelle, et le mode passif n'envoie que GET et HEAD (aucune requête qui agit, TF-2498). Retirer l'opération de la définition pour la passe passive, ou demander le mode actif sous \`actif_autorise: true\``, url);
    }
  }
  const origines = [...new Set(operations.flatMap((o) => o.serveurs.filter((s) => !s.defaut).map((s) => s.origine)))];
  const methodes = {};
  for (const o of operations) methodes[o.methode] = (methodes[o.methode] || 0) + 1;
  synthese.openapi = { fichier: fichierDef, format, version, serveurs: [...serveurs.keys()], origines, operations: operations.length, methodes };
  if (refus.length) {
    for (const x of refus) add("bloquant", x.regle, x.msg, x.where);
    add("info", "DAST-OPENAPI", `définition OpenAPI refusée : ${refus.length} défaut(s) ci-dessus, chacun nommé ; un seul suffit à refuser tout le lancement. Rien n'a été émis vers la cible.`, fichierDef);
    synthese.openapi.verdict = "refusée";
    sortir("FAIL", 1);
  }
  synthese.openapi.verdict = "jugée dans le périmètre";
  // Le texte jugé est celui que ZAP reçoit : un JSON réécrit tel que l'oracle l'a lu (sans clé en double), un YAML tel quel.
  definition = { fichier: fichierDef, format, version, nom: `definition-openapi.${format}`, contenu: format === "json" ? `${JSON.stringify(doc, null, 2)}\n` : texte };
  originesBalayees = [origineCible, ...origines.filter((o) => o !== origineCible)];
}
// ── Délai de ZAP (TF-2486) ───────────────────────────────────────────────────
// Le constat : un délai fixe de 30 min coupait avant son rapport tout balayage dont le mandat borne
// le débit. À 10 requêtes par minute (6 000 ms entre deux), 30 min font environ 299 requêtes ; le
// banc en a compté 891 pour une cible de 4 routes. Le plafond par défaut, 1000, couvre ce banc.
const DUREE_DEFAUT_MIN = 30;
const DEMARRAGE_MIN = 5;
const PLAFOND_REQUETES_DEFAUT = 1000;
let delaiMinutes;
let delaiSource;
if (dureeMaxMinutes !== null) {
  delaiMinutes = dureeMaxMinutes;
  delaiSource = "duree_max_minutes du mandat";
} else if (debit) {
  const plafond = plafondRequetes ?? PLAFOND_REQUETES_DEFAUT;
  const deduit = Math.ceil((plafond * debit.delai_ms) / 60000) + DEMARRAGE_MIN;
  delaiMinutes = Math.max(DUREE_DEFAUT_MIN, deduit);
  delaiSource = `déduit du débit : ${plafond} requêtes × ${debit.delai_ms} ms + ${DEMARRAGE_MIN} min de démarrage`
    + `${plafondRequetes === null ? " (plafond par défaut)" : ""}${deduit < DUREE_DEFAUT_MIN ? `, relevé au plancher de ${DUREE_DEFAUT_MIN} min` : ""}`;
} else {
  delaiMinutes = DUREE_DEFAUT_MIN;
  delaiSource = `défaut de ${DUREE_DEFAUT_MIN} min (ni débit ni duree_max_minutes dans le mandat)`;
}
const resteFenetreMin = (fin.getTime() - Date.now()) / 60000;
if (resteFenetreMin < delaiMinutes) {
  delaiMinutes = Math.max(resteFenetreMin, 0);
  delaiSource += " ; borné par la fin de la fenêtre d'autorisation";
}
const delaiMs = Math.max(1, Math.floor(delaiMinutes * 60000));
const arrondi = (m) => Math.round(m * 100) / 100;

// Le mode passif ne traite ni n'envoie aucun formulaire (TF-2498) : `spider.processform` coupe le traitement des formulaires par
// l'araignée, `spider.postform` l'envoi de ceux qui sont en POST. Les deux, pour que l'intention ne dépende pas de la valeur
// par défaut de l'une.
const OPTIONS_PASSIF_SANS_FORMULAIRE = ["spider.processform=false", "spider.postform=false"];
// Titre de la section de referentiels/wstg-cas.md qui dit, cas par cas, ce que la voie Docker ne joue plus depuis `-silent` (TF-2499) ;
// le verdict la nomme, et le self-test refuse un verdict qui renvoie à une section absente.
const SECTION_REGLES_BETA = "Ce que la voie Docker ne joue plus depuis -silent";

synthese.balayage = {
  scan: mode,
  en_tete_acces: enTeteAcces ? { nom: enTeteAcces.nom, valeur: "(masquée)", source: enTeteAcces.source } : null,
  debit, exclusions,
  formulaires: mode === "passif"
    ? `ni traités ni envoyés (${OPTIONS_PASSIF_SANS_FORMULAIRE.join(", ")}) : aucune requête POST ne part de l'araignée`
    : "réglage par défaut de ZAP, non modifié par l'oracle en mode actif (seule `exclusions` empêche l'envoi d'un formulaire)",
  delai_max_minutes: arrondi(delaiMinutes), delai_source: delaiSource,
};
// TF-2853 : ce que la voie OpenAPI envoie, dit au verdict (l'import, l'attaque, le serveur).
if (definition) {
  synthese.balayage.openapi = {
    definition: definition.fichier, transmise: definition.nom, format: definition.format, version: definition.version,
    requetes: `l'import envoie une requête par opération de la définition, à sa méthode, vers les serveurs qu'elle écrit ; ${mode === "passif" ? "GET et HEAD seulement en mode passif (garde-fou)" : "toutes les méthodes en mode actif (GET et HEAD seulement en mode passif)"}`,
    attaque_active: mode === "actif" ? "politique API-Minimal de zap-api-scan.py" : "aucune : -S (mode sûr) saute l'attaque active",
    remplacement_du_serveur: "aucun : -O n'est pas passé, ZAP part des serveurs jugés",
  };
}

// Options passées à ZAP en paires clé=valeur (`-config clé=valeur`), les mêmes pour toutes les formes.
function optionsZap() {
  const o = [];
  if (enTeteAcces) {
    const r = "replacer.full_list(0).";
    o.push(`${r}description=websec acces ${enTeteAcces.nom}`, `${r}enabled=true`, `${r}matchtype=REQ_HEADER`,
      `${r}matchstr=${enTeteAcces.nom}`, `${r}regex=false`, `${r}replacement=${enTeteAcces.valeur}`,
      `${r}url=^${echapperRegex(origineCible)}(/.*)?$`);
  }
  // TF-2498 : le mode passif ne soumet aucun formulaire. L'araignée de ZAP traite sinon les formulaires qu'elle trouve et
  // POSTE celui de la cible (mesuré le 13/11/2026 : POST /connexion, corps identifiant=ZAP&secret=ZAP) : une passe qui
  // « n'attaque pas » n'en était pas pour autant en lecture seule. Le mode actif garde le comportement de ZAP, sous l'autorisation
  // écrite qui l'exige (`actif_autorise`) ; seule `exclusions` y empêche un envoi.
  if (mode === "passif") o.push(...OPTIONS_PASSIF_SANS_FORMULAIRE);
  if (debit) {
    o.push("scanner.threadPerHost=1", `scanner.delayInMs=${debit.delai_ms}`, "spider.thread=1", `spider.requestwait=${debit.delai_ms}`);
  }
  // TF-2853 : une définition OpenAPI peut viser plusieurs origines de `cibles` ; chaque exclusion vaut sur chacune. Sans définition,
  // la seule origine balayée est celle de la cible, et la liste est celle d'avant.
  let n = 0;
  for (const origine of originesBalayees) {
    for (const chemin of exclusions) {
      const g = `globalexcludeurl.url_list.url(${n++}).`;
      o.push(`${g}description=websec exclusion ${chemin}${originesBalayees.length > 1 ? ` sur ${origine}` : ""}`, `${g}enabled=true`, `${g}regex=${regexExclusion(origine, chemin)}`);
    }
  }
  return o;
}
const optionsZapListe = optionsZap();
// La ligne de commande peut porter la valeur de l'en-tête : tout texte repris de ZAP la masque.
const masquer = (t) => (enTeteAcces ? String(t).split(enTeteAcces.valeur).join("(masquée)") : String(t));

// Voie B — exécution ZAP sur le poste.
// La détection RÉSOUT la commande dans le PATH, elle ne l'exécute jamais « pour voir » : sur
// Windows, une commande inexistante sort en 1 avec un message sur stderr, indiscernable d'un
// `-h` qui sort en 1 — sonder par exécution produirait un faux positif (défaut constaté puis
// corrigé le 14/08/2026). `where` (win32) / `command -v` (posix) tranchent sans rien lancer.
function resoluDansLePath(cmd) {
  if (cmd.includes("/") || cmd.includes("\\")) return fs.existsSync(cmd);
  const r = process.platform === "win32"
    ? spawnSync("where", [cmd], { encoding: "utf8", timeout: 10000 })
    : spawnSync("sh", ["-c", `command -v ${JSON.stringify(cmd)}`], { encoding: "utf8", timeout: 10000 });
  return r.error === undefined && r.status === 0 && String(r.stdout || "").trim().length > 0;
}

// Chemin complet d'une commande résolue : il fixe le dossier courant de ZAP natif, dont zap.bat a
// besoin (TF-2485). Même résolution que ci-dessus, sans rien exécuter de la commande elle-même.
function cheminResolu(cmd) {
  if (cmd.includes("/") || cmd.includes("\\")) return path.resolve(cmd);
  const r = process.platform === "win32"
    ? spawnSync("where", [cmd], { encoding: "utf8", timeout: 10000 })
    : spawnSync("sh", ["-c", `command -v ${JSON.stringify(cmd)}`], { encoding: "utf8", timeout: 10000 });
  const premiere = String(r.stdout || "").split(/\r?\n/).map((l) => l.trim()).find(Boolean);
  return premiere ? path.resolve(premiere) : null;
}

// Voie DOCKER (14/08, TF-0206) : c'est la façon dont ZAP est réellement exécuté en chaîne
// d'intégration, et sur un poste Windows c'est souvent la SEULE joignable — l'installation
// native réclame un JRE, donc une élévation. L'image officielle porte `zap-baseline.py` ;
// l'oracle ne la construit ni ne la télécharge JAMAIS : elle doit être déjà présente
// (`docker pull` de la référence ci-dessous), sans quoi un oracle « installerait » son
// propre outillage à l'insu de l'appelant.
// TF-2477 : l'image est épinglée par EMPREINTE (ZAP 2.17.0, créée le 07/08/2026, lue sur ce poste), non par
// l'étiquette mobile `stable` qui avait changé de règles sans que le référentiel le sache. Changer d'image
// se décide : relire ses règles (`node scripts/lire-regles-zap.mjs --image <référence> --ecrire`), puis
// changer cette constante et referentiels/zap-regles.json dans le même commit — le self-test refuse l'écart.
const IMAGE_DEFAUT = "ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef";
// Épinglée : par empreinte (`@sha256:…`) ou par version complète (`:2.17.0`), jamais par une étiquette mobile.
const imageEpinglee = (ref) => /@sha256:[0-9a-f]{64}$/.test(ref) || /:\d+\.\d+\.\d+$/.test(ref);
// TF-2884 : l'image que les scripts zap-baseline.py, zap-full-scan.py et zap-api-scan.py tirent eux-mêmes hors d'un conteneur (étiquette mobile).
const IMAGE_WEEKLY_DES_SCRIPTS = "ghcr.io/zaproxy/zaproxy:weekly";
// WEBSEC_DAST_DOCKER : le banc désigne un Docker simulé (script .mjs, joué par node) ; sinon `docker`.
const DOCKER = process.env.WEBSEC_DAST_DOCKER || "docker";
const lancerDocker = (a, opts) => (/\.mjs$/i.test(DOCKER) ? spawnSync(process.execPath, [DOCKER, ...a], opts) : spawnSync(DOCKER, a, opts));

// Rend null (image absente) ou l'identifiant local de l'image, lu sans la tirer.
function imageDockerPresente(image) {
  if (!resoluDansLePath(DOCKER)) return null;
  const r = lancerDocker(["image", "inspect", image, "--format", "{{.Id}}"], { encoding: "utf8", timeout: 30000 });
  return r.error === undefined && r.status === 0 ? (String(r.stdout || "").trim() || "(identifiant non lu)") : null;
}

// La FORME d'un ZAP se lit du nom de sa commande : baseline (passif), complet (araignée + attaque
// active), rapide (zap.sh / zap.bat, dont l'option `-quickurl` « attaque » l'URL, selon l'aide de
// ZAP 2.17.0). Un script au nom inconnu (.py, .mjs) est lu comme baseline en passif, et jamais admis
// en actif : l'oracle ne peut pas savoir qu'il attaque. TF-2853 : api (zap-api-scan), qui part d'une
// définition OpenAPI, en passif avec -S comme en actif.
function formeDe(cmd) {
  const base = path.basename(cmd).toLowerCase().replace(/\.(py|mjs|sh|bat|cmd|exe)$/, "");
  if (base === "zap-baseline") return "baseline";
  if (base === "zap-full-scan") return "complet";
  if (base === "zap-api-scan") return "api";
  if (base === "zap") return "rapide";
  return /\.(py|mjs)$/i.test(cmd) ? "script-inconnu" : "rapide";
}

function resoudreZap() {
  const force = process.env.WEBSEC_DAST_ZAP;
  const candidats = force ? [force] : (definition ? ["zap-api-scan.py"] : (mode === "actif" ? ["zap-full-scan.py", "zap.sh", "zap.bat"] : ["zap-baseline.py"]));
  for (const cmd of candidats) {
    try {
      if (resoluDansLePath(cmd)) return { mode: "poste", cmd, forme: formeDe(cmd) };
    } catch { /* candidat suivant */ }
  }
  // `WEBSEC_DAST_ZAP` déclaré et injouable = un CHOIX de l'opérateur, pas une absence : on ne
  // se rabat PAS sur Docker. Sans cette garde, un poste où l'image traîne aurait lancé un scan
  // réel là où l'appelant avait explicitement désigné une autre commande — et le self-test,
  // qui force cette variable sur un chemin injouable pour prouver le SKIP, aurait scanné pour
  // de vrai. Garde posée le 14/08 en ajoutant la voie Docker.
  if (force) return null;
  const image = process.env.WEBSEC_DAST_IMAGE || IMAGE_DEFAUT;
  const idLocal = imageDockerPresente(image);
  if (idLocal) return { mode: "docker", cmd: DOCKER, image, idLocal, forme: definition ? "api" : (mode === "actif" ? "complet" : "baseline") };
  return null;
}

const zap = resoudreZap();
if (!zap) {
  const ou = process.env.WEBSEC_DAST_ZAP
    ? `commande déclarée dans WEBSEC_DAST_ZAP (« ${process.env.WEBSEC_DAST_ZAP} ») injouable`
    : (definition
      ? `zap-api-scan.py absent du PATH, et l'image Docker ZAP « ${process.env.WEBSEC_DAST_IMAGE || IMAGE_DEFAUT} » absente du poste`
      : (mode === "actif"
        ? `aucun de zap-full-scan.py / zap.sh / zap.bat dans le PATH, et l'image Docker ZAP « ${process.env.WEBSEC_DAST_IMAGE || IMAGE_DEFAUT} » absente du poste`
        : `zap-baseline.py absent du PATH, et l'image Docker ZAP « ${process.env.WEBSEC_DAST_IMAGE || IMAGE_DEFAUT} » absente du poste`));
  add("info", "DAST-SKIP", `ZAP absent de ce poste — ${ou}. Aucun scan lancé, aucun verdict rendu : SKIP motivé, jamais un PASS par défaut. Cet oracle n'installe jamais ZAP ; installer ZAP (ou « docker pull ${IMAGE_DEFAUT} ») puis relancer, ou juger un rapport déjà produit avec --rapport <fichier.json>.`, origineCible);
  if (mode === "passif" && !definition && !process.env.WEBSEC_DAST_ZAP && (resoluDansLePath("zap.sh") || resoluDansLePath("zap.bat"))) {
    add("info", "DAST-PASSIF-IMPOSSIBLE", "zap.sh / zap.bat est présent, mais son balayage rapide (-quickurl) ATTAQUE la cible : il n'est pas admis en mode passif. Une passe passive exige zap-baseline.py ou l'image Docker ; l'attaque exige `--mode actif` et `actif_autorise: true`.", origineCible);
  }
  synthese.zap = { provenance: "aucune — ZAP introuvable sur le poste", rapport: null };
  sortir("SKIP", 2);
}

// TF-2853 : une définition OpenAPI ne se lit que par zap-api-scan, et zap-api-scan ne part que d'une définition. Un autre ZAP
// partirait de la racine de la cible, que la définition est là pour remplacer : rien n'est lancé.
if (Boolean(definition) !== (zap.forme === "api")) {
  add("info", "DAST-API-IMPOSSIBLE", definition
    ? `définition OpenAPI fournie, mais « ${zap.cmd} » est un ZAP de forme « ${zap.forme} », qui ne lit pas de définition : il partirait de la racine de la cible. Aucun scan lancé. Désigner zap-api-scan.py (WEBSEC_DAST_ZAP, ou le PATH) ou l'image Docker.`
    : `« ${zap.cmd} » est un ZAP de forme « api » (zap-api-scan.py), qui ne part que d'une définition OpenAPI : aucun scan lancé. Fournir la définition par \`--openapi-fichier <fichier>\`, ou désigner ${mode === "actif" ? "zap-full-scan.py" : "zap-baseline.py"}.`, origineCible);
  synthese.zap = { provenance: `aucune — forme « ${zap.forme} » incompatible ${definition ? "avec" : "sans"} définition OpenAPI`, rapport: null };
  sortir("SKIP", 2);
}
// Un mode ne se rabat jamais sur l'autre (TF-2444) : la forme du ZAP trouvé doit faire ce que le
// mode annonce, sinon rien n'est lancé. La forme api fait l'un ou l'autre (-S en passif).
if (mode === "actif" && zap.forme !== "complet" && zap.forme !== "rapide" && zap.forme !== "api") {
  add("info", "DAST-ACTIF-IMPOSSIBLE", `mode actif demandé, mais « ${zap.cmd} » est un ZAP de forme « ${zap.forme} », qui ne lance pas d'attaque active : il en rendrait une passe passive sous le nom d'un balayage actif. Aucun scan lancé. Désigner zap-full-scan.py (WEBSEC_DAST_ZAP, ou le PATH) ou l'image Docker, ou demander le mode passif.`, origineCible);
  synthese.zap = { provenance: `aucune — forme « ${zap.forme} » incompatible avec le mode actif`, rapport: null };
  sortir("SKIP", 2);
}
if (mode === "passif" && zap.forme !== "baseline" && zap.forme !== "script-inconnu" && zap.forme !== "api") {
  add("info", "DAST-PASSIF-IMPOSSIBLE", `mode passif demandé, mais « ${zap.cmd} » est un ZAP de forme « ${zap.forme} », qui attaque la cible : il n'est pas admis en passif. Aucun scan lancé. Désigner zap-baseline.py (WEBSEC_DAST_ZAP, ou le PATH) ou l'image Docker, ou demander le mode actif avec \`actif_autorise: true\`.`, origineCible);
  synthese.zap = { provenance: `aucune — forme « ${zap.forme} » incompatible avec le mode passif`, rapport: null };
  sortir("SKIP", 2);
}

// ZAP présent, de la bonne forme : balayage du MODE demandé contre la cible AUTORISÉE, rapport JSON en sortie.
const horodatage = Date.now();
const dossierTravail = fs.mkdtempSync(path.join(os.tmpdir(), `zap-${horodatage}-`));
const nomRapport = "zap-rapport.json";
const sortieRapport = path.join(dossierTravail, nomRapport);

// Les options (en-tête, débit, exclusions) passent en `-z "-config k=v …"` aux scripts Python de ZAP
// (découpés par shlex : chaque paire est citée entre apostrophes), en `-config k=v` à zap.sh.
const citer = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
const optionsScript = optionsZapListe.length ? ["-z", optionsZapListe.map((o) => `-config ${citer(o)}`).join(" ")] : [];
const scriptDocker = definition ? "zap-api-scan.py" : (mode === "actif" ? "zap-full-scan.py" : "zap-baseline.py");
// Voie Docker (TF-2477) : `-silent` coupe la mise à jour des modules au lancement (-addonupdate et installation
// des add-ons bêta, que zap-baseline.py, zap-full-scan.py et zap-api-scan.py sautent quand `-silent` figure dans -z).
const optionsDocker = ["-z", ["-silent", ...optionsZapListe.map((o) => `-config ${citer(o)}`)].join(" ")];
// TF-2853 : la définition jugée est écrite dans le dossier de travail ; c'est ce texte, et lui seul, que ZAP importe. zap-api-scan.py
// lit `-t` comme un fichier relatif à /zap/wrk dans le conteneur, `-f openapi` en donne le format, et `-S` (mode sûr) saute
// l'attaque active : en passif, seules partent les requêtes de l'import, GET et HEAD par le garde-fou.
const cheminDefinition = definition ? path.join(dossierTravail, definition.nom) : null;
if (definition) fs.writeFileSync(cheminDefinition, definition.contenu);
const optionsApi = definition ? ["-f", "openapi"] : [];
const modeSur = definition && mode === "passif" ? ["-S"] : [];

// Nom du conteneur : c'est par lui qu'un délai dépassé le retire (TF-2486). Tuer le client docker ne
// suffit pas sous Windows, où le conteneur continuerait d'émettre vers la cible.
const nomConteneur = `websec-zap-${horodatage}-${process.pid}`;
const cheminZap = zap.mode === "docker" ? null : cheminResolu(zap.cmd);
let commande = zap.cmd;
let argv;
let cwd;
if (zap.mode === "docker") {
  // Les scripts écrivent leurs rapports dans /zap/wrk : on y monte un dossier de travail
  // du poste, et le rapport en ressort par le montage. `--rm` : aucun conteneur ne survit.
  argv = [
    "run", "--rm", "--name", nomConteneur, "-v", `${dossierTravail}:/zap/wrk:rw`, zap.image,
    scriptDocker, "-t", definition ? definition.nom : cible, ...optionsApi, "-J", nomRapport, "-I", ...modeSur, ...optionsDocker,
  ];
} else if (zap.forme === "rapide") {
  // zap.sh / zap.bat : `-dir` pointe un dossier de ZAP jetable, qui ne heurte pas le dossier d'une
  // instance de bureau ouverte sur le poste (TF-2485).
  const dossierZap = path.join(dossierTravail, "zap-home");
  fs.mkdirSync(dossierZap);
  argv = ["-cmd", "-dir", dossierZap, ...optionsZapListe.flatMap((o) => ["-config", o]), "-quickurl", cible, "-quickout", sortieRapport];
} else {
  argv = ["-t", cheminDefinition || cible, ...optionsApi, "-J", sortieRapport, "-I", ...modeSur, ...optionsScript];
}
// ZAP natif tourne dans son propre dossier : zap.bat l'exige pour trouver son jar (TF-2485).
if (cheminZap) cwd = path.dirname(cheminZap);
let windowsVerbatimArguments = false;
if (/\.mjs$/i.test(zap.cmd)) {
  // Un script .mjs (ZAP simulé du banc) est joué par node, comme les outils simulés d'oracle-sca.
  argv = [cheminZap || zap.cmd, ...argv]; commande = process.execPath;
} else if (process.platform === "win32" && /\.(bat|cmd)$/i.test(zap.cmd)) {
  // Node refuse de lancer un .bat ou un .cmd sans shell (EINVAL, mesuré sous Node v24.16.0). La ligne
  // passe à cmd.exe, chaque argument entre guillemets : entre guillemets, cmd.exe lit `^ & | < > ( )`
  // comme du texte. Il interprète encore `%` (variables) et ne sait pas échapper `"` : un argument qui
  // en porte un n'est jamais réécrit, il fait refuser le lancement.
  const piege = [cheminZap || zap.cmd, ...argv].filter((a) => /["%\r\n]/.test(a));
  if (piege.length) {
    add("info", "DAST-LANCEMENT", `ZAP (« ${zap.cmd} ») non lancé : ${piege.length} argument(s) portent \`"\`, \`%\` ou un saut de ligne, que cmd.exe interpréterait au lieu de les transmettre à ZAP (par ex. « ${masquer(piege[0]).slice(0, 120)} »). Aucun scan lancé : retirer ce caractère de la cible ou du mandat, ou désigner zap-full-scan.py ou l'image Docker.`, origineCible);
    synthese.zap = { provenance: "aucune — ligne de commande non transmissible par cmd.exe", rapport: null };
    sortir("SKIP", 2);
  }
  const ligne = [cheminZap || zap.cmd, ...argv].map((a) => `"${a}"`).join(" ");
  commande = process.env.ComSpec || "cmd.exe";
  argv = ["/d", "/v:off", "/s", "/c", `"${ligne}"`];
  windowsVerbatimArguments = true;
}
const commandeLisible = zap.mode === "docker" ? `docker run ${zap.image} ${scriptDocker}` : zap.cmd;
synthese.balayage.forme = zap.forme;
synthese.balayage.commande = commandeLisible;
if (zap.mode === "docker") {
  const epinglee = imageEpinglee(zap.image);
  synthese.balayage.image = { reference: zap.image, epinglee, id_local: zap.idLocal };
  synthese.balayage.maj_modules = "coupée : -silent passé à ZAP, les règles sont celles de l'image";
  // TF-2499 : ce que `-silent` retire est dit au verdict, pas seulement au référentiel. zap-baseline.py installait pscanrulesBeta depuis le
  // réseau, zap-full-scan.py y ajoutait ascanrulesBeta ; aucun des deux n'est dans l'image, et leurs règles n'ont jamais été lues. Aucune
  // n'est réactivée par le réseau : ni -addonupdate ni -addoninstall ne sont passés. TF-2853 : zap-api-scan.py n'installait que
  // pscanrulesBeta, dans les deux modes (lu dans son script de l'image le 25/11/2026).
  synthese.balayage.regles_beta = {
    jouees: false,
    modules: mode === "actif" && !definition ? ["pscanrulesBeta", "ascanrulesBeta"] : ["pscanrulesBeta"],
    cause: "-silent coupe la mise à jour des modules au lancement : les add-ons bêta que zap-baseline.py, zap-full-scan.py et zap-api-scan.py installaient depuis le réseau ne sont plus installés",
    liste_lue: false,
    reactivees_par_le_reseau: false,
    cas_par_cas: `referentiels/wstg-cas.md, section « ${SECTION_REGLES_BETA} »`,
  };
  if (!epinglee) {
    add("info", "DAST-IMAGE-MOBILE", `image ZAP « ${zap.image} » désignée par une étiquette mobile (WEBSEC_DAST_IMAGE) : ses règles peuvent changer sans que referentiels/zap-regles.json le sache. Identifiant local de l'image qui a tourné : ${zap.idLocal}. Épingler par empreinte (@sha256:…) ou par version complète (:2.17.0).`, origineCible);
  }
} else {
  synthese.balayage.maj_modules = "non maîtrisée : ZAP natif du poste, dont l'oracle ne coupe pas la mise à jour des modules au lancement";
  synthese.balayage.regles_beta = {
    jouees: "indéterminé",
    cause: "ZAP natif : la mise à jour des modules n'est pas coupée, des add-ons bêta peuvent être installés depuis le réseau au lancement ; l'oracle ne lit ni ce qui l'a été ni leurs règles",
    liste_lue: false,
    cas_par_cas: `referentiels/wstg-cas.md, section « ${SECTION_REGLES_BETA} » (dit ce que la voie Docker ne joue plus)`,
  };
  // TF-2884 : lancés hors d'un conteneur, zap-baseline.py, zap-full-scan.py et zap-api-scan.py exécutent eux-mêmes `docker pull
  // ghcr.io/zaproxy/zaproxy:weekly` (zap_common.start_docker_zap), puis y font tourner le balayage. Lu le 26/11/2026 dans l'image 2.17.0
  // (docker run --network none, sans balayage) : l'étiquette est écrite en dur à chaque appel (zap-baseline.py ligne 543, zap-api-scan.py
  // ligne 382, zap-full-scan.py ligne 319) et aucune option des trois scripts ne désigne une autre image. L'oracle ne peut donc pas leur
  // passer l'image épinglée ; il le dit au verdict. zap.sh et zap.bat (forme « rapide ») ne passent par aucun de ces scripts.
  if (["baseline", "complet", "api"].includes(zap.forme)) {
    synthese.balayage.image_tiree_par_le_script = {
      reference: IMAGE_WEEKLY_DES_SCRIPTS, epinglee: false,
      cause: "le script tire lui-même cette image (docker pull) hors d'un conteneur ; aucune de ses options ne désigne une autre image",
      remede: "lancer par la voie Docker de l'oracle (image épinglée)",
    };
    add("info", "DAST-IMAGE-MOBILE", `ZAP natif « ${zap.cmd} » (forme ${zap.forme}) : lancé hors d'un conteneur, le script tire lui-même l'image « ${IMAGE_WEEKLY_DES_SCRIPTS} » (docker pull), une étiquette mobile que l'oracle n'épingle pas et dont les règles ne sont pas lues par referentiels/zap-regles.json. Le script n'offre aucune option pour désigner une autre image (lu dans l'image 2.17.0 le 26/11/2026) : l'oracle ne peut pas lui passer l'image épinglée. Remède : lancer par la voie Docker de l'oracle, sans WEBSEC_DAST_ZAP ni zap-*.py dans le PATH, l'image « ${IMAGE_DEFAUT} » étant présente sur le poste.`, origineCible);
  }
}
if (cwd) synthese.balayage.dossier_courant = cwd;

// Exécution bornée par le délai, avec arrêt de l'ARBRE de processus (TF-2486) : `spawnSync` ne tue
// que l'enfant direct, et sous Windows l'enfant direct de zap.bat est cmd.exe — java aurait continué
// le balayage après le délai, donc au-delà de ce que le mandat autorise.
function executer() {
  return new Promise((resoudre) => {
    let stdout = "";
    let stderr = "";
    let coupe = false;
    let p;
    try {
      p = spawn(commande, argv, {
        shell: false, cwd, windowsVerbatimArguments, windowsHide: true,
        detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) { resoudre({ error: e, status: null, signal: null, stdout, stderr, coupe }); return; }
    p.stdout.on("data", (d) => { if (stdout.length < 65536) stdout += d; });
    p.stderr.on("data", (d) => { if (stderr.length < 65536) stderr += d; });
    const minuterie = setTimeout(() => {
      coupe = true;
      if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(p.pid), "/T", "/F"], { timeout: 30000, windowsHide: true });
      else { try { process.kill(-p.pid, "SIGKILL"); } catch { try { p.kill("SIGKILL"); } catch { /* déjà fini */ } } }
      if (zap.mode === "docker") lancerDocker(["rm", "-f", nomConteneur], { timeout: 60000, windowsHide: true });
    }, delaiMs);
    p.on("error", (e) => { clearTimeout(minuterie); resoudre({ error: e, status: null, signal: null, stdout, stderr, coupe }); });
    p.on("close", (status, signal) => { clearTimeout(minuterie); resoudre({ error: undefined, status, signal, stdout, stderr, coupe }); });
  });
}
const r = await executer();
synthese.balayage.execution = { code_sortie: r.status, signal: r.signal || null, coupe_par_le_delai: r.coupe, erreur: r.error ? (r.error.code || String(r.error.message)) : null };
if (r.coupe) {
  add("info", "DAST-DELAI", `ZAP (« ${commandeLisible} ») arrêté au bout de ${arrondi(delaiMinutes)} min (${delaiSource}), avant d'avoir livré son rapport ; l'arbre de processus a été arrêté${zap.mode === "docker" ? " et le conteneur retiré" : ""}. SKIP motivé : allonger \`duree_max_minutes\` ou \`plafond_requetes\` dans le mandat, dans les limites de sa fenêtre, ou réduire le périmètre par \`exclusions\`.`, origineCible);
  synthese.zap = { provenance: `exécution ${commandeLisible} coupée par le délai`, rapport: null };
  sortir("SKIP", 2);
}
if (!fs.existsSync(sortieRapport)) {
  const extrait = masquer(String(r.stderr || r.stdout || "")).slice(0, 300).trim();
  const cause = r.error
    ? `le système a refusé de lancer la commande (${r.error.code || r.error.message})`
    : `ZAP a fini (code ${r.status}${r.signal ? `, signal ${r.signal}` : ""}) sans rapport exploitable : ${extrait || "sortie vide"}`;
  add("info", "DAST-SKIP", `ZAP (« ${commandeLisible} ») : ${cause}. SKIP motivé — jamais un PASS faute de preuve.`, origineCible);
  synthese.zap = { provenance: `exécution ${commandeLisible} en échec`, rapport: null };
  sortir("SKIP", 2);
}
jugerRapport(sortieRapport, `exécution ${commandeLisible} (mode ${mode}${definition ? ", depuis la définition OpenAPI" : ""}) sur cible autorisée`, { imageEpinglee: zap.mode === "docker" && zap.image === IMAGE_DEFAUT, openapi: Boolean(definition) });
