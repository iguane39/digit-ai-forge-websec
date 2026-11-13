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
//     passif (défaut) → zap-baseline.py (araignée + règles passives, aucune attaque) ;
//     actif           → zap-full-scan.py (araignée + attaque active des URL trouvées), ou
//                       zap.sh / zap.bat (balayage rapide, qui attaque aussi) ; jamais baseline.
//   Un mode ne se rabat JAMAIS sur l'autre : un ZAP qui ne sait que baseline ne rend pas un
//   « actif » passif, un ZAP qui ne sait que le balayage rapide ne rend pas un « passif » qui
//   attaque — SKIP motivé dans les deux cas (TF-2444 : le mode actif lançait la passe passive).
// Options de balayage portées par le FICHIER d'autorisation (mêmes limites dans les deux modes) :
//   `en_tete_acces` {nom, valeur | valeur_env} : en-tête ajouté à toute requête vers l'origine
//                     autorisée (la valeur ne sort jamais dans le verdict) ;
//   `debit_max_requetes_par_seconde` : un fil, un délai de ceil(1000/n) ms entre deux requêtes ;
//   `exclusions` : chemins (« /deconnexion ») dont aucune requête ne part, préfixe compris ;
//   `duree_max_minutes` : durée au-delà de laquelle ZAP est arrêté (TF-2486) ;
//   `plafond_requetes` : avec un débit, le nombre de requêtes dont la durée se déduit (défaut 1000).
// Une option présente et mal formée est un refus (FAIL), jamais un balayage sans la limite.
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
//                              [--seuils <f.json>] [--mode passif|actif] [--json-only]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const VERSION = "0.3.0";
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
  "l'exécution réelle sur une application riche et authentifiée : la preuve réelle (scripts/preuve-dast-actif.mjs) vise une cible de fixture locale de quelques routes, par l'image Docker de ZAP ; les formes natives (zap-baseline.py, zap-full-scan.py, zap.sh, zap.bat) ne sont prouvées que par un ZAP simulé qui enregistre sa ligne de commande — zap.bat et zap.sh par un vrai script qui l'enveloppe, jamais par le vrai ZAP natif (cf. README §Limites)",
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

synthese.balayage = {
  scan: mode,
  en_tete_acces: enTeteAcces ? { nom: enTeteAcces.nom, valeur: "(masquée)", source: enTeteAcces.source } : null,
  debit, exclusions,
  delai_max_minutes: arrondi(delaiMinutes), delai_source: delaiSource,
};

// Options passées à ZAP en paires clé=valeur (`-config clé=valeur`), les mêmes pour les trois formes.
const echapperRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function optionsZap() {
  const o = [];
  if (enTeteAcces) {
    const r = "replacer.full_list(0).";
    o.push(`${r}description=websec acces ${enTeteAcces.nom}`, `${r}enabled=true`, `${r}matchtype=REQ_HEADER`,
      `${r}matchstr=${enTeteAcces.nom}`, `${r}regex=false`, `${r}replacement=${enTeteAcces.valeur}`,
      `${r}url=^${echapperRegex(origineCible)}(/.*)?$`);
  }
  if (debit) {
    o.push("scanner.threadPerHost=1", `scanner.delayInMs=${debit.delai_ms}`, "spider.thread=1", `spider.requestwait=${debit.delai_ms}`);
  }
  exclusions.forEach((chemin, i) => {
    const g = `globalexcludeurl.url_list.url(${i}).`;
    o.push(`${g}description=websec exclusion ${chemin}`, `${g}enabled=true`, `${g}regex=^${echapperRegex(origineCible)}${echapperRegex(chemin)}.*`);
  });
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
// (`docker pull ghcr.io/zaproxy/zaproxy:stable`), sans quoi un oracle « installerait » son
// propre outillage à l'insu de l'appelant.
const IMAGE_DEFAUT = "ghcr.io/zaproxy/zaproxy:stable";

function imageDockerPresente(image) {
  if (!resoluDansLePath("docker")) return false;
  const r = spawnSync("docker", ["image", "inspect", image], { encoding: "utf8", timeout: 30000 });
  return r.error === undefined && r.status === 0;
}

// La FORME d'un ZAP se lit du nom de sa commande : baseline (passif), complet (araignée + attaque
// active), rapide (zap.sh / zap.bat, dont l'option `-quickurl` « attaque » l'URL, selon l'aide de
// ZAP 2.17.0). Un script au nom inconnu (.py, .mjs) est lu comme baseline en passif, et jamais admis
// en actif : l'oracle ne peut pas savoir qu'il attaque.
function formeDe(cmd) {
  const base = path.basename(cmd).toLowerCase().replace(/\.(py|mjs|sh|bat|cmd|exe)$/, "");
  if (base === "zap-baseline") return "baseline";
  if (base === "zap-full-scan") return "complet";
  if (base === "zap") return "rapide";
  return /\.(py|mjs)$/i.test(cmd) ? "script-inconnu" : "rapide";
}

function resoudreZap() {
  const force = process.env.WEBSEC_DAST_ZAP;
  const candidats = force ? [force] : (mode === "actif" ? ["zap-full-scan.py", "zap.sh", "zap.bat"] : ["zap-baseline.py"]);
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
  if (imageDockerPresente(image)) return { mode: "docker", cmd: "docker", image, forme: mode === "actif" ? "complet" : "baseline" };
  return null;
}

const zap = resoudreZap();
if (!zap) {
  const ou = process.env.WEBSEC_DAST_ZAP
    ? `commande déclarée dans WEBSEC_DAST_ZAP (« ${process.env.WEBSEC_DAST_ZAP} ») injouable`
    : (mode === "actif"
      ? "aucun de zap-full-scan.py / zap.sh / zap.bat dans le PATH, et aucune image Docker ZAP présente"
      : "zap-baseline.py absent du PATH, et aucune image Docker ZAP présente");
  add("info", "DAST-SKIP", `ZAP absent de ce poste — ${ou}. Aucun scan lancé, aucun verdict rendu : SKIP motivé, jamais un PASS par défaut. Cet oracle n'installe jamais ZAP ; installer ZAP (ou « docker pull ${IMAGE_DEFAUT} ») puis relancer, ou juger un rapport déjà produit avec --rapport <fichier.json>.`, origineCible);
  if (mode === "passif" && !process.env.WEBSEC_DAST_ZAP && (resoluDansLePath("zap.sh") || resoluDansLePath("zap.bat"))) {
    add("info", "DAST-PASSIF-IMPOSSIBLE", "zap.sh / zap.bat est présent, mais son balayage rapide (-quickurl) ATTAQUE la cible : il n'est pas admis en mode passif. Une passe passive exige zap-baseline.py ou l'image Docker ; l'attaque exige `--mode actif` et `actif_autorise: true`.", origineCible);
  }
  synthese.zap = { provenance: "aucune — ZAP introuvable sur le poste", rapport: null };
  sortir("SKIP", 2);
}

// Un mode ne se rabat jamais sur l'autre (TF-2444) : la forme du ZAP trouvé doit faire ce que le
// mode annonce, sinon rien n'est lancé.
if (mode === "actif" && zap.forme !== "complet" && zap.forme !== "rapide") {
  add("info", "DAST-ACTIF-IMPOSSIBLE", `mode actif demandé, mais « ${zap.cmd} » est un ZAP de forme « ${zap.forme} », qui ne lance pas d'attaque active : il en rendrait une passe passive sous le nom d'un balayage actif. Aucun scan lancé. Désigner zap-full-scan.py (WEBSEC_DAST_ZAP, ou le PATH) ou l'image Docker, ou demander le mode passif.`, origineCible);
  synthese.zap = { provenance: `aucune — forme « ${zap.forme} » incompatible avec le mode actif`, rapport: null };
  sortir("SKIP", 2);
}
if (mode === "passif" && zap.forme !== "baseline" && zap.forme !== "script-inconnu") {
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
const scriptDocker = mode === "actif" ? "zap-full-scan.py" : "zap-baseline.py";

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
    scriptDocker, "-t", cible, "-J", nomRapport, "-I", ...optionsScript,
  ];
} else if (zap.forme === "rapide") {
  // zap.sh / zap.bat : `-dir` pointe un dossier de ZAP jetable, qui ne heurte pas le dossier d'une
  // instance de bureau ouverte sur le poste (TF-2485).
  const dossierZap = path.join(dossierTravail, "zap-home");
  fs.mkdirSync(dossierZap);
  argv = ["-cmd", "-dir", dossierZap, ...optionsZapListe.flatMap((o) => ["-config", o]), "-quickurl", cible, "-quickout", sortieRapport];
} else {
  argv = ["-t", cible, "-J", sortieRapport, "-I", ...optionsScript];
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
      if (zap.mode === "docker") spawnSync("docker", ["rm", "-f", nomConteneur], { timeout: 60000, windowsHide: true });
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
jugerRapport(sortieRapport, `exécution ${commandeLisible} (mode ${mode}) sur cible autorisée`);
