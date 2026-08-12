#!/usr/bin/env node
// oracle-sca — Domaine « Dépendances vulnérables : outillage disponible enveloppé en
// verdict machine normalisé » (zéro dépendance propre — délègue à l'outillage DÉJÀ présent
// sur le poste, ne l'installe jamais). Deux écosystèmes couverts en v0 :
//   npm  : présence de package.json + package-lock.json dans la cible → `npm audit
//          --package-lock-only --json`, compteurs par sévérité lus dans metadata.vulnerabilities ;
//   pip  : présence de requirements.txt dans la cible → `pip-audit -r requirements.txt
//          --format json` (pas de sévérité fournie par l'outil : chaque paquet vulnérable
//          compte pour 1, seuil sur le nombre de paquets).
// osv-scanner (multi-écosystème) n'est PAS enveloppé en v0 faute de poste équipé pour le
// prouver par fixture — restes explicites en README, jamais promis au catalogue.
//
// Règle dure (mandat TF-0123) : AUCUN outil disponible ni manifeste exploitable → verdict
// SKIP MOTIVÉ, jamais un PASS silencieux. Un manifeste présent mais l'outil correspondant
// absent (ou son exécution en échec, ex. registre injoignable) est également signalé —
// visible dans les findings même quand l'autre écosystème, lui, a pu être audité.
//
// Contrat : JSON {oracle, version, artefact, verdict, findings, non_juge, synthese,
// seuils_appliques} · exit 0 (PASS) / 1 (FAIL) / 2 (SKIP — rien n'a pu être audité).
// Usage : node oracle-sca.mjs <dossier-cible> [--seuils <fichier.json>] [--json-only]
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const VERSION = "0.1.0";
const ORACLE = "oracle-sca";
const NON_JUGE = [
  "l'exhaustivité de la base d'avisos consultée (npm advisory database / OSV/PyPA) — dépend de l'outil et de sa fraîcheur au moment du run",
  "osv-scanner (multi-écosystème) — non enveloppé en v0, faute de poste équipé pour le prouver par fixture (cf. README §Limites)",
  "les vulnérabilités dans du code propriétaire non publié en avis (0-day interne)",
  "l'exploitabilité réelle d'une CVE dans le contexte applicatif précis (une CVE listée n'est pas toujours atteignable)",
  "la correction des dépendances signalées — un constat, jamais un geste automatique",
];

const args = process.argv.slice(2);
const cible = args.find((a) => !a.startsWith("--"));
const jsonOnly = args.includes("--json-only");
const iSeuils = args.indexOf("--seuils");
const seuilsPath = iSeuils >= 0 ? args[iSeuils + 1] : null;
const F = [];
const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where });

const SEUILS_DEFAUT = { npm: { critical: 0, high: 0 }, pip: { vulnerabilites: 0 } };
let seuils = SEUILS_DEFAUT;
let seuilsSource = "défaut embarqué (critical=0, high=0 côté npm ; vulnerabilites=0 côté pip)";
if (seuilsPath) {
  if (!fs.existsSync(seuilsPath)) { add("bloquant", "—", `fichier de seuils introuvable : ${seuilsPath}`, seuilsPath); }
  else {
    try {
      const perso = JSON.parse(fs.readFileSync(seuilsPath, "utf8"));
      seuils = { npm: { ...SEUILS_DEFAUT.npm, ...(perso.npm || {}) }, pip: { ...SEUILS_DEFAUT.pip, ...(perso.pip || {}) } };
      seuilsSource = seuilsPath;
    } catch (e) { add("bloquant", "—", `fichier de seuils illisible (JSON invalide) : ${e.message}`, seuilsPath); }
  }
}

function outilDisponible(cmd, versionArg = "--version") {
  try {
    const r = spawnSync(cmd, [versionArg], { encoding: "utf8", timeout: 10000, shell: process.platform === "win32" });
    return r.error === undefined && r.status === 0;
  } catch { return false; }
}

const synthese = {};

function sortir(verdict, code) {
  process.stdout.write(JSON.stringify({
    oracle: ORACLE, version: VERSION, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucune dépendance vulnérable au-delà des seuils appliqués", where: cible }],
    synthese, seuils_appliques: { source: seuilsSource, ...seuils },
    non_juge: NON_JUGE,
  }, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

if (!cible || !fs.existsSync(cible)) { add("info", "—", "cible introuvable", String(cible)); sortir("SKIP", 2); }
if (F.some((f) => f.sev === "bloquant")) sortir("FAIL", 1); // seuils fournis mais illisibles : refus net, pas de défaut implicite

const npmLock = path.join(cible, "package-lock.json");
const npmManifest = path.join(cible, "package.json");
const pipReq = path.join(cible, "requirements.txt");

let ecosystemesAudites = 0;

// ── npm ────────────────────────────────────────────────────────────────────
if (fs.existsSync(npmLock) && fs.existsSync(npmManifest)) {
  if (!outilDisponible("npm")) {
    add("info", "SCA-SKIP", "package-lock.json présent mais npm absent du poste — écosystème npm non audité", npmLock);
  } else {
    const r = spawnSync("npm", ["audit", "--package-lock-only", "--json"], { cwd: cible, encoding: "utf8", timeout: 60000, shell: process.platform === "win32" });
    let rapport = null;
    try { rapport = JSON.parse(r.stdout); } catch { /* rapport non-JSON (registre injoignable, erreur réseau) */ }
    if (!rapport || !rapport.metadata || !rapport.metadata.vulnerabilities) {
      const extrait = String(r.stderr || r.stdout || "").slice(0, 200).trim();
      add("info", "SCA-SKIP", `npm présent mais audit indisponible (registre injoignable ou sortie inattendue) : ${extrait || "sortie vide"}`, npmLock);
    } else {
      ecosystemesAudites++;
      const v = rapport.metadata.vulnerabilities;
      synthese.npm = v;
      for (const sev of ["critical", "high", "moderate", "low"]) {
        const seuil = seuils.npm[sev];
        if (typeof seuil === "number" && (v[sev] || 0) > seuil) {
          const gravite = sev === "critical" || sev === "high" ? "bloquant" : "majeur";
          add(gravite, "SCA-NPM", `npm audit : ${v[sev]} vulnérabilité(s) « ${sev} » > seuil ${seuil} (package-lock.json)`, npmLock);
        }
      }
    }
  }
} else if (fs.existsSync(npmLock) || fs.existsSync(npmManifest)) {
  add("info", "SCA-SKIP", "manifeste npm incomplet (package.json et package-lock.json requis ensemble) — écosystème npm non audité", cible);
}

// ── pip ────────────────────────────────────────────────────────────────────
if (fs.existsSync(pipReq)) {
  if (!outilDisponible("pip-audit")) {
    add("info", "SCA-SKIP", "requirements.txt présent mais pip-audit absent du poste — écosystème pip non audité", pipReq);
  } else {
    const r = spawnSync("pip-audit", ["-r", pipReq, "--format", "json"], { encoding: "utf8", timeout: 90000, shell: process.platform === "win32" });
    let rapport = null;
    try { rapport = JSON.parse(r.stdout); } catch { /* rapport non-JSON (registre injoignable, erreur réseau) */ }
    const deps = rapport && Array.isArray(rapport.dependencies) ? rapport.dependencies : null;
    if (!deps) {
      const extrait = String(r.stderr || r.stdout || "").slice(0, 200).trim();
      add("info", "SCA-SKIP", `pip-audit présent mais audit indisponible (base d'avisos injoignable ou sortie inattendue) : ${extrait || "sortie vide"}`, pipReq);
    } else {
      ecosystemesAudites++;
      const vulnerables = deps.filter((d) => Array.isArray(d.vulns) && d.vulns.length);
      synthese.pip = { paquets_vulnerables: vulnerables.length, total_paquets: deps.length };
      const seuil = seuils.pip.vulnerabilites;
      if (typeof seuil === "number" && vulnerables.length > seuil) {
        for (const d of vulnerables) {
          add("bloquant", "SCA-PIP", `pip-audit : « ${d.name} ${d.version} » vulnérable (${d.vulns.map((v) => v.id).join(", ")})`, pipReq);
        }
      }
    }
  }
}

if (!fs.existsSync(npmLock) && !fs.existsSync(pipReq)) {
  add("info", "—", "aucun manifeste reconnu dans la cible (package-lock.json ou requirements.txt attendu)", cible);
}

if (ecosystemesAudites === 0) {
  // Rien n'a pu être réellement audité : fail-visible, jamais un PASS silencieux.
  sortir("SKIP", 2);
}

const durs = F.filter((f) => f.sev === "bloquant" || f.sev === "majeur");
sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0);
