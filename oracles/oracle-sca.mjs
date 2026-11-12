#!/usr/bin/env node
// oracle-sca — Domaine « Dépendances vulnérables : outillage disponible enveloppé en
// verdict machine normalisé » (zéro dépendance propre — délègue à l'outillage DÉJÀ présent
// sur le poste, ne l'installe jamais). Deux écosystèmes couverts :
//   npm  : présence de package.json + package-lock.json dans la cible → `npm audit
//          --package-lock-only --json`, compteurs par sévérité lus dans metadata.vulnerabilities ;
//   pip  : présence de requirements.txt, de uv.lock ou de poetry.lock dans la cible →
//          `pip-audit -r <requirements> --format json` (pas de sévérité fournie par l'outil :
//          chaque paquet vulnérable compte pour 1, seuil sur le nombre de paquets). Un verrou
//          (uv.lock, poetry.lock) est lu ici, ses paquets de registre sont écrits épinglés dans
//          un requirements temporaire HORS de la cible, et audités avec --no-deps --disable-pip
//          (rien n'est résolu ni installé). Si pip-audit est absent du poste, il est lancé par
//          `uvx --from pip-audit==<version du remède> pip-audit` quand uvx est présent (0.2.0, TF-2272 ;
//          épinglé en 0.2.2, TF-2455) ; ni l'un ni l'autre → manque nommé. Les deux voies ont le même délai.
// osv-scanner (multi-écosystème) n'est PAS enveloppé en v0 faute de poste équipé pour le
// prouver par fixture — restes explicites en README, jamais promis au catalogue.
//
// Règle dure (mandat TF-0123) : AUCUN outil disponible ni manifeste exploitable → verdict
// SKIP MOTIVÉ, jamais un PASS silencieux. Un manifeste présent mais l'outil correspondant
// absent (ou son exécution en échec, ex. registre injoignable) est également signalé —
// visible dans les findings même quand l'autre écosystème, lui, a pu être audité.
//
// Un SKIP se rend comme un MANQUE NOMMÉ (TF-2272) : le champ `manques` liste, pour chaque
// écosystème ou manifeste non audité, ce qui manque (outil, réseau, format) et le remède ; sur
// un SKIP, le champ `motif` le dit en une phrase. Une porte de production qui lit un SKIP lit
// donc « l'audit des dépendances n'a pas eu lieu, voici pourquoi », jamais un silence.
//
// Surcharge de l'outillage, pour la recette (rien n'est installé) : WEBSEC_SCA_PIP_AUDIT et
// WEBSEC_SCA_UVX désignent la commande à utiliser à la place de `pip-audit` / `uvx` (un chemin
// qui finit par .mjs est joué par node ; un chemin injouable simule l'absence de l'outil).
//
// Contrat : JSON {oracle, version, artefact, verdict, findings, non_juge, synthese,
// seuils_appliques, manques[, motif]} · exit 0 (PASS) / 1 (FAIL) / 2 (SKIP — rien n'a pu être audité).
// Usage : node oracle-sca.mjs <dossier-cible> [--seuils <fichier.json>] [--json-only]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const VERSION = "0.2.2";
const ORACLE = "oracle-sca";
// Version de pip-audit nommée dans le remède d'un SKIP « outil absent » (TF-2398) : celle mesurée
// sur le poste le 12/11/2026 (`pip-audit --version` → 2.10.1). Le remède donne une commande, pas un vœu.
const PIP_AUDIT_EPINGLE = "pip-audit==2.10.1";
const NON_JUGE = [
  "l'exhaustivité de la base d'avisos consultée (npm advisory database / OSV/PyPA) — dépend de l'outil et de sa fraîcheur au moment du run",
  "osv-scanner (multi-écosystème) — non enveloppé en v0, faute de poste équipé pour le prouver par fixture (cf. README §Limites)",
  "les vulnérabilités dans du code propriétaire non publié en avis (0-day interne)",
  "l'exploitabilité réelle d'une CVE dans le contexte applicatif précis (une CVE listée n'est pas toujours atteignable)",
  "la correction des dépendances signalées — un constat, jamais un geste automatique",
  "les paquets d'un verrou uv.lock ou poetry.lock installés depuis un dépôt git, un chemin, une URL ou un index privé — comptés et nommés au manque, non audités",
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

// Un outil est une commande, des arguments de tête et un mode de lancement. Par défaut, le nom nu
// (shell sous Windows pour npm.cmd) ; une variable d'environnement le surcharge pour la recette.
function resoudre(nom, variable, delai) {
  const force = variable ? process.env[variable] : undefined;
  if (force) {
    if (/\.(mjs|cjs|js)$/i.test(force)) return { nom, cmd: process.execPath, pre: [force], shell: false, delai };
    return { nom, cmd: force, pre: [], shell: false, delai };
  }
  return { nom, cmd: nom, pre: [], shell: nom === "npm" && process.platform === "win32", delai };
}

function outilDisponible(outil, versionArg = "--version") {
  try {
    const r = spawnSync(outil.cmd, [...outil.pre, versionArg], { encoding: "utf8", timeout: 10000, shell: outil.shell });
    return r.error === undefined && r.status === 0;
  } catch { return false; }
}

const synthese = {};
const MANQUES = []; // ce qui n'a pas été audité, nommé (TF-2272)

// Un manque est un finding `SCA-SKIP` (info : il ne fait pas échouer l'oracle) ET une entrée
// de `manques`, que la porte de production lit sans avoir à parser une phrase.
function manque(ecosysteme, manifeste, cause, remede) {
  MANQUES.push({ ecosysteme, manifeste, cause, remede });
  add("info", "SCA-SKIP", `MANQUE (${ecosysteme}) — ${cause} ; remède : ${remede}`, manifeste);
}

function sortir(verdict, code) {
  const sortie = {
    oracle: ORACLE, version: VERSION, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucune dépendance vulnérable au-delà des seuils appliqués", where: cible }],
    synthese, seuils_appliques: { source: seuilsSource, ...seuils },
    manques: MANQUES,
    non_juge: NON_JUGE,
  };
  if (verdict === "SKIP") {
    sortie.motif = "AUDIT NON JOUÉ, aucune dépendance jugée (ce n'est pas un PASS) — manque : " +
      (MANQUES.length ? MANQUES.map((m) => `${m.ecosysteme} : ${m.cause}`).join(" | ") : "cause non nommée");
  }
  process.stdout.write(JSON.stringify(sortie, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

if (!cible || !fs.existsSync(cible)) {
  add("info", "—", "cible introuvable", String(cible));
  MANQUES.push({ ecosysteme: "—", manifeste: String(cible), cause: "cible introuvable", remede: "passer le dossier racine du produit" });
  sortir("SKIP", 2);
}
if (F.some((f) => f.sev === "bloquant")) sortir("FAIL", 1); // seuils fournis mais illisibles : refus net, pas de défaut implicite

const npmLock = path.join(cible, "package-lock.json");
const npmManifest = path.join(cible, "package.json");
const pipReq = path.join(cible, "requirements.txt");
const uvLock = path.join(cible, "uv.lock");
const poetryLock = path.join(cible, "poetry.lock");

let ecosystemesAudites = 0;

// ── npm ────────────────────────────────────────────────────────────────────
if (fs.existsSync(npmLock) && fs.existsSync(npmManifest)) {
  if (!outilDisponible(resoudre("npm"))) {
    manque("npm", npmLock, "package-lock.json présent mais npm absent du poste — écosystème npm non audité", "installer Node.js/npm (geste humain, l'oracle n'installe rien)");
  } else {
    const r = spawnSync("npm", ["audit", "--package-lock-only", "--json"], { cwd: cible, encoding: "utf8", timeout: 60000, shell: process.platform === "win32" });
    let rapport = null;
    try { rapport = JSON.parse(r.stdout); } catch { /* rapport non-JSON (registre injoignable, erreur réseau) */ }
    if (!rapport || !rapport.metadata || !rapport.metadata.vulnerabilities) {
      const extrait = String(r.stderr || r.stdout || "").slice(0, 200).trim();
      manque("npm", npmLock, `npm présent mais audit indisponible (registre injoignable ou sortie inattendue) : ${extrait || "sortie vide"}`, "rejouer avec un accès réseau au registre npm");
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
  manque("npm", cible, "manifeste npm incomplet (package.json et package-lock.json requis ensemble) — écosystème npm non audité", "fournir package.json et package-lock.json ensemble");
}

// ── pip ────────────────────────────────────────────────────────────────────
// Voie d'exécution de pip-audit : la commande du poste, sinon `uvx pip-audit` (TF-2272), sinon rien.
// Un seul délai pour les deux voies (TF-2455) : `pip-audit` direct met 85 à 90 s et plus sur `pip-vulnerable`
// (django 1.4, des centaines d'avis), `uvx` 159 s (mesurées le 12/11/2026) ; l'ancien délai de 90 s de la voie
// directe tombait sur la frontière et rendait un audit réussi `indisponible`.
const DELAI_PIP_AUDIT = 240000;
const pipAudit = resoudre("pip-audit", "WEBSEC_SCA_PIP_AUDIT", DELAI_PIP_AUDIT);
const uvx = resoudre("uvx", "WEBSEC_SCA_UVX", DELAI_PIP_AUDIT);
let voieMemo;
function voiePip() {
  if (voieMemo !== undefined) return voieMemo;
  if (outilDisponible(pipAudit)) voieMemo = { libelle: "pip-audit", ...pipAudit };
  // L'appel uvx est épinglé à la version du remède (TF-2455) : sans `--from`, uvx prend la dernière version publiée
  // et le verdict changerait avec elle. `--from` s'écrit pareil sur toute version d'uv.
  else if (outilDisponible(uvx)) voieMemo = { libelle: "uvx pip-audit", ...uvx, pre: [...uvx.pre, "--from", PIP_AUDIT_EPINGLE, "pip-audit"] };
  else voieMemo = null;
  return voieMemo;
}

// Lecture d'un verrou uv.lock ou poetry.lock : blocs [[package]], clés name et version en tête de
// bloc. Un paquet qui ne vient pas d'un registre (git, chemin, URL ; le projet lui-même côté uv ;
// toute [package.source] côté poetry) n'est pas interrogeable : il est compté dans `ignores`.
const NOM_OK = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const VERSION_OK = /^[A-Za-z0-9][A-Za-z0-9._+!-]*$/;
function lireVerrou(fichier, format) {
  const paquets = [];
  const ignores = [];
  let cur = null;
  let zone = "tete";
  const clore = () => {
    if (!cur) return;
    if (cur.projet) { cur = null; return; } // le projet lui-même (uv : source virtual ou editable) n'est pas une dépendance
    if (cur.registre &&cur.name && cur.version && NOM_OK.test(cur.name) && VERSION_OK.test(cur.version)) paquets.push({ name: cur.name, version: cur.version });
    else ignores.push(cur.name || "(sans nom)");
    cur = null;
  };
  for (const l of fs.readFileSync(fichier, "utf8").split(/\r?\n/)) {
    if (l.trim() === "[[package]]") { clore(); cur = { name: null, version: null, registre: format === "poetry" }; zone = "tete"; continue; }
    if (/^\[/.test(l)) {
      if (cur && /^\[\[?package\./.test(l)) { zone = format === "poetry" && /^\[package\.source\]/.test(l) ? "source" : "autre"; if (zone === "source") cur.registre = false; }
      else clore();
      continue;
    }
    if (!cur || zone !== "tete") continue;
    let m;
    if ((m = /^name\s*=\s*"([^"]*)"/.exec(l))) cur.name = m[1];
    else if ((m = /^version\s*=\s*"([^"]*)"/.exec(l))) cur.version = m[1];
    else if (format === "uv" && /^source\s*=\s*\{\s*registry\s*=/.test(l)) cur.registre = true;
    else if (format === "uv" && /^source\s*=\s*\{\s*(virtual|editable)\s*=/.test(l)) cur.projet = true;
  }
  clore();
  return { paquets, ignores };
}

// Un appel à pip-audit sur un requirements. `epingle` : paquets déjà épinglés (verrou) → sans
// résolution ni installation (--no-deps --disable-pip), donc rapide et sans environnement.
function auditerPip(voie, req, epingle) {
  const argv = [...voie.pre, "-r", req, "--format", "json", ...(epingle ? ["--no-deps", "--disable-pip"] : [])];
  const r = spawnSync(voie.cmd, argv, { encoding: "utf8", timeout: voie.delai, shell: voie.shell });
  let rapport = null;
  try { rapport = JSON.parse(r.stdout); } catch { /* rapport non-JSON (registre injoignable, erreur réseau) */ }
  const deps = rapport && Array.isArray(rapport.dependencies) ? rapport.dependencies : null;
  let extrait = "";
  if (!deps) {
    extrait = r.error && r.error.code === "ETIMEDOUT" ? `délai de ${voie.delai / 1000} s dépassé`
      : (r.error ? r.error.message : String(r.stderr || r.stdout || "").slice(-200).trim()) || "sortie vide";
  }
  return { deps, extrait };
}

const sourcesPip = [
  { fichier: pipReq, format: "requirements" },
  { fichier: uvLock, format: "uv" },
  { fichier: poetryLock, format: "poetry" },
].filter((s) => fs.existsSync(s.fichier));

const pipVus = new Set();
const pipVulnerables = new Map();
const pipParSource = {};
let pipVoie = null;
let pipDelai = null;
for (const s of sourcesPip) {
  const base = path.basename(s.fichier);
  const voie = voiePip();
  if (!voie) {
    manque("pip", s.fichier, `${base} présent mais ni pip-audit ni uvx sur le poste — écosystème pip non audité`, `installer l'outil épinglé, par « pip install ${PIP_AUDIT_EPINGLE} » ou « uv tool install ${PIP_AUDIT_EPINGLE} » ; ou installer uv, qui fournit uvx (« uvx pip-audit » est alors lancé sans installation globale) — geste humain, l'oracle n'installe rien`);
    continue;
  }
  let lots; // fichiers requirements à auditer : [chemin]
  let nettoyage = null;
  let epingle = false;
  if (s.format === "requirements") {
    lots = [s.fichier];
  } else {
    const v = lireVerrou(s.fichier, s.format);
    if (v.ignores.length) manque("pip", s.fichier, `${v.ignores.length} paquet(s) de ${base} hors registre non audité(s) : ${v.ignores.slice(0, 10).join(", ")}${v.ignores.length > 10 ? ", …" : ""}`, "auditer ces sources à part (git, chemin, URL ou index privé)");
    if (!v.paquets.length) { manque("pip", s.fichier, `${base} lu mais aucun paquet de registre reconnu — format inattendu ou verrou vide`, "vérifier le verrou ou fournir un requirements.txt exporté"); continue; }
    // pip-audit refuse deux versions du même nom dans un fichier : une couche par rang de version.
    const parNom = new Map();
    for (const p of v.paquets) { if (!parNom.has(p.name)) parNom.set(p.name, []); const vs = parNom.get(p.name); if (!vs.includes(p.version)) vs.push(p.version); }
    const rangs = Math.max(...[...parNom.values()].map((vs) => vs.length));
    nettoyage = fs.mkdtempSync(path.join(os.tmpdir(), "websec-sca-"));
    lots = [];
    for (let i = 0; i < rangs; i++) {
      const lignes = [...parNom].filter(([, vs]) => vs.length > i).map(([n, vs]) => `${n}==${vs[i]}`);
      const f = path.join(nettoyage, `requirements-${i}.txt`);
      fs.writeFileSync(f, lignes.join("\n") + "\n");
      lots.push(f);
    }
    epingle = true;
  }
  let echec = null;
  const deps = [];
  try {
    for (const f of lots) {
      const { deps: d, extrait } = auditerPip(voie, f, epingle);
      if (!d) { echec = extrait; break; }
      deps.push(...d);
    }
  } finally { if (nettoyage) fs.rmSync(nettoyage, { recursive: true, force: true }); }
  if (echec !== null) {
    manque("pip", s.fichier, `${voie.libelle} présent mais audit de ${base} indisponible (base d'avisos injoignable ou sortie inattendue) : ${echec}`, "rejouer avec un accès réseau à la base d'avisos PyPA/OSV");
    continue;
  }
  ecosystemesAudites++;
  pipVoie = voie.libelle;
  pipDelai = voie.delai;
  const vulnerables = deps.filter((d) => Array.isArray(d.vulns) && d.vulns.length);
  for (const d of deps) pipVus.add(`${d.name}@${d.version}`);
  for (const d of vulnerables) pipVulnerables.set(`${d.name}@${d.version}`, { d, fichier: s.fichier });
  pipParSource[base] = { paquets_vulnerables: vulnerables.length, total_paquets: deps.length };
}
if (pipVoie) {
  synthese.pip = { paquets_vulnerables: pipVulnerables.size, total_paquets: pipVus.size, outil: pipVoie, delai_s: pipDelai / 1000, par_source: pipParSource };
  const seuil = seuils.pip.vulnerabilites;
  if (typeof seuil === "number" && pipVulnerables.size > seuil) {
    for (const { d, fichier } of pipVulnerables.values()) {
      add("bloquant", "SCA-PIP", `${pipVoie} : « ${d.name} ${d.version} » vulnérable (${d.vulns.map((v) => v.id).join(", ")})`, fichier);
    }
  }
}

if (!fs.existsSync(npmLock) && !sourcesPip.length) {
  manque("—", cible, "aucun manifeste reconnu dans la cible (package-lock.json, requirements.txt, uv.lock ou poetry.lock attendu)", "passer le dossier racine du produit, ou ajouter un manifeste verrouillé");
}

if (ecosystemesAudites === 0) {
  // Rien n'a pu être réellement audité : fail-visible, jamais un PASS silencieux.
  sortir("SKIP", 2);
}

const durs = F.filter((f) => f.sev === "bloquant" || f.sev === "majeur");
sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0);
