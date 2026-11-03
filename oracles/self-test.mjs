#!/usr/bin/env node
// self-test.mjs — preuve par le geste (double sens) : rejoue TOUTES les fixtures des cinq
// oracles et vérifie que chaque verte PASSE (ou, pour la SCA dépendante du poste, que le
// silence est un SKIP motivé et jamais un PASS non prouvé) et que chaque rouge ÉCHOUE pour
// la bonne raison (code `regle` vérifié dans les findings, pas juste un verdict générique).
//
// oracle-exposition : intégralement déterministe, zéro dépendance externe, zéro réseau —
// les 15 fixtures locales sont rejouées à l'identique à chaque exécution.
// oracle-workflows : déterministe aussi — des workflows YAML synthétiques lus, jamais exécutés.
// oracle-exposition-statique : déterministe — des fichiers _headers synthétiques, jugés par les
// règles EX d'oracle-exposition.
// oracle-sca : dépend de l'outillage RÉELLEMENT présent sur le poste (npm, pip-audit) et,
// pour npm/pip-audit, d'un accès réseau à leur base d'avisos. Le sens rouge n'est démontré
// que si l'outil est disponible ET répond — sinon SKIP motivé consigné (jamais compté comme
// un échec du self-test, jamais présenté comme une preuve du sens rouge).
//
// Exit 0 si tous les contrôles PROUVÉS passent, 1 sinon. À rejouer après toute modification.
import { execFile, execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = (...p) => path.join(HERE, "..", "fixtures", ...p);
const ORACLE_EXPOSITION = path.join(HERE, "oracle-exposition.mjs");
const ORACLE_SCA = path.join(HERE, "oracle-sca.mjs");
const ORACLE_DAST = path.join(HERE, "oracle-dast.mjs");

let pass = 0, echec = 0, note = 0;
const ok = (b, m) => { console.log(`  [${b ? "PASS" : "FAIL"}] ${m}`); b ? pass++ : echec++; };
const skipNote = (m) => { console.log(`  [SKIP] ${m}`); note++; };

function runJson(script, args) {
  try { return JSON.parse(execFileSync(process.execPath, [script, ...args, "--json-only"], { encoding: "utf8", timeout: 120000 })); }
  catch (e) { try { return JSON.parse(String(e.stdout)); } catch { return { verdict: "ILLISIBLE", findings: [], _stderr: String(e.stderr || e) }; } }
}
function aRegle(res, regle) { return (res.findings || []).some((f) => f.regle === regle); }

console.log("SELF-TEST forge-websec — oracle-exposition (déterministe, 15 fixtures)\n");

const casExposition = [
  ["vert-complet.json", "PASS", null, "toutes les règles satisfaites"],
  ["vert-http-hsts-non-applicable.json", "PASS", null, "HTTP : HSTS non applicable, pas un défaut"],
  ["rouge-csp-absente.json", "FAIL", "EX-1", "CSP absente"],
  ["rouge-csp-triviale.json", "FAIL", "EX-2", "CSP triviale (default-src *)"],
  ["rouge-hsts-absente.json", "FAIL", "EX-3", "HSTS absente sur HTTPS"],
  ["rouge-xcto-absente.json", "FAIL", "EX-4", "X-Content-Type-Options absente"],
  ["rouge-clickjacking.json", "FAIL", "EX-5", "ni X-Frame-Options ni frame-ancestors"],
  ["rouge-referrer-absente.json", "FAIL", "EX-6", "Referrer-Policy absente"],
  ["rouge-referrer-unsafe.json", "FAIL", "EX-6", "Referrer-Policy unsafe-url"],
  ["rouge-cookie-insecure.json", "FAIL", "EX-8", "cookie sans Secure"],
  ["rouge-cookie-sans-httponly.json", "FAIL", "EX-9", "cookie sans HttpOnly"],
  ["rouge-cookie-sans-samesite.json", "FAIL", "EX-10", "cookie sans SameSite"],
  ["rouge-version-leak.json", "FAIL", "EX-11", "fuite de version serveur"],
  ["rouge-invalide.json", "FAIL", "—", "capture sans champ headers"],
];
for (const [fichier, verdictAttendu, regle, libelle] of casExposition) {
  const r = runJson(ORACLE_EXPOSITION, [FX("exposition", fichier)]);
  const bon = r.verdict === verdictAttendu && (regle === null || aRegle(r, regle));
  ok(bon, `${fichier} (${libelle}) → ${verdictAttendu}${regle ? " avec " + regle : ""} (obtenu ${r.verdict})`);
}
// EX-7 (Permissions-Policy absente) est un défaut MINEUR par doctrine (surface moindre que
// les 10 autres règles) : le verdict global reste PASS, seule la présence du finding prouve
// que la règle a bien été évaluée — double sens au niveau de la règle, pas du verdict global.
{
  const r = runJson(ORACLE_EXPOSITION, [FX("exposition", "rouge-permissions-absente.json")]);
  ok(r.verdict === "PASS" && aRegle(r, "EX-7"), `rouge-permissions-absente.json (Permissions-Policy absente, sévérité mineure) → règle EX-7 relevée, verdict PASS par doctrine (obtenu ${r.verdict})`);
}
// refus propre : capture absente
{
  const r = runJson(ORACLE_EXPOSITION, [FX("exposition", "n-existe-pas.json")]);
  ok(r.verdict === "SKIP", `capture introuvable → SKIP (obtenu ${r.verdict})`);
}

console.log("\nSELF-TEST forge-websec — oracle-sca (dépend de l'outillage réel du poste)\n");

const npmDispo = (() => { try { return spawnSync("npm", ["--version"], { encoding: "utf8", shell: process.platform === "win32" }).status === 0; } catch { return false; } })();
const pipDispo = (() => { try { return spawnSync("pip-audit", ["--version"], { encoding: "utf8", shell: process.platform === "win32" }).status === 0; } catch { return false; } })();
console.log(`  outillage détecté : npm=${npmDispo ? "présent" : "absent"} pip-audit=${pipDispo ? "présent" : "absent"}`);

// ── npm : sens rouge (lodash 4.17.15, CVE connues) ───────────────────────────
if (!npmDispo) {
  skipNote("npm absent du poste — sens rouge SCA-NPM non démontrable, self-test ne compte ni PASS ni FAIL");
} else {
  const r = runJson(ORACLE_SCA, [FX("sca", "npm-vulnerable")]);
  if (r.verdict === "SKIP") skipNote(`npm présent mais audit indisponible (probable absence réseau vers le registre) — sens rouge SCA-NPM non démontré cette exécution : ${JSON.stringify(r.findings)}`);
  else ok(r.verdict === "FAIL" && aRegle(r, "SCA-NPM"), `npm-vulnerable (lodash 4.17.15) → FAIL avec SCA-NPM (obtenu ${r.verdict})`);
}
// ── npm : sens vert (aucune dépendance) ──────────────────────────────────────
if (!npmDispo) {
  skipNote("npm absent du poste — sens vert SCA-NPM non démontrable");
} else {
  const r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")]);
  if (r.verdict === "SKIP") skipNote(`npm présent mais audit indisponible — sens vert SCA-NPM non démontré cette exécution : ${JSON.stringify(r.findings)}`);
  else ok(r.verdict === "PASS", `npm-clean (aucune dépendance) → PASS (obtenu ${r.verdict})`);
}

// ── pip : sens rouge (django 1.4, CVE connues nombreuses) ────────────────────
if (!pipDispo) {
  skipNote("pip-audit absent du poste — sens rouge SCA-PIP non démontrable");
} else {
  const r = runJson(ORACLE_SCA, [FX("sca", "pip-vulnerable")]);
  if (r.verdict === "SKIP") skipNote(`pip-audit présent mais audit indisponible (base d'avisos injoignable) — sens rouge SCA-PIP non démontré cette exécution : ${JSON.stringify(r.findings)}`);
  else ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP"), `pip-vulnerable (django 1.4) → FAIL avec SCA-PIP (obtenu ${r.verdict})`);
}
// ── pip : sens vert (aucune dépendance) ──────────────────────────────────────
if (!pipDispo) {
  skipNote("pip-audit absent du poste — sens vert SCA-PIP non démontrable");
} else {
  const r = runJson(ORACLE_SCA, [FX("sca", "pip-clean")]);
  if (r.verdict === "SKIP") skipNote(`pip-audit présent mais audit indisponible — sens vert SCA-PIP non démontré cette exécution : ${JSON.stringify(r.findings)}`);
  else ok(r.verdict === "PASS", `pip-clean (aucune dépendance) → PASS (obtenu ${r.verdict})`);
}

// ── fail-visible : ni manifeste ni outil exploitable → SKIP motivé, jamais un PASS ──
{
  const r = runJson(ORACLE_SCA, [FX("sca", "aucun-manifeste")]);
  ok(r.verdict === "SKIP", `dossier sans aucun manifeste → SKIP motivé, jamais un PASS silencieux (obtenu ${r.verdict})`);
}
// ── refus propre : cible absente ─────────────────────────────────────────────
{
  const r = runJson(ORACLE_SCA, [FX("sca", "n-existe-pas")]);
  ok(r.verdict === "SKIP", `cible introuvable → SKIP (obtenu ${r.verdict})`);
}
// ── seuils personnalisés : fichier introuvable → refus net, aucun défaut implicite ──
{
  const r = runJson(ORACLE_SCA, [FX("sca", "npm-clean"), "--seuils", FX("sca", "seuils-n-existent-pas.json")]);
  ok(r.verdict === "FAIL", `--seuils pointant un fichier introuvable → FAIL (aucun défaut implicite) (obtenu ${r.verdict})`);
}

console.log("\nSELF-TEST forge-websec — oracle-dast (garde-fou dual-use + lecture de rapport ZAP)\n");

// Aucun de ces cas n'émet quoi que ce soit vers une cible : les cas « garde-fou » s'arrêtent
// AVANT toute exécution, et les cas « rapport » jugent un fichier local (--rapport), jamais un
// scan. Le cas « ZAP absent » force WEBSEC_DAST_ZAP sur un chemin injouable pour rester
// déterministe même sur un poste qui, lui, aurait ZAP installé — un self-test ne lance jamais
// de scan, fût-il autorisé.
const AUTZ = (f) => FX("dast", f);
const CIBLE_OK = "https://recette.exemple.tld";

function runDast(args, env) {
  try { return JSON.parse(execFileSync(process.execPath, [ORACLE_DAST, ...args, "--json-only"], { encoding: "utf8", timeout: 60000, env: { ...process.env, WEBSEC_DAST_AUTORISATION: "", ...(env || {}) } })); }
  catch (e) { try { return JSON.parse(String(e.stdout)); } catch { return { verdict: "ILLISIBLE", findings: [], _stderr: String(e.stderr || e) }; } }
}

// ── sens ROUGE du garde-fou : six refus fail-closed ──────────────────────────
{
  const r = runDast([]);
  ok(r.verdict === "SKIP" && aRegle(r, "DAST-USAGE"), `aucune cible → SKIP motivé, aucune cible par défaut (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-ABSENTE"), `cible sans autorisation → FAIL avec DAST-AUTZ-ABSENTE (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", "https://recette.exemple.tId", "--autorisation", AUTZ("autorisation-valide.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-CIBLE"), `cible mal orthographiée (exemple.tId) hors des cibles déclarées → FAIL avec DAST-AUTZ-CIBLE (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-expiree.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-FENETRE"), `autorisation hors fenêtre → FAIL avec DAST-AUTZ-FENETRE (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-production.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-PROD"), `production sans autorisation distincte → FAIL avec DAST-AUTZ-PROD (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-incomplete.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-CHAMPS"), `autorisation incomplète → FAIL avec DAST-AUTZ-CHAMPS (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--mode", "actif"]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-MODE"), `mode actif sans actif_autorise → FAIL avec DAST-AUTZ-MODE (obtenu ${r.verdict})`);
}
// ── sens VERT du garde-fou : autorisation conforme, aucun refus levé ─────────
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-propre.json")]);
  const aucunRefus = !(r.findings || []).some((f) => String(f.regle).startsWith("DAST-AUTZ"));
  ok(r.verdict === "PASS" && aucunRefus, `autorisation conforme + rapport ZAP propre → PASS sans aucun refus DAST-AUTZ-* (obtenu ${r.verdict})`);
}
// ── ZAP absent : SKIP motivé, jamais un PASS de complaisance ─────────────────
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json")], { WEBSEC_DAST_ZAP: AUTZ("zap-qui-n-existe-pas") });
  ok(r.verdict === "SKIP" && aRegle(r, "DAST-SKIP"), `cible autorisée mais ZAP introuvable → SKIP motivé avec DAST-SKIP, jamais un PASS (obtenu ${r.verdict})`);
}
// ── seuils : sens rouge, puis preuve que --seuils est réellement appliqué ────
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-vulnerable.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-SEUIL"), `rapport ZAP à 1 high + 2 medium → FAIL avec DAST-SEUIL (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-vulnerable.json"), "--seuils", AUTZ("seuils-permissifs.json")]);
  ok(r.verdict === "PASS" && r.seuils_appliques && r.seuils_appliques.high === 5, `même rapport avec --seuils desserrés → PASS et seuils_appliques tracés (obtenu ${r.verdict})`);
}
// ── refus net : rapport annoncé mais introuvable / illisible ─────────────────
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-qui-n-existe-pas.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-RAPPORT"), `--rapport pointant un fichier introuvable → FAIL (aucun verdict sans artefact) (obtenu ${r.verdict})`);
}
{
  const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", FX("exposition", "vert-complet.json")]);
  ok(r.verdict === "FAIL" && aRegle(r, "DAST-RAPPORT"), `--rapport pointant un JSON qui n'est pas un rapport ZAP → FAIL, jamais un PASS silencieux (obtenu ${r.verdict})`);
}

// ── TF-2001 · oracle-workflows : durcissement des workflows GitHub Actions, WF-1..WF-5 ────────
// Déterministe : lecture de fichiers YAML synthétiques, aucun réseau, rien d'exécuté. Chaque rouge
// doit lever SA règle et aucune autre règle dure, pour prouver qu'elle échoue pour la bonne raison.
console.log("\nSELF-TEST forge-websec — oracle-workflows (statique, déterministe, WF-1..WF-5)\n");
{
  const ORACLE_WORKFLOWS = path.join(HERE, "oracle-workflows.mjs");
  const WFX = (...p) => FX("workflows", ...p);
  const DURS = new Set(["bloquant", "majeur"]);
  const durs = (r) => (r.findings || []).filter((f) => DURS.has(f.sev));
  const casWorkflows = [
    ["vert-complet.yml", "PASS", null, "permissions minimales, SHA complets, variable intermédiaire, OIDC"],
    ["vert-id-token-au-workflow.yml", "PASS", null, "id-token: write hérité du workflow, qui n'est pas une écriture"],
    ["rouge-permissions-absentes.yml", "FAIL", "WF-1", "aucune clé permissions"],
    ["rouge-permissions-write-all.yml", "FAIL", "WF-1", "permissions: write-all"],
    ["rouge-action-non-epinglee.yml", "FAIL", "WF-2", "action tierce épinglée par étiquette"],
    ["rouge-pull-request-target.yml", "FAIL", "WF-3", "déclencheur pull_request_target"],
    ["rouge-pull-request-target-checkout.yml", "FAIL", "WF-3", "checkout de la tête de la pull request"],
    ["rouge-injection-run.yml", "FAIL", "WF-4", "titre d'issue substitué dans run"],
    ["rouge-injection-env.yml", "FAIL", "WF-4", "corps de commentaire substitué par env.CORPS"],
    ["rouge-secret-long.yml", "FAIL", "WF-5", "jeton PyPI en secret, sans id-token: write"],
    ["rouge-illisible.yml", "FAIL", "—", "chaîne jamais fermée : fichier non jugé"],
  ];
  for (const [fichier, verdictAttendu, regle, libelle] of casWorkflows) {
    const r = runJson(ORACLE_WORKFLOWS, [WFX(fichier)]);
    const bon = r.verdict === verdictAttendu && (regle === null
      ? !(r.findings || []).some((f) => f.sev !== "info")
      : aRegle(r, regle) && durs(r).every((f) => f.regle === regle));
    ok(bon, `${fichier} (${libelle}) → ${verdictAttendu}${regle ? ` avec ${regle} et aucune autre règle dure` : " sans aucun constat"} (obtenu ${r.verdict} : ${[...new Set((r.findings || []).filter((f) => f.sev !== "info").map((f) => f.regle))].join(", ") || "rien"})`);
  }
  {
    const r = runJson(ORACLE_WORKFLOWS, [WFX("rouge-pull-request-target-checkout.yml")]);
    ok((r.findings || []).some((f) => f.regle === "WF-3" && f.sev === "bloquant"),
      `WF-3 · le checkout de la tête de la pull request sous pull_request_target est relevé en BLOQUANT (forme « pwn request »), pas seulement le déclencheur (obtenu ${r.verdict})`);
  }
  {
    const r = runJson(ORACLE_WORKFLOWS, [WFX("rouge-action-non-epinglee.yml")]);
    ok((r.findings || []).some((f) => f.regle === "WF-2" && f.sev === "majeur" && /exemple-org\/outil-tiers@v2/.test(f.msg)),
      "WF-2 · l'action tierce non épinglée est nommée dans le constat, en sévérité majeure");
  }
  {
    // Sévérité MINEURE par doctrine, comme EX-7 : l'action d'une organisation de GitHub épinglée par
    // étiquette est relevée sans faire échouer le verdict (la page n'admet l'étiquette que si l'on fait
    // confiance au créateur, et l'oracle ne présume cette confiance que pour GitHub lui-même).
    const r = runJson(ORACLE_WORKFLOWS, [WFX("mineur-action-github-etiquette.yml")]);
    ok(r.verdict === "PASS" && (r.findings || []).some((f) => f.regle === "WF-2" && f.sev === "mineur"),
      `mineur-action-github-etiquette.yml (actions/checkout@v6) → règle WF-2 relevée en mineur, verdict PASS par doctrine (obtenu ${r.verdict})`);
  }
  {
    // Dépôt entier : l'oracle trouve .github/workflows, lit le verrou, et départage les deux workflows.
    const r = runJson(ORACLE_WORKFLOWS, [WFX("depot-verrouille")]);
    const wf2 = durs(r).filter((f) => f.regle === "WF-2");
    ok(r.verdict === "FAIL" && r.synthese?.fichiers_juges === 2 && wf2.length === 1 && /hors-verrou\.yml/.test(wf2[0].where),
      `dépôt avec actions.lock → seul le workflow NON inscrit au verrou lève WF-2 (obtenu ${r.verdict}, ${wf2.length} WF-2 dur, ${r.synthese?.fichiers_juges ?? "?"} fichiers jugés)`);
  }
  {
    const r = runJson(ORACLE_WORKFLOWS, [WFX("depot-verrouille", ".github", "workflows", "ci.yml")]);
    ok(r.verdict === "PASS" && (r.findings || []).some((f) => f.regle === "WF-2" && f.sev === "info"),
      `workflow inscrit au verrou, jugé seul → PASS, la référence par étiquette est dite couverte par actions.lock (obtenu ${r.verdict})`);
  }
  {
    // « Chaque règle cite la page de docs.github.com qui la fonde » : vérifié sur tous les rouges.
    const regles = new Set();
    let sansSource = 0;
    for (const [fichier, , regle] of casWorkflows) {
      if (!regle || regle === "—") continue;
      for (const f of runJson(ORACLE_WORKFLOWS, [WFX(fichier)]).findings || []) {
        if (!/^WF-\d$/.test(f.regle)) continue;
        regles.add(f.regle);
        if (!/^https:\/\/docs\.github\.com\/en\//.test(f.source || "")) sansSource++;
      }
    }
    ok(regles.size === 5 && sansSource === 0,
      `chaque constat WF-1..WF-5 cite sa page docs.github.com (${regles.size} règles vues sur 5, ${sansSource} constat sans source)`);
  }
  {
    const r = runJson(ORACLE_WORKFLOWS, [WFX("n-existe-pas.yml")]);
    ok(r.verdict === "SKIP", `cible introuvable → SKIP (obtenu ${r.verdict})`);
  }
  {
    const r = runJson(ORACLE_WORKFLOWS, [FX("sca", "aucun-manifeste")]);
    ok(r.verdict === "SKIP", `dossier sans aucun workflow → SKIP motivé, jamais un PASS silencieux (obtenu ${r.verdict})`);
  }
}

// ── TF-1996 · oracle-exposition-statique : un fichier _headers jugé par les règles EX-1..EX-11 ──
// La lecture statique d'un _headers (Cloudflare Workers static assets ou Pages) ne réécrit aucune
// règle d'en-tête : elle calcule les en-têtes que chaque requête sondée recevrait, puis les passe à
// jugerEnTetes d'oracle-exposition. La réutilisation se prouve par l'équivalence : un _headers qui
// pose les en-têtes d'une capture lève exactement les règles que lève la capture.
console.log("\nSELF-TEST forge-websec — oracle-exposition-statique (fichier _headers, règles EX-1..EX-11 réutilisées)\n");
{
  const ORACLE_STATIQUE = path.join(HERE, "oracle-exposition-statique.mjs");
  const HX = (...p) => FX("exposition-statique", ...p);
  const DURS = new Set(["bloquant", "majeur"]);
  const reglesDures = (r) => [...new Set((r.findings || []).filter((f) => DURS.has(f.sev)).map((f) => f.regle))].sort();
  const cas = [
    // [dossier, verdict attendu, règle exigée, règles dures admises, libellé]
    ["vert-complet", "PASS", null, [], "en-têtes de la capture verte sur /*, règle de cache sur /static/*"],
    ["rouge-csp-absente", "FAIL", "EX-1", ["EX-1"], "CSP absente de la règle /*, indentation par tabulation"],
    ["rouge-cookie-insecure", "FAIL", "EX-8", ["EX-8"], "Set-Cookie sans Secure"],
    ["rouge-detache-csp", "FAIL", "EX-1", ["EX-1"], "CSP retirée par « ! Content-Security-Policy » sous /telechargements/*"],
    ["rouge-racine-nue", "FAIL", "EX-1", ["EX-1", "EX-3", "EX-4", "EX-5", "EX-6"], "aucune règle ne couvre la racine /"],
    ["rouge-syntaxe", "FAIL", "HD-1", ["HD-1"], "en-tête hors règle, URL en http, port, deux astérisques, ligne sans « : »"],
    ["rouge-trop-de-regles", "FAIL", "HD-2", ["HD-2"], "101 règles pour 100 admises"],
    ["rouge-ligne-trop-longue", "FAIL", "HD-2", ["HD-2"], "ligne de plus de 2 000 caractères"],
  ];
  for (const [dossier, verdictAttendu, regle, admises, libelle] of cas) {
    const r = runJson(ORACLE_STATIQUE, [HX(dossier)]);
    const dures = reglesDures(r);
    const bon = r.verdict === verdictAttendu && (regle === null
      ? !(r.findings || []).some((f) => f.sev !== "info")
      : aRegle(r, regle) && dures.every((x) => admises.includes(x)));
    ok(bon, `${dossier}/_headers (${libelle}) → ${verdictAttendu}${regle ? ` avec ${regle}, rien hors de ${admises.join(", ")}` : " sans aucun constat"} (obtenu ${r.verdict} : ${dures.join(", ") || "rien de dur"})`);
  }
  // Réutilisation sans duplication : mêmes en-têtes, mêmes règles levées par les deux oracles.
  const leves = (r) => [...new Set((r.findings || []).filter((f) => f.sev !== "info").map((f) => `${f.sev}:${f.regle}`))].sort().join(" ");
  for (const [capture, dossier] of [["vert-complet.json", "vert-complet"], ["rouge-csp-absente.json", "rouge-csp-absente"], ["rouge-cookie-insecure.json", "rouge-cookie-insecure"]]) {
    const a = runJson(ORACLE_EXPOSITION, [FX("exposition", capture)]);
    const b = runJson(ORACLE_STATIQUE, [HX(dossier)]);
    ok(a.verdict === b.verdict && leves(a) === leves(b),
      `réutilisation · ${capture} et ${dossier}/_headers portent les mêmes en-têtes → mêmes règles levées par oracle-exposition et par la lecture statique (« ${leves(a) || "aucune"} » / « ${leves(b) || "aucune"} »)`);
  }
  {
    const r = runJson(ORACLE_STATIQUE, [HX("rouge-detache-csp")]);
    const ex1 = (r.findings || []).filter((f) => f.regle === "EX-1");
    ok(ex1.length === 1 && Array.isArray(ex1[0].sondes) && ex1[0].sondes.includes("/telechargements/x") && !ex1[0].sondes.includes("/"),
      `détachement · la CSP retirée sous /telechargements/* ne manque qu'à cette sonde, la racine / la garde (sondes en EX-1 : ${ex1[0]?.sondes?.join(", ") ?? "aucune"})`);
  }
  {
    const r = runJson(ORACLE_STATIQUE, [HX("rouge-racine-nue")]);
    const ex1 = (r.findings || []).filter((f) => f.regle === "EX-1");
    ok(ex1.length === 1 && Array.isArray(ex1[0].sondes) && ex1[0].sondes.includes("/") && !ex1[0].sondes.includes("/app/x"),
      `sonde racine · une règle limitée à /app/* laisse la racine / sans en-tête, /app/x reste couvert (sondes en EX-1 : ${ex1[0]?.sondes?.join(", ") ?? "aucune"})`);
  }
  {
    const r = runJson(ORACLE_STATIQUE, [HX("rouge-syntaxe")]);
    const hd1 = (r.findings || []).filter((f) => f.regle === "HD-1");
    const sources = (r.findings || []).filter((f) => /^HD-/.test(f.regle)).every((f) => /^https:\/\/developers\.cloudflare\.com\//.test(f.source || ""));
    ok(hd1.length === 5 && sources && (r.sources || []).length === 2 && r.sources.every((s) => s.lu_le === "2026-10-28"),
      `HD-1 · les 5 défauts de syntaxe sont relevés un par un, chacun avec sa page developers.cloudflare.com, les 2 pages lues datées (${hd1.length} relevés)`);
  }
  {
    const r = runJson(ORACLE_STATIQUE, [HX("n-existe-pas")]);
    ok(r.verdict === "SKIP", `cible introuvable → SKIP (obtenu ${r.verdict})`);
  }
  {
    const r = runJson(ORACLE_STATIQUE, [FX("sca", "aucun-manifeste")]);
    ok(r.verdict === "SKIP", `dossier sans fichier _headers → SKIP motivé, jamais un PASS silencieux (obtenu ${r.verdict})`);
  }
}

// ── TF-2095 · la capture ne garde jamais la VALEUR d'un cookie (classe capture-de-preuve-porte-un-jeton) ──
// Une capture rangée sous forge/etapes/websec est versionnée : un jeton de session ou de formulaire y
// entrerait dans le dépôt. Le banc sert la réponse d'une origine locale qui pose trois cookies (dont une
// valeur à « = » de bourrage et un cookie sans attribut de sécurité), lance le VRAI capturer.mjs contre
// elle, puis juge la capture : ROUGE si une valeur survit dans le fichier ou dans la sortie standard,
// VERT si les noms et les attributs restent, de sorte qu'oracle-exposition juge encore la capture.
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2095 : valeur des cookies caviardée à la capture)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const SECRETS = ["JETON-SESSION-9f3a7c21", "JETON-FORMULAIRE-b81d44e0", "YWJjZGVmZw=="];
  const origine = http.createServer((req, res) => {
    res.setHeader("Set-Cookie", [
      `session=${SECRETS[0]}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`,
      `csrf=${SECRETS[1]}; Path=/app; SameSite=Lax`,
      `jeton=${SECRETS[2]}; Domain=exemple.test; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=None`,
    ]);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.end("ok");
  });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const urlOrigine = `http://127.0.0.1:${origine.address().port}/`;
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-capture-"));
  const lancer = (args) => new Promise((resolve) => execFile(process.execPath, [CAPTURER, urlOrigine, ...args], { encoding: "utf8", timeout: 30000 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
  try {
    const fichier = path.join(tmpCap, "capture.json");
    const viaFichier = await lancer(["--sortie", fichier]);
    const brut = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : "";
    const viaStdout = await lancer([]);
    ok(viaFichier.code === 0 && viaStdout.code === 0 && brut.length > 0,
      `capturer.mjs capture l'origine locale à cookies, par fichier et par sortie standard (codes ${viaFichier.code} / ${viaStdout.code})`);
    // ROUGE : aucune valeur de cookie ne survit, ni dans le fichier, ni sur la sortie standard, ni dans les messages.
    const survivants = SECRETS.filter((s) => (brut + viaStdout.stdout + viaFichier.stderr + viaStdout.stderr).includes(s));
    ok(survivants.length === 0,
      `ROUGE · la valeur des 3 cookies est caviardée à la capture — fichier, sortie standard et messages (valeurs survivantes : ${survivants.length})`);
    // VERT : la capture reste exploitable — noms et attributs présents, un seul caviardage par cookie.
    let cap = null;
    try { cap = JSON.parse(brut); } catch { /* le contrôle suivant le dit */ }
    const sc = cap?.headers?.["set-cookie"];
    const attendu = [
      ["session", ["Path=/", "HttpOnly", "Secure", "SameSite=Strict", "Max-Age=3600"]],
      ["csrf", ["Path=/app", "SameSite=Lax"]],
      ["jeton", ["Domain=exemple.test", "Expires=Wed, 21 Oct 2026 07:28:00 GMT", "Secure", "HttpOnly", "SameSite=None"]],
    ];
    const nomsEtAttributs = Array.isArray(sc) && sc.length === 3 && attendu.every(([nom, attrs]) => {
      const c = sc.find((x) => x.startsWith(`${nom}=`));
      if (!c) return false;
      const segments = c.split(";").map((s) => s.trim());
      return attrs.every((a) => segments.includes(a)) && segments.length === attrs.length + 1 && !/^[^=]+=$/.test(segments[0]);
    });
    ok(nomsEtAttributs,
      "VERT · les 3 cookies gardent leur nom et tous leurs attributs (Path, Domain, Expires, Max-Age, Secure, HttpOnly, SameSite), la valeur seule est remplacée");
    ok(cap?.headers?.["x-content-type-options"] === "nosniff" && cap?.status === 200,
      "VERT · le reste de la capture (statut, autres en-têtes) est intact");
    // Exploitable : oracle-exposition juge cette capture (EX-8/EX-9 sur csrf, jamais sur session) et ne recopie aucune valeur.
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    const ex8 = (jug.findings || []).filter((f) => f.regle === "EX-8").map((f) => f.msg).join(" ");
    ok(jug.verdict === "FAIL" && /« csrf »/.test(ex8) && !/« session »/.test(ex8),
      `VERT · la capture caviardée reste exploitable : oracle-exposition lève EX-8 sur le seul cookie csrf, sans Secure (obtenu ${jug.verdict}, EX-8 : « ${ex8.slice(0, 60)} »)`);
    ok(!SECRETS.some((s) => JSON.stringify(jug).includes(s)),
      "oracle-exposition ne réintroduit aucune valeur de cookie dans son verdict (capture caviardée)");
    // oracle-exposition sur une capture NON caviardée (fixture historique à valeur « abc123 ») : il nomme le cookie, jamais sa valeur.
    const brute = runJson(ORACLE_EXPOSITION, [FX("exposition", "rouge-cookie-insecure.json")]);
    ok(brute.verdict === "FAIL" && aRegle(brute, "EX-8") &&!JSON.stringify(brute).includes("abc123"),
      "oracle-exposition sur une capture à valeur en clair (abc123) : règle levée, mais la valeur n'est recopiée dans aucun constat");
    // Bords de la fonction de caviardage : valeur à « = », cookie sans nom, sans valeur, tableau vide.
    const { caviarderSetCookie } = await import(pathToFileURL(path.join(HERE, "..", "scripts", "caviarder-cookies.mjs")).href);
    const bords = [
      ["a=b=c==; Secure", "a=[caviardé]; Secure"],
      ["JETONSEUL; HttpOnly", "=[caviardé]; HttpOnly"],
      ["vide=; Path=/", "vide=[caviardé]; Path=/"],
      ["  espace = val ue ;Secure;SameSite=Lax", "espace=[caviardé]; Secure; SameSite=Lax"],
    ];
    const ecarts = bords.filter(([entree, sortie]) => caviarderSetCookie(entree) !== sortie).map(([e]) => e);
    ok(ecarts.length === 0 && Array.isArray(caviarderSetCookie([])) && caviarderSetCookie([]).length === 0,
      `bords du caviardage : valeur à « = », cookie sans nom, valeur vide, espaces, liste vide (écarts : ${ecarts.length})`);
  } finally {
    origine.close();
    fs.rmSync(tmpCap, { recursive: true, force: true });
  }
}

// ── TF-1319 · la découverte des oracles LIT LE DISQUE, dans les deux sens ─────────────────────
// Le juge du pilot (méta-oracle d'enclenchement) confronte ce que cette forge DÉCOUVRE aux
// verdicts consignés au ledger d'un run. Une découverte qui raterait un oracle le rendrait
// invisible au juge ; une découverte qui prendrait une recette ou une fixture pour un oracle
// ferait accuser un run de n'avoir pas joué ce qui n'est pas un oracle. Les deux sens se prouvent,
// sans réseau ni outillage : ce bloc est déterministe sur tout poste.
{
  const DECOUVRIR = path.join(HERE, "decouvrir-oracles.mjs");
  const decouvre = (racine) => {
    const r = spawnSync(process.execPath, [DECOUVRIR, ...(racine ? ["--racine", racine] : [])], { encoding: "utf8" });
    let j = null;
    try { j = JSON.parse(r.stdout); } catch { /* sortie illisible : les contrôles ci-dessous la disent */ }
    return { code: r.status, j };
  };
  const reel = decouvre(null);
  ok(reel.code === 0 && reel.j?.contrat === "digit-ai/decouverte-oracles@1" && reel.j?.forge === "digit-ai-forge-websec"
    && reel.j.oracles.length > 0 && reel.j.oracles.every((o) => fs.existsSync(path.join(HERE, "..", o.chemin))),
    `TF-1319 · VERT — la forge découvre ${reel.j?.oracles?.length ?? "?"} oracle(s) sur son propre disque, contrat digit-ai/decouverte-oracles@1 tenu, chaque chemin rendu existe`);
  const tmpDec = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-decouverte-"));
  try {
    const poser = (rel) => {
      const p = path.join(tmpDec, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, "// fixture de découverte\n");
    };
    ["oracles/oracle-alpha.mjs", "scripts/oracle_beta.py"].forEach(poser);
    const leurres = ["oracles/oracle-alpha.test.mjs", "oracles/self-test.mjs", "scripts/capturer.mjs",
      "fixtures/oracle-faux.mjs", "Old/oracle-vieux.mjs", "node_modules/paquet/oracle-dep.mjs", "input/oracle-entrant.mjs"];
    leurres.forEach(poser);
    const v = decouvre(tmpDec);
    const noms = (v.j?.oracles || []).map((o) => o.nom).sort();
    ok(v.code === 0 && JSON.stringify(noms) === JSON.stringify(["oracle-alpha", "oracle_beta"]),
      `TF-1319 · VERT — un oracle posé sur le disque est découvert, où qu'il vive dans le dépôt (obtenu ${JSON.stringify(noms)})`);
    ok(v.code === 0 && !(v.j?.oracles || []).some((o) => leurres.includes(o.chemin)),
      `TF-1319 · ROUGE — recette, capture, fixture, archive, dépendance et entrant ne sont JAMAIS pris pour des oracles (${leurres.length} leurres refusés)`);
    poser("oracles/oracle-gamma.mjs");
    const apres = decouvre(tmpDec);
    ok((apres.j?.oracles || []).some((o) => o.nom === "oracle-gamma" && o.chemin === "oracles/oracle-gamma.mjs"),
      "TF-1319 · un oracle AJOUTÉ est découvert au passage suivant sans qu'aucune liste soit tenue à jour : la liste vient du disque");
    poser("scripts/oracle-alpha.mjs");
    const doublon = decouvre(tmpDec);
    ok((doublon.j?.non_juge || []).some((n) => /oracle-alpha/.test(n) && /2 fichiers/.test(n)),
      "TF-1319 · deux fichiers du même nom sont DITS : un verdict qui le nomme ne dit pas lequel a tourné");
  } finally {
    fs.rmSync(tmpDec, { recursive: true, force: true });
  }
  const absente = decouvre(path.join(os.tmpdir(), "forge-websec-racine-qui-n-existe-pas"));
  ok(absente.code === 2 && absente.j?.oracles?.length === 0 && /introuvable/.test(absente.j?.motif || ""),
    `TF-1319 · ROUGE — une racine absente sort en 2 avec son motif, jamais en liste vide muette (obtenu exit ${absente.code})`);
}

console.log(`\nSelf-test forge-websec : ${pass} PASS, ${echec} FAIL, ${note} SKIP motivé (outillage/réseau du poste, non comptés)`);
process.exit(echec ? 1 : 0);
