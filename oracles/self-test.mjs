#!/usr/bin/env node
// self-test.mjs — preuve par le geste (double sens) : rejoue TOUTES les fixtures des deux
// oracles et vérifie que chaque verte PASSE (ou, pour la SCA dépendante du poste, que le
// silence est un SKIP motivé et jamais un PASS non prouvé) et que chaque rouge ÉCHOUE pour
// la bonne raison (code `regle` vérifié dans les findings, pas juste un verdict générique).
//
// oracle-exposition : intégralement déterministe, zéro dépendance externe, zéro réseau —
// les 15 fixtures locales sont rejouées à l'identique à chaque exécution.
// oracle-sca : dépend de l'outillage RÉELLEMENT présent sur le poste (npm, pip-audit) et,
// pour npm/pip-audit, d'un accès réseau à leur base d'avisos. Le sens rouge n'est démontré
// que si l'outil est disponible ET répond — sinon SKIP motivé consigné (jamais compté comme
// un échec du self-test, jamais présenté comme une preuve du sens rouge).
//
// Exit 0 si tous les contrôles PROUVÉS passent, 1 sinon. À rejouer après toute modification.
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = (...p) => path.join(HERE, "..", "fixtures", ...p);
const ORACLE_EXPOSITION = path.join(HERE, "oracle-exposition.mjs");
const ORACLE_SCA = path.join(HERE, "oracle-sca.mjs");

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

console.log(`\nSelf-test forge-websec : ${pass} PASS, ${echec} FAIL, ${note} SKIP motivé (outillage/réseau du poste, non comptés)`);
process.exit(echec ? 1 : 0);
