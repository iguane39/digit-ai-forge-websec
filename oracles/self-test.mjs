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

// `delai` : l'oracle-sca laisse 240 s à uvx (résolution de django 1.4 dans un environnement isolé, 159 s mesurées le
// 12/11/2026) ; le banc doit attendre plus longtemps que l'oracle, sinon un audit réussi est lu comme ILLISIBLE (TF-2398).
function runJson(script, args, env, delai = 120000) {
  try { return JSON.parse(execFileSync(process.execPath, [script, ...args, "--json-only"], { encoding: "utf8", timeout: delai, ...(env ? { env: { ...process.env, ...env } } : {}) })); }
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
// uvx lance pip-audit sans installation globale : l'oracle l'utilise quand pip-audit est absent (TF-2272),
// donc le banc le compte comme une voie pip du poste (TF-2398) au lieu de passer le sens rouge en SKIP.
const uvxDispo = (() => { try { return spawnSync("uvx", ["--version"], { encoding: "utf8", shell: process.platform === "win32" }).status === 0; } catch { return false; } })();
const pipVoie = pipDispo ? "pip-audit" : (uvxDispo ? "uvx pip-audit" : null);
// Le remède que l'oracle lui-même rend quand ni pip-audit ni uvx ne sont là : une seule source, la commande épinglée.
const remedePipAbsent = () => {
  const r = runJson(ORACLE_SCA, [FX("sca", "pip-clean")], { WEBSEC_SCA_PIP_AUDIT: path.join(os.tmpdir(), "websec-outil-absent"), WEBSEC_SCA_UVX: path.join(os.tmpdir(), "websec-outil-absent") });
  return ((r.manques || [])[0] || {}).remede || "remède non lu";
};
console.log(`  outillage détecté : npm=${npmDispo ? "présent" : "absent"} pip-audit=${pipDispo ? "présent" : "absent"} uvx=${uvxDispo ? "présent" : "absent"}`);

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
if (!pipVoie) {
  skipNote(`ni pip-audit ni uvx sur le poste — sens rouge SCA-PIP non démontrable ; pour le jouer : ${remedePipAbsent()}`);
} else {
  const r = runJson(ORACLE_SCA, [FX("sca", "pip-vulnerable")], undefined, 300000);
  if (r.verdict === "SKIP") skipNote(`${pipVoie} présent mais audit indisponible (base d'avisos injoignable) — sens rouge SCA-PIP non démontré cette exécution : ${JSON.stringify(r.findings)}`);
  else ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP"), `pip-vulnerable (django 1.4) → FAIL avec SCA-PIP (obtenu ${r.verdict})`);
}
// ── pip : sens vert (aucune dépendance) ──────────────────────────────────────
if (!pipVoie) {
  skipNote(`ni pip-audit ni uvx sur le poste — sens vert SCA-PIP non démontrable ; pour le jouer : ${remedePipAbsent()}`);
} else {
  const r = runJson(ORACLE_SCA, [FX("sca", "pip-clean")], undefined, 300000);
  if (r.verdict === "SKIP") skipNote(`${pipVoie} présent mais audit indisponible — sens vert SCA-PIP non démontré cette exécution : ${JSON.stringify(r.findings)}`);
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

// ── verrous uv.lock / poetry.lock, uvx, manque nommé (TF-2272) ──────────────────
// Déterministe : un outil SIMULÉ (fixtures/sca/outils/outil-simule.mjs) joue pip-audit et
// `uvx pip-audit`, désigné par WEBSEC_SCA_PIP_AUDIT / WEBSEC_SCA_UVX ; rien n'est installé, rien
// ne passe par le réseau. Un chemin injouable simule l'absence de l'outil.
{
  const SIM = FX("sca", "outils", "outil-simule.mjs");
  const ABSENT = path.join(os.tmpdir(), "websec-outil-absent");
  const traceDir = fs.mkdtempSync(path.join(os.tmpdir(), "websec-sca-trace-"));
  const trace = path.join(traceDir, "appels.jsonl");
  // dossier temporaire PROPRE à ces cas : on y lit où l'oracle écrit son requirements dérivé, et qu'il l'efface
  const tmpOracle = path.join(traceDir, "tmp");
  fs.mkdirSync(tmpOracle);
  const tmpEnv = { TEMP: tmpOracle, TMP: tmpOracle, TMPDIR: tmpOracle };
  const lireTrace = () => (fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  const viaUvx = { WEBSEC_SCA_PIP_AUDIT: ABSENT, WEBSEC_SCA_UVX: SIM, WEBSEC_SIM_TRACE: trace, ...tmpEnv };
  const direct = { WEBSEC_SCA_PIP_AUDIT: SIM, WEBSEC_SCA_UVX: ABSENT, WEBSEC_SIM_TRACE: trace, ...tmpEnv };
  const rien = { WEBSEC_SCA_PIP_AUDIT: ABSENT, WEBSEC_SCA_UVX: ABSENT };
  const causes = (r) => (r.manques || []).map((m) => m.cause).join(" | ");

  let r = runJson(ORACLE_SCA, [FX("sca", "uv-vulnerable")], viaUvx);
  ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP") && (r.findings || []).some((f) => f.regle === "SCA-PIP" && /django 1\.4/.test(f.msg)),
    `uv.lock avec django 1.4, pip-audit absent, uvx présent → FAIL avec SCA-PIP sur django 1.4 (obtenu ${r.verdict})`);
  ok(r.synthese && r.synthese.pip && r.synthese.pip.outil === "uvx pip-audit" && r.synthese.pip.total_paquets === 1,
    `uv.lock : le projet (source virtual) et le paquet git ne sont pas audités, 1 paquet de registre jugé via « uvx pip-audit » (obtenu ${JSON.stringify(r.synthese && r.synthese.pip)})`);
  ok(/paquet-git/.test(causes(r)) && !/demo-app/.test(causes(r)),
    `uv.lock : le paquet hors registre est NOMMÉ au manque, le projet lui-même n'y figure pas (obtenu « ${causes(r)} »)`);
  const appels = lireTrace().filter((a) => a.argv.includes("-r")); // hors sonde de présence (--version)
  ok(appels.length === 1 && appels[0].mode === "uvx" && appels[0].argv.includes("--no-deps") && appels[0].argv.includes("--disable-pip"),
    `uv.lock : un seul appel d'audit « uvx pip-audit … --no-deps --disable-pip », rien n'est résolu ni installé (obtenu ${JSON.stringify(appels)})`);
  const reqUtilise = appels[0] && appels[0].argv[appels[0].argv.indexOf("-r") + 1];
  ok(typeof reqUtilise === "string" && reqUtilise.startsWith(tmpOracle) && !reqUtilise.startsWith(FX("sca")) && fs.readdirSync(tmpOracle).length === 0,
    `le requirements dérivé du verrou est écrit dans le dossier temporaire, jamais dans la cible, et supprimé après l'audit (obtenu ${reqUtilise}, ${fs.readdirSync(tmpOracle).length} reste)`);

  r = runJson(ORACLE_SCA, [FX("sca", "uv-propre")], viaUvx);
  ok(r.verdict === "PASS" && r.synthese.pip && r.synthese.pip.total_paquets === 2 && (r.manques || []).length === 0,
    `uv.lock sans avis (2 paquets, projet editable exclu) → PASS, aucun manque (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);

  r = runJson(ORACLE_SCA, [FX("sca", "uv-versions-multiples")], viaUvx);
  ok(r.verdict === "PASS" && r.synthese.pip && r.synthese.pip.total_paquets === 3,
    `uv.lock avec deux versions du même paquet → PASS, 3 paquets jugés en deux lots (pip-audit refuse deux versions du même nom dans un fichier) (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);

  r = runJson(ORACLE_SCA, [FX("sca", "poetry-vulnerable")], viaUvx);
  ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP") && r.synthese.pip && r.synthese.pip.total_paquets === 1 && /paquet-git/.test(causes(r)),
    `poetry.lock avec django 1.4 → FAIL avec SCA-PIP ; la table [package.dependencies] n'est pas lue comme un paquet, le paquet git est nommé au manque (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);
  r = runJson(ORACLE_SCA, [FX("sca", "poetry-propre")], viaUvx);
  ok(r.verdict === "PASS" && r.synthese.pip && r.synthese.pip.total_paquets === 2,
    `poetry.lock sans avis (2 paquets) → PASS (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);

  fs.rmSync(trace, { force: true });
  r = runJson(ORACLE_SCA, [FX("sca", "uv-vulnerable")], direct);
  ok(r.verdict === "FAIL" && r.synthese.pip && r.synthese.pip.outil === "pip-audit" && lireTrace().length > 0 && lireTrace().every((a) => a.mode === "direct"),
    `pip-audit présent, uvx absent → pip-audit est lancé directement, sans uvx (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip && r.synthese.pip.outil)})`);

  r = runJson(ORACLE_SCA, [FX("sca", "pip-vulnerable")], viaUvx);
  ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP") && r.synthese.pip.outil === "uvx pip-audit",
    `requirements.txt avec django 1.4, pip-audit absent, uvx présent → FAIL avec SCA-PIP via uvx (obtenu ${r.verdict})`);

  // le manque nommé : un SKIP dit quoi, où, pourquoi et le remède
  r = runJson(ORACLE_SCA, [FX("sca", "uv-propre")], rien);
  ok(r.verdict === "SKIP" && (r.manques || []).length === 1 && /uv\.lock/.test(causes(r)) && /ni pip-audit ni uvx/.test(causes(r)) && r.manques[0].remede && /uv\.lock/.test(r.manques[0].manifeste),
    `uv.lock sans pip-audit ni uvx → SKIP avec un manque nommé (manifeste, cause, remède) (obtenu ${r.verdict}, « ${causes(r)} »)`);
  ok(typeof r.motif === "string" && /AUDIT NON JOUÉ/.test(r.motif) && /pas un PASS/.test(r.motif) && /uv\.lock/.test(r.motif),
    `le SKIP porte un motif en une phrase qui dit « audit non joué » et nomme le manque (obtenu « ${r.motif} »)`);

  // TF-2398 : le remède d'un SKIP « outil absent » est une commande, épinglée à une version : un
  // « installer pip-audit » nu laisse l'humain deviner la commande et la version à poser.
  for (const cas of ["pip-clean", "uv-propre", "poetry-propre"]) {
    r = runJson(ORACLE_SCA, [FX("sca", cas)], rien);
    const remede = ((r.manques || [])[0] || {}).remede || "";
    ok(r.verdict === "SKIP" && /pip install pip-audit==\d+\.\d+\.\d+/.test(remede) && /uv tool install pip-audit==\d+\.\d+\.\d+/.test(remede) && /uvx/.test(remede),
      `${cas} sans pip-audit ni uvx → le remède du SKIP nomme les commandes d'installation épinglées (pip, uv) et la voie uvx (obtenu ${r.verdict}, « ${remede} »)`);
  }

  r = runJson(ORACLE_SCA, [FX("sca", "uv-propre")], { ...direct, WEBSEC_SIM_ECHEC: "1" });
  ok(r.verdict === "SKIP" && /indisponible/.test(causes(r)) && /base d'avisos injoignable/.test(causes(r)),
    `outil présent mais audit en échec → SKIP dont le manque cite la cause lue de l'outil (obtenu ${r.verdict}, « ${causes(r)} »)`);

  r = runJson(ORACLE_SCA, [FX("sca", "uv-vide")], viaUvx);
  ok(r.verdict === "SKIP" && /aucun paquet de registre reconnu/.test(causes(r)),
    `uv.lock où rien n'est reconnu → SKIP qui le nomme, jamais un PASS (obtenu ${r.verdict}, « ${causes(r)} »)`);

  r = runJson(ORACLE_SCA, [FX("sca", "aucun-manifeste")]);
  ok(r.verdict === "SKIP" && /uv\.lock/.test(causes(r)) && /poetry\.lock/.test(causes(r)) && typeof r.motif === "string",
    `dossier sans manifeste → SKIP dont le manque cite les quatre manifestes attendus et le motif est posé (obtenu « ${causes(r)} »)`);

  try { fs.rmSync(traceDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* nettoyage du banc : un verrou Windows passager n'est pas un échec de preuve */ }
}

// ── verrous avec l'outil RÉEL du poste (pip-audit, sinon uvx) et le réseau ───────
{
  if (!pipVoie) {
    skipNote(`ni pip-audit ni uvx sur le poste — sens rouge SCA-PIP sur uv.lock / poetry.lock non démontré avec l'outil réel ; pour le jouer : ${remedePipAbsent()}`);
  } else {
    for (const cas of ["uv-vulnerable", "poetry-vulnerable"]) {
      const r = runJson(ORACLE_SCA, [FX("sca", cas)]);
      if (r.verdict === "SKIP") skipNote(`${cas} : audit indisponible avec l'outil réel (probable absence réseau) — sens rouge non démontré cette exécution : ${r.motif}`);
      else ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP"), `${cas} (django 1.4) → FAIL avec SCA-PIP, outil réel « ${r.synthese && r.synthese.pip && r.synthese.pip.outil} » (obtenu ${r.verdict})`);
    }
    // la voie uvx RÉELLE : pip-audit déclaré absent (chemin injouable), uvx du poste lancé pour de bon
    if (uvxDispo) {
      const r = runJson(ORACLE_SCA, [FX("sca", "uv-vulnerable")], { WEBSEC_SCA_PIP_AUDIT: path.join(os.tmpdir(), "websec-outil-absent") });
      if (r.verdict === "SKIP") skipNote(`uvx réel : audit indisponible (probable absence réseau) — voie uvx non démontrée avec l'outil réel cette exécution : ${r.motif}`);
      else ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP") && r.synthese.pip.outil === "uvx pip-audit", `uv-vulnerable, pip-audit absent, VRAI uvx du poste → FAIL avec SCA-PIP via « uvx pip-audit » (obtenu ${r.verdict}, ${r.synthese && r.synthese.pip && r.synthese.pip.outil})`);
    } else {
      skipNote("uvx absent du poste — voie uvx non démontrable avec l'outil réel (démontrée avec l'outil simulé)");
    }
  }
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

// ── TF-2444 · mode actif réel et options de balayage portées par l'autorisation ─────────────────
// Un ZAP SIMULÉ (fixtures/dast/zap-simule.mjs, copié sous les noms des vraies commandes) enregistre la
// ligne de commande qu'oracle-dast lui passe, sans rien émettre vers aucune cible. Chaque cas force
// WEBSEC_DAST_ZAP sur ce ZAP simulé : aucun ne peut atteindre le vrai ZAP ni Docker. La preuve avec le vrai
// ZAP, contre une cible de fixture locale, est scripts/preuve-dast-actif.mjs (hors self-test).
{
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "websec-dast-"));
  const simule = (nom) => { const f = path.join(dossier, `${nom}.mjs`); fs.copyFileSync(AUTZ("zap-simule.mjs"), f); return f; };
  const ZAP = { baseline: simule("zap-baseline"), complet: simule("zap-full-scan"), rapide: simule("zap"), inconnu: simule("zap-mystere") };
  const trace = path.join(dossier, "trace.jsonl");
  // Valeur d'en-tête fictive assemblée à l'exécution (espace et apostrophe : elle éprouve la citation).
  const ACCES = ["Bearer", ["fixture", "non", "secret"].join("-")].join(" ") + " a'b";
  const lancer = (zap, autz, mode, env) => {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", autz, "--mode", mode], {
      WEBSEC_DAST_ZAP: zap, WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"),
      WEBSEC_DAST_TEST_ACCES: ACCES, ...(env || {}),
    });
    const lignes = fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
    return { r, lignes };
  };
  const optionsZ = (lignes) => { const a = (lignes[0] && lignes[0].argv) || []; const i = a.indexOf("-z"); return i >= 0 ? a[i + 1] : ""; };
  const msgs = (r) => (r.findings || []).map((f) => f.msg).join(" ");

  // sens VERT : chaque mode lance SA passe, une seule fois
  {
    const { r, lignes } = lancer(ZAP.baseline, AUTZ("autorisation-valide.json"), "passif");
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === "zap-baseline.mjs" && r.synthese.balayage.scan === "passif" && !lignes[0].argv.includes("-z"),
      `mode passif → la passe baseline, une fois, sans option (obtenu ${r.verdict}, ${lignes.map((l) => l.script).join(",")})`);
  }
  {
    const { r, lignes } = lancer(ZAP.complet, AUTZ("autorisation-actif.json"), "actif");
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === "zap-full-scan.mjs" && r.synthese.balayage.scan === "actif" && r.synthese.balayage.forme === "complet" && lignes[0].argv.includes("-t") && !lignes[0].argv.includes("-z"),
      `mode actif autorisé → le balayage complet (zap-full-scan), une fois, jamais baseline (obtenu ${r.verdict}, ${lignes.map((l) => l.script).join(",")})`);
  }
  {
    const { r, lignes } = lancer(ZAP.rapide, AUTZ("autorisation-actif.json"), "actif");
    const a = (lignes[0] && lignes[0].argv) || [];
    ok(r.verdict === "PASS" && lignes.length === 1 && a.includes("-quickurl") && a[a.indexOf("-quickurl") + 1] === CIBLE_OK,
      `mode actif avec un ZAP natif de forme rapide (zap.sh) → son balayage rapide, qui attaque (obtenu ${r.verdict})`);
  }
  // sens ROUGE : un mode ne se rabat jamais sur l'autre, et rien n'est lancé
  {
    const { r, lignes } = lancer(ZAP.baseline, AUTZ("autorisation-actif.json"), "actif");
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-ACTIF-IMPOSSIBLE") && lignes.length === 0, `mode actif avec un ZAP baseline seul → SKIP DAST-ACTIF-IMPOSSIBLE, aucune passe passive sous le nom d'actif (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const { r, lignes } = lancer(ZAP.inconnu, AUTZ("autorisation-actif.json"), "actif");
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-ACTIF-IMPOSSIBLE") && lignes.length === 0, `mode actif avec un script de nom inconnu → SKIP DAST-ACTIF-IMPOSSIBLE, l'oracle ne sait pas qu'il attaque (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const { r, lignes } = lancer(ZAP.complet, AUTZ("autorisation-valide.json"), "passif");
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-PASSIF-IMPOSSIBLE") && lignes.length === 0, `mode passif avec un ZAP de balayage complet → SKIP DAST-PASSIF-IMPOSSIBLE, aucune attaque sous le nom de passif (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const { r, lignes } = lancer(ZAP.rapide, AUTZ("autorisation-valide.json"), "passif");
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-PASSIF-IMPOSSIBLE") && lignes.length === 0, `mode passif avec zap.sh (balayage rapide, qui attaque) → SKIP DAST-PASSIF-IMPOSSIBLE (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const { r, lignes } = lancer(ZAP.complet, AUTZ("autorisation-valide.json"), "actif");
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-MODE") && lignes.length === 0, `mode actif sans actif_autorise, même avec le bon ZAP → FAIL DAST-AUTZ-MODE, aucun lancement (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }

  // options : en-tête d'accès, débit, exclusions — sens VERT
  const dedans = (z, morceau) => z.includes(morceau);
  {
    const { r, lignes } = lancer(ZAP.complet, AUTZ("autorisation-actif-options.json"), "actif");
    const z = optionsZ(lignes);
    ok(r.verdict === "PASS" && dedans(z, "replacer.full_list(0).matchtype=REQ_HEADER") && dedans(z, "replacer.full_list(0).matchstr=Authorization")
      && dedans(z, `'replacer.full_list(0).replacement=${ACCES.replace(/'/g, "'\\''")}'`) && dedans(z, "replacer.full_list(0).url=^https://recette\\.exemple\\.tld(/.*)?$"),
      `en_tete_acces (valeur_env) → règle de remplacement d'en-tête bornée à l'origine autorisée, valeur citée pour shlex (obtenu ${r.verdict})`);
    ok(dedans(z, "scanner.threadPerHost=1") && dedans(z, "scanner.delayInMs=200") && dedans(z, "spider.thread=1") && dedans(z, "spider.requestwait=200"),
      "debit_max_requetes_par_seconde: 5 → un fil et 200 ms entre deux requêtes, pour l'araignée comme pour l'attaque");
    ok(dedans(z, "globalexcludeurl.url_list.url(0).regex=^https://recette\\.exemple\\.tld/deconnexion.*") && dedans(z, "globalexcludeurl.url_list.url(1).regex=^https://recette\\.exemple\\.tld/admin/supprimer.*"),
      "exclusions → une exclusion globale par chemin, ancrée sur l'origine autorisée");
    const sortie = JSON.stringify(r);
    ok(!sortie.includes(ACCES) && !sortie.includes("fixture-non-secret") && r.synthese.balayage.en_tete_acces.nom === "Authorization" && r.synthese.balayage.en_tete_acces.valeur === "(masquée)",
      "la valeur de l'en-tête n'apparaît nulle part dans le verdict : son nom et « (masquée) » seulement");
  }
  {
    const f = path.join(dossier, "autorisation-valeur.json");
    const base = JSON.parse(fs.readFileSync(AUTZ("autorisation-actif-options.json"), "utf8"));
    fs.writeFileSync(f, JSON.stringify({ ...base, en_tete_acces: { nom: "X-Acces", valeur: ACCES } }));
    const { r, lignes } = lancer(ZAP.complet, f, "actif", { WEBSEC_DAST_TEST_ACCES: "" });
    ok(r.verdict === "PASS" && dedans(optionsZ(lignes), "replacer.full_list(0).matchstr=X-Acces") && !JSON.stringify(r).includes("fixture-non-secret"),
      `en_tete_acces avec « valeur » littérale → appliqué, jamais repris dans le verdict (obtenu ${r.verdict})`);
  }
  {
    const { r, lignes } = lancer(ZAP.baseline, AUTZ("autorisation-actif-options.json"), "passif");
    const z = optionsZ(lignes);
    ok(r.verdict === "PASS" && lignes[0].script === "zap-baseline.mjs" && dedans(z, "globalexcludeurl.url_list.url(0).regex=") && dedans(z, "scanner.delayInMs=200") && dedans(z, "replacer.full_list(0).matchstr=Authorization"),
      `les options valent aussi en passif : la passe baseline reçoit exclusions, débit et en-tête (obtenu ${r.verdict})`);
  }

  // options mal formées — sens ROUGE : FAIL DAST-AUTZ-CHAMPS qui nomme le champ, rien n'est lancé
  const valide = JSON.parse(fs.readFileSync(AUTZ("autorisation-actif-options.json"), "utf8"));
  const rouges = [
    ["débit à 0", { debit_max_requetes_par_seconde: 0 }, "debit_max_requetes_par_seconde"],
    ["débit négatif", { debit_max_requetes_par_seconde: -3 }, "debit_max_requetes_par_seconde"],
    ["débit en texte", { debit_max_requetes_par_seconde: "5" }, "debit_max_requetes_par_seconde"],
    ["débit au-delà de 1000", { debit_max_requetes_par_seconde: 5000 }, "debit_max_requetes_par_seconde"],
    ["exclusion sans « / » initial", { exclusions: ["deconnexion"] }, "exclusions"],
    ["exclusion avec espace", { exclusions: ["/a b"] }, "exclusions"],
    ["exclusions qui n'est pas une liste", { exclusions: "/deconnexion" }, "exclusions"],
    ["nom d'en-tête avec espace", { en_tete_acces: { nom: "X Mauvais", valeur_env: "WEBSEC_DAST_TEST_ACCES" } }, "en_tete_acces.nom"],
    ["en-tête sans nom", { en_tete_acces: { valeur_env: "WEBSEC_DAST_TEST_ACCES" } }, "en_tete_acces.nom"],
    ["en-tête avec valeur ET valeur_env", { en_tete_acces: { nom: "Authorization", valeur: "x", valeur_env: "WEBSEC_DAST_TEST_ACCES" } }, "exactement un"],
    ["en-tête sans valeur", { en_tete_acces: { nom: "Authorization" } }, "exactement un"],
    ["valeur d'en-tête avec saut de ligne", { en_tete_acces: { nom: "Authorization", valeur: "a\nb" } }, "caractère de contrôle"],
  ];
  for (const [libelle, variante, motif] of rouges) {
    const f = path.join(dossier, "autorisation-rouge.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, ...variante }));
    const { r, lignes } = lancer(ZAP.complet, f, "actif");
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-CHAMPS") && msgs(r).includes(motif) && lignes.length === 0,
      `${libelle} → FAIL DAST-AUTZ-CHAMPS qui cite « ${motif} », rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const { r, lignes } = lancer(ZAP.complet, AUTZ("autorisation-actif-options.json"), "actif", { WEBSEC_DAST_TEST_ACCES: "" });
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-CHAMPS") && msgs(r).includes("WEBSEC_DAST_TEST_ACCES") && lignes.length === 0,
      `en-tête annoncé mais variable absente → FAIL, jamais un balayage sans son en-tête (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const f = path.join(dossier, "autorisation-debit-0.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, debit_max_requetes_par_seconde: 0 }));
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", f, "--rapport", AUTZ("rapport-zap-propre.json")]);
    ok(r.verdict === "PASS", `voie --rapport : rien n'est émis, les options de balayage ne sont pas lues (obtenu ${r.verdict})`);
  }
  fs.rmSync(dossier, { recursive: true, force: true });
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

// ── TF-2107 · la capture ne garde AUCUN autre porteur de jeton (même classe que TF-2095) ──────────
// Après la valeur des cookies posés, restent l'URL capturée, Location, Authorization, Proxy-Authorization,
// Cookie et les paramètres d'URL de forme jeton. Le banc sert une réponse 302 d'une origine locale qui porte
// chaque porteur avec un secret reconnaissable, lance le VRAI capturer.mjs contre une URL à jetons, puis juge :
// ROUGE si un secret survit dans le fichier, la sortie standard ou les messages ; VERT si la capture reste
// exploitable (statut, schéma, paramètres sans jeton, autres en-têtes) et que oracle-exposition la juge encore.
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2107 : URL, Location, Authorization, Cookie caviardés à la capture)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const PORTEURS = {
    "URL capturée": ["SECRET-ACCESS-91f0", "SECRET-APIKEY-7777", "SECRET-SIGNATURE-d4d4", "SECRET-SESSION-0b0b"],
    "Location": ["SECRET-CODE-3b7e", "SECRET-IDTOKEN-aa19", "SECRET-JSESSION-5e5e", "SECRET-USERINFO-pw"],
    "Authorization": ["SECRET-AUTHORIZATION-71c4"],
    "Proxy-Authorization": ["SECRET-PROXY-c0ffee12"],
    "Cookie": ["SECRET-COOKIE-REQ-5d2b", "SECRET-COOKIE-PREF-88aa"],
    "Set-Cookie": ["SECRET-SETCOOKIE-1a2b"],
  };
  const TOUS = Object.values(PORTEURS).flat();
  const origine = http.createServer((req, res) => {
    res.statusCode = 302;
    res.setHeader("Location", "https://SECRET-USERINFO-pw@sso.exemple.test/callback;jsessionid=SECRET-JSESSION-5e5e?code=SECRET-CODE-3b7e&state=ok&lang=fr#id_token=SECRET-IDTOKEN-aa19&token_type=Bearer");
    res.setHeader("Authorization", "Bearer SECRET-AUTHORIZATION-71c4");
    res.setHeader("Proxy-Authorization", "Basic SECRET-PROXY-c0ffee12");
    res.setHeader("Cookie", "sid=SECRET-COOKIE-REQ-5d2b; pref=SECRET-COOKIE-PREF-88aa");
    res.setHeader("Set-Cookie", "session=SECRET-SETCOOKIE-1a2b; Path=/; HttpOnly");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.end("");
  });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${origine.address().port}/`;
  const urlJetons = `${base}?access_token=SECRET-ACCESS-91f0&apikey=SECRET-APIKEY-7777&signature=SECRET-SIGNATURE-d4d4&session=SECRET-SESSION-0b0b&page=2`;
  const urlAttendue = `${base}?access_token=[caviardé]&apikey=[caviardé]&signature=[caviardé]&session=[caviardé]&page=[caviardé]`;
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-jetons-"));
  const lancer = (cible, args) => new Promise((resolve) => execFile(process.execPath, [CAPTURER, cible, ...args], { encoding: "utf8", timeout: 30000 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
  try {
    const fichier = path.join(tmpCap, "capture.json");
    const viaFichier = await lancer(urlJetons, ["--sortie", fichier]);
    const brut = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : "";
    const viaStdout = await lancer(urlJetons, []);
    ok(viaFichier.code === 0 && viaStdout.code === 0 && brut.length > 0,
      `capturer.mjs capture l'origine locale à jetons (302, redirection non suivie), par fichier et par sortie standard (codes ${viaFichier.code} / ${viaStdout.code})`);
    // ROUGE : par porteur, aucun secret ne survit ni dans le fichier, ni sur la sortie standard, ni dans les messages.
    const sortie = brut + viaStdout.stdout + viaFichier.stderr + viaStdout.stderr;
    for (const [porteur, secrets] of Object.entries(PORTEURS)) {
      const survivants = secrets.filter((s) => sortie.includes(s));
      ok(survivants.length === 0, `ROUGE · porteur « ${porteur} » caviardé à la capture (secrets survivants : ${survivants.length}/${secrets.length})`);
    }
    // VERT : la capture reste exploitable, seules les valeurs de jeton sont remplacées.
    let cap = null;
    try { cap = JSON.parse(brut); } catch { /* les contrôles suivants le disent */ }
    const h = cap?.headers ?? {};
    ok(cap?.url === urlAttendue,
      `VERT · l'URL capturée garde schéma, hôte, chemin et les NOMS de ses paramètres ; la valeur de chacun, page comprise, est remplacée par position (TF-2390) (obtenu ${cap?.url})`);
    ok(h.location === "https://[caviardé]@sso.exemple.test/callback;jsessionid=[caviardé]?code=[caviardé]&state=[caviardé]&lang=[caviardé]#id_token=[caviardé]&token_type=[caviardé]",
      `VERT · Location garde sa forme (schéma, hôte, chemin, NOMS des paramètres) ; l'identifiant, jsessionid et la valeur de chaque paramètre sont remplacés par position (TF-2306) (obtenu ${h.location})`);
    ok(h.authorization === "Bearer [caviardé]" && h["proxy-authorization"] === "Basic [caviardé]",
      "VERT · Authorization et Proxy-Authorization gardent le schéma (Bearer, Basic), les justificatifs sont remplacés");
    ok(h.cookie === "sid=[caviardé]; pref=[caviardé]" && Array.isArray(h["set-cookie"]) && h["set-cookie"][0] === "session=[caviardé]; Path=/; HttpOnly",
      "VERT · Cookie garde les noms de ses paires ; Set-Cookie garde nom et attributs (TF-2095 inchangé)");
    ok(cap?.status === 302 && h["x-content-type-options"] === "nosniff" && cap?.redirections_suivies === false,
      "VERT · le reste de la capture (statut, autre en-tête, drapeau de redirection) est intact");
    // Exploitable : oracle-exposition juge cette capture (EX-1, pas de CSP) et ne recopie aucun secret.
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    ok(jug.verdict === "FAIL" && aRegle(jug, "EX-1") && !TOUS.some((s) => JSON.stringify(jug).includes(s)),
      `VERT · la capture caviardée reste exploitable : oracle-exposition la juge (EX-1) sans recopier de secret (obtenu ${jug.verdict})`);
    // Un échec de capture ne réécrit pas l'URL à jetons sur la sortie d'erreur.
    const libre = http.createServer(); await new Promise((r) => libre.listen(0, "127.0.0.1", r));
    const portMort = libre.address().port; await new Promise((r) => libre.close(r));
    const echec = await lancer(`http://127.0.0.1:${portMort}/?access_token=SECRET-ECHEC-e3e3&page=2`, []);
    ok(echec.code === 1 && /capture échouée/.test(echec.stderr) && !echec.stderr.includes("SECRET-ECHEC-e3e3") && echec.stderr.includes("?access_token=[caviardé]&page=[caviardé]"),
      `ROUGE · le message d'échec ne recopie pas le jeton de l'URL demandée, l'URL reste reconnaissable par son hôte, son chemin et les noms de ses paramètres (code ${echec.code})`);
    // Bords du caviardage : URL relative, fragment-route, nom encodé, casse, paramètre sans valeur, idempotence.
    const { caviarderUrl, caviarderAutorisation, caviarderCookieRequete, caviarderEnTetes } =
      await import(pathToFileURL(path.join(HERE, "..", "scripts", "caviarder-jetons.mjs")).href);
    const bordsUrl = [
      ["/relatif?Access_Token=1&x=2", "/relatif?Access_Token=[caviardé]&x=2"],
      ["https://h.test/#/cb?token=9&a=1", "https://h.test/#/cb?token=[caviardé]&a=1"],
      ["https://h.test/p?api%5Fkey=9&x-api-key=8&X-Amz-Signature=7&Sig=6", "https://h.test/p?api%5Fkey=[caviardé]&x-api-key=[caviardé]&X-Amz-Signature=[caviardé]&Sig=[caviardé]"],
      ["https://h.test/p?token=&k&jwt=a=b", "https://h.test/p?token=[caviardé]&k&jwt=[caviardé]"],
      ["https://h.test/p?token_type=x&state=y&lang=fr&page=3&sortkey=", "https://h.test/p?token_type=[caviardé]&state=y&lang=fr&page=3&sortkey=[caviardé]"], // TF-2394 : token_type contient « token », masqué par le motif (attente durcie, aucune relâchée)
      ["https://h.test/p/a?x=1", "https://h.test/p/a?x=1"],
      ["", ""],
    ];
    const ecartsUrl = bordsUrl.filter(([e, s]) => caviarderUrl(e) !== s || caviarderUrl(caviarderUrl(e)) !== s).map(([e]) => e);
    ok(ecartsUrl.length === 0, `bords du caviardage d'URL : relative, fragment-route, nom encodé, casse, sans valeur, sans jeton, vide, idempotent (écarts : ${ecartsUrl.length}${ecartsUrl.length ? " · " + ecartsUrl[0] : ""})`);
    const bordsAuth = [["Bearer abc.def", "Bearer [caviardé]"], ["abc", "[caviardé]"], [' Basic  Zm9v ', "Basic [caviardé]"], ['Digest username="a", response="x"', "Digest [caviardé]"]];
    const ecartsAuth = bordsAuth.filter(([e, s]) => caviarderAutorisation(e) !== s).map(([e]) => e);
    const cookieOk = caviarderCookieRequete("a=b; c=d=e;") === "a=[caviardé]; c=[caviardé]" && caviarderCookieRequete(["x=1"])[0] === "x=[caviardé]";
    const enTetes = caviarderEnTetes({ Authorization: "Bearer zz", LOCATION: "/x?code=1", "X-Autre": "garde?code=1", "Set-Cookie": ["s=1; Secure"] });
    const enTetesOk = enTetes.Authorization === "Bearer [caviardé]" && enTetes.LOCATION === "/x?code=[caviardé]"
      && enTetes["X-Autre"] === "garde?code=1" && enTetes["Set-Cookie"][0] === "s=[caviardé]; Secure";
    ok(ecartsAuth.length === 0 && cookieOk && enTetesOk,
      `bords des en-têtes : schéma d'Authorization gardé, justificatif nu, paires de Cookie, noms d'en-tête sans casse, en-tête hors liste intact (écarts : ${ecartsAuth.length}, Cookie ${cookieOk}, en-têtes ${enTetesOk})`);
  } finally {
    origine.close();
    fs.rmSync(tmpCap, { recursive: true, force: true });
  }
}

// ── TF-2133 · cinq en-têtes de plus et l'URL imbriquée (même classe que TF-2107) ──────────────────
// Content-Location, Link, Refresh, X-Auth-Token et WWW-Authenticate peuvent porter une URL à jeton ou un jeton ;
// un jeton caché dans un paramètre encodé (redirect_uri=…%3Fcode%3D…) ne se voit pas au nom d'en-tête.
// Le banc sert une réponse 302 qui porte chaque cas avec un secret reconnaissable, lance le VRAI capturer.mjs, puis
// juge dans les deux sens : ROUGE si un secret survit ; VERT si ce qui n'est pas un jeton sort octet pour octet.
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2133 : Content-Location, Link, Refresh, X-Auth-Token, WWW-Authenticate, URL encodée)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const PORTEURS = {
    "Content-Location": ["SECRET-CLOC-1a1a"],
    "Link": ["SECRET-LINK-2b2b"],
    "Refresh": ["SECRET-REFRESH-3c3c"],
    "X-Auth-Token": ["SECRET-XAUTH-4d4d"],
    "WWW-Authenticate": ["SECRET-WWWURL-5e5e", "SECRET-NEGOTIATE-6f6f", "SECRET-NONCE-7a7a"],
    "Location (redirect_uri encodé)": ["SECRET-NESTED-LOC-8b8b"],
    "URL capturée (redirect_uri encodé)": ["SECRET-NESTED-URL-9c9c"],
  };
  const TOUS = Object.values(PORTEURS).flat();
  const origine = http.createServer((req, res) => {
    res.statusCode = 302;
    res.setHeader("Location", "https://sso.exemple.test/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.exemple.test%2Fcb%3Fcode%3DSECRET-NESTED-LOC-8b8b%26state%3Dok&lang=fr");
    res.setHeader("Content-Location", "/v2/doc?access_token=SECRET-CLOC-1a1a&page=1");
    res.setHeader("Link", '<https://api.exemple.test/p2?token=SECRET-LINK-2b2b&page=2>; rel="next", <https://api.exemple.test/p1?page=1>; rel="prev"');
    res.setHeader("Refresh", "0; url=https://sso.exemple.test/r?code=SECRET-REFRESH-3c3c&lang=fr");
    res.setHeader("X-Auth-Token", "SECRET-XAUTH-4d4d");
    res.setHeader("WWW-Authenticate", [
      'Bearer realm="api", error="invalid_token", resource_metadata="https://api.exemple.test/.well-known/m?access_token=SECRET-WWWURL-5e5e"',
      "Negotiate SECRET-NEGOTIATE-6f6f",
      'Digest realm="api", nonce="SECRET-NONCE-7a7a", qop="auth"',
    ]);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.end("");
  });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${origine.address().port}/`;
  const urlImbriquee = `${base}?redirect_uri=https%3A%2F%2Fapp.exemple.test%2Fcb%3Fcode%3DSECRET-NESTED-URL-9c9c%26state%3Dok&page=2`;
  const urlAttendue = `${base}?redirect_uri=[caviardé]&page=[caviardé]`;
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-entetes-"));
  const lancer = (cible, args) => new Promise((resolve) => execFile(process.execPath, [CAPTURER, cible, ...args], { encoding: "utf8", timeout: 30000 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
  try {
    const fichier = path.join(tmpCap, "capture.json");
    const viaFichier = await lancer(urlImbriquee, ["--sortie", fichier]);
    const brut = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : "";
    const viaStdout = await lancer(urlImbriquee, []);
    ok(viaFichier.code === 0 && viaStdout.code === 0 && brut.length > 0,
      `capturer.mjs capture l'origine locale aux cinq en-têtes à jeton et à l'URL encodée, par fichier et par sortie standard (codes ${viaFichier.code} / ${viaStdout.code})`);
    // ROUGE : par porteur, aucun secret ne survit ni dans le fichier, ni sur la sortie standard, ni dans les messages.
    const sortie = brut + viaStdout.stdout + viaFichier.stderr + viaStdout.stderr;
    for (const [porteur, secrets] of Object.entries(PORTEURS)) {
      const survivants = secrets.filter((s) => sortie.includes(s));
      ok(survivants.length === 0, `ROUGE · porteur « ${porteur} » caviardé à la capture (secrets survivants : ${survivants.length}/${secrets.length})`);
    }
    // VERT : la capture reste exploitable, seules les valeurs de jeton sont remplacées.
    let cap = null;
    try { cap = JSON.parse(brut); } catch { /* les contrôles suivants le disent */ }
    const h = cap?.headers ?? {};
    ok(h["content-location"] === "/v2/doc?access_token=[caviardé]&page=[caviardé]",
      `VERT · Content-Location garde le chemin et les noms access_token et page, leurs valeurs sont remplacées (obtenu ${h["content-location"]})`);
    ok(h.link === '<https://api.exemple.test/p2?token=[caviardé]&page=[caviardé]>; rel="next", <https://api.exemple.test/p1?page=[caviardé]>; rel="prev"',
      `VERT · Link garde ses deux liens, ses rel, les chemins et les noms de paramètres ; chaque valeur est remplacée (obtenu ${h.link})`);
    ok(h.refresh === "0; url=https://sso.exemple.test/r?code=[caviardé]&lang=[caviardé]",
      `VERT · Refresh garde le délai, l'hôte, le chemin et les noms code et lang ; leurs valeurs sont remplacées (obtenu ${h.refresh})`);
    ok(h["x-auth-token"] === "[caviardé]", `VERT · X-Auth-Token est remplacé en entier (obtenu ${h["x-auth-token"]})`);
    ok(h["www-authenticate"] === 'Bearer realm="api", error="invalid_token", resource_metadata="https://api.exemple.test/.well-known/m?access_token=[caviardé]", Negotiate [caviardé], Digest realm="api", nonce="[caviardé]", qop="auth"',
      `VERT · WWW-Authenticate garde schémas, realm, error et qop ; l'URL à jeton, le jeton nu de Negotiate et le nonce sont remplacés (obtenu ${h["www-authenticate"]})`);
    ok(h.location === "https://sso.exemple.test/authorize?client_id=[caviardé]&redirect_uri=[caviardé]&lang=[caviardé]",
      `VERT · Location garde l'hôte, le chemin et les noms client_id, redirect_uri et lang ; le redirect_uri encodé et son code disparaissent avec la valeur (obtenu ${h.location})`);
    ok(cap?.url === urlAttendue, `VERT · l'URL capturée garde les noms redirect_uri et page ; le redirect_uri encodé disparaît en entier avec son code, page aussi est remplacé (TF-2390) (obtenu ${cap?.url})`);
    ok(cap?.status === 302 && h["x-content-type-options"] === "nosniff" && cap?.redirections_suivies === false,
      "VERT · le reste de la capture (statut, autre en-tête, drapeau de redirection) est intact");
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    ok(jug.verdict === "FAIL" && aRegle(jug, "EX-1") && !TOUS.some((s) => JSON.stringify(jug).includes(s)),
      `VERT · la capture caviardée reste exploitable : oracle-exposition la juge (EX-1) sans recopier de secret (obtenu ${jug.verdict})`);
    // Bords du caviardage, sur les fonctions : URL imbriquée (simple, double, liste, non encodée), sans jeton, tableau, casse, idempotence.
    const { caviarderUrl, caviarderEnTetes } = await import(pathToFileURL(path.join(HERE, "..", "scripts", "caviarder-jetons.mjs")).href);
    const bordsUrl = [
      ["https://h.test/p?r=https%253A%252F%252Fa.test%252Fcb%253Fcode%253DSEC", "https://h.test/p?r=https%253A%252F%252Fa.test%252Fcb%253Fcode%253D[caviardé]"],
      ["https://h.test/p?state=code%3DSEC%26x%3D1", "https://h.test/p?state=code%3D[caviardé]%26x%3D1"],
      ["https://h.test/p?next=https://a.test/b?token=SEC&x=1", "https://h.test/p?next=https://a.test/b?token=[caviardé]&x=1"],
      ["https://h.test/p?next=%2Fcompte%3Fapi_key%3DSEC%23frag", "https://h.test/p?next=%2Fcompte%3Fapi_key%3D[caviardé]%23frag"],
      ["https://h.test/p?redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Fstate%3Dok%26lang%3Dfr&q=%C3%A9t%C3%A9", "https://h.test/p?redirect_uri=https%3A%2F%2Fapp.test%2Fcb%3Fstate%3Dok%26lang%3Dfr&q=%C3%A9t%C3%A9"],
      ["https://h.test/p?redirect=/accueil?page=2&b64=YWJjZGVmZw==&mauvais=%E0%A4%A&t=a%2Bb", "https://h.test/p?redirect=/accueil?page=2&b64=YWJjZGVmZw==&mauvais=%E0%A4%A&t=a%2Bb"],
    ];
    const ecartsUrl = bordsUrl.filter(([e, s]) => caviarderUrl(e) !== s || caviarderUrl(caviarderUrl(e)) !== s).map(([e, s]) => `${e} → ${caviarderUrl(e)} (attendu ${s})`);
    ok(ecartsUrl.length === 0, `bords de l'URL imbriquée : double encodage, liste encodée, non encodée, chemin relatif, URL sans jeton intacte, idempotent (écarts : ${ecartsUrl.length}${ecartsUrl.length ? " · " + ecartsUrl[0] : ""})`);
    const e2 = caviarderEnTetes({
      "CONTENT-LOCATION": "/a?code=1", Link: ["<https://h.test/n?sig=1>; rel=next"], REFRESH: "5", "x-auth-token": ["t1", "t2"],
      "WWW-Authenticate": 'Basic realm="zone"', "Www-Authenticate": 'Bearer error="invalid_token", error_description="expired"',
    });
    const sansJeton = caviarderEnTetes({
      Link: '<https://h.test/n?page=2>; rel="next"; anchor="https://h.test/a"', Refresh: "3; URL='https://h.test/ok?lang=fr'",
      "Content-Location": "/doc/12", "WWW-Authenticate": 'Bearer realm="api", scope="read write"',
    });
    const enTetesOk = e2["CONTENT-LOCATION"] === "/a?code=[caviardé]" && e2.Link[0] === "<https://h.test/n?sig=[caviardé]>; rel=next"
      && e2.REFRESH === "5" && e2["x-auth-token"].join() === "[caviardé],[caviardé]" && e2["WWW-Authenticate"] === 'Basic realm="zone"'
      && e2["Www-Authenticate"] === 'Bearer error="invalid_token", error_description="expired"'
      && sansJeton.Link === '<https://h.test/n?page=[caviardé]>; rel="next"; anchor="https://h.test/a"' && sansJeton.Refresh === "3; URL='https://h.test/ok?lang=[caviardé]'"
      && sansJeton["Content-Location"] === "/doc/12" && sansJeton["WWW-Authenticate"] === 'Bearer realm="api", scope="read write"';
    ok(enTetesOk, `bords des en-têtes : noms sans casse, valeurs en tableau, Refresh sans URL, défi sans jeton et en-têtes sans jeton intacts (${enTetesOk ? "tous tenus" : JSON.stringify([e2, sansJeton])})`);
  } finally {
    origine.close();
    fs.rmSync(tmpCap, { recursive: true, force: true });
  }
}

// ── TF-2306 · tout paramètre de requête d'une URL d'en-tête est caviardé PAR POSITION ─────────────
// Troisième passe sur la même classe (TF-2107, TF-2133 : caviardage par FORME du nom). Une redirection Cloudflare
// Access porte son jeton dans `meta` (JWT de 684 caractères) et Report-To sa signature dans `s` : aucun de ces noms
// n'est « de forme jeton ». Le banc sert une réponse 302 qui porte ces deux en-têtes et trois autres porteurs d'URL
// aux paramètres de nom ordinaire, lance le VRAI capturer.mjs, puis juge dans les deux sens : ROUGE si une valeur
// survit ; VERT si schéma, hôte, chemin et NOMS des paramètres restent lisibles. Les faux jetons sont ASSEMBLÉS À
// L'EXÉCUTION : aucun jeton de test en clair dans le source (la protection des secrets de l'hébergeur le refuse).
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2306 : toute valeur de paramètre d'une URL d'en-tête caviardée par position)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const b64 = (o) => Buffer.from(typeof o === "string" || Buffer.isBuffer(o) ? o : JSON.stringify(o)).toString("base64url");
  const enteteJwt = b64({ alg: "RS256", typ: "JWT", kid: "cle-de-test" });
  const signatureJwt = b64(Buffer.from(Array.from({ length: 256 }, (_, i) => (i * 7 + 13) % 256)));
  let charge = "";
  for (let n = 0; enteteJwt.length + charge.length + signatureJwt.length + 2 < 684; n++) {
    charge = b64({ aud: "app.exemple.test", marque: "SECRET-META-3f9a", bourrage: "x".repeat(n) });
  }
  const jetonMeta = `${enteteJwt}.${charge}.${signatureJwt}`;
  const signatureRapport = b64("SECRET-REPORTTO-" + "8c1d".repeat(8));
  const valeurCurseur = b64("SECRET-CURSEUR-" + "5a".repeat(10));
  const valeurContexte = b64("SECRET-CONTEXTE-" + "9b".repeat(10));
  const valeurRapports = b64("SECRET-RAPPORTS-" + "2e".repeat(10));
  const PORTEURS = {
    "Location (Cloudflare Access, paramètre meta)": [jetonMeta, charge, signatureJwt],
    "Report-To (signature du point de terminaison)": [signatureRapport],
    "Link (paramètre de nom ordinaire)": [valeurCurseur],
    "Content-Security-Policy (report-uri)": [valeurContexte],
    "Reporting-Endpoints": [valeurRapports],
  };
  const TOUS = Object.values(PORTEURS).flat();
  const origine = http.createServer((req, res) => {
    res.statusCode = 302;
    res.setHeader("Location", `https://equipe.exemple.test/cdn-cgi/access/login/app.exemple.test?kid=cle-acces-id&meta=${jetonMeta}&redirect_url=%2Faccueil`);
    res.setHeader("Report-To", `{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=${signatureRapport}"}]}`);
    res.setHeader("NEL", '{"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}');
    res.setHeader("Link", `<https://api.exemple.test/liste?curseur=${valeurCurseur}&page=2>; rel="next"`);
    res.setHeader("Content-Security-Policy", `default-src 'self'; report-uri https://rapports.exemple.test/csp?ctx=${valeurContexte}; frame-ancestors 'none'`);
    res.setHeader("Reporting-Endpoints", `default="https://rapports.exemple.test/r?ref=${valeurRapports}"`);
    res.setHeader("Access-Control-Allow-Origin", "https://app.exemple.test");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.end("");
  });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${origine.address().port}/`;
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-position-"));
  const lancer = (cible, args) => new Promise((resolve) => execFile(process.execPath, [CAPTURER, cible, ...args], { encoding: "utf8", timeout: 30000 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
  try {
    ok(jetonMeta.length >= 684 && /^[\w-]+\.[\w-]+\.[\w-]+$/.test(jetonMeta),
      `le faux jeton meta est un JWT assemblé à l'exécution de ${jetonMeta.length} caractères (en-tête.charge.signature), jamais écrit dans le source`);
    const fichier = path.join(tmpCap, "capture.json");
    const viaFichier = await lancer(base, ["--sortie", fichier]);
    const brut = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : "";
    const viaStdout = await lancer(base, []);
    ok(viaFichier.code === 0 && viaStdout.code === 0 && brut.length > 0,
      `capturer.mjs capture l'origine locale à redirection d'accès, par fichier et par sortie standard (codes ${viaFichier.code} / ${viaStdout.code})`);
    // ROUGE : par porteur, aucune valeur ne survit ni dans le fichier, ni sur la sortie standard, ni dans les messages.
    const sortie = brut + viaStdout.stdout + viaFichier.stderr + viaStdout.stderr;
    for (const [porteur, secrets] of Object.entries(PORTEURS)) {
      const survivants = secrets.filter((s) => sortie.includes(s));
      ok(survivants.length === 0, `ROUGE · porteur « ${porteur} » caviardé à la capture (valeurs survivantes : ${survivants.length}/${secrets.length})`);
    }
    // VERT : schéma, hôte, chemin et NOMS des paramètres restent lisibles ; seules les valeurs sont remplacées.
    let cap = null;
    try { cap = JSON.parse(brut); } catch { /* les contrôles suivants le disent */ }
    const h = cap?.headers ?? {};
    ok(h.location === "https://equipe.exemple.test/cdn-cgi/access/login/app.exemple.test?kid=[caviardé]&meta=[caviardé]&redirect_url=[caviardé]",
      `VERT · Location garde schéma, hôte, chemin et les noms kid, meta, redirect_url ; chaque valeur est remplacée (obtenu ${h.location})`);
    ok(h["report-to"] === '{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=[caviardé]"}]}',
      `VERT · Report-To garde son JSON, l'hôte, le chemin et le nom s ; la signature est remplacée (obtenu ${h["report-to"]})`);
    ok(h.link === '<https://api.exemple.test/liste?curseur=[caviardé]&page=[caviardé]>; rel="next"',
      `VERT · Link garde l'hôte, le chemin, les noms curseur et page, et rel (obtenu ${h.link})`);
    ok(h["content-security-policy"] === "default-src 'self'; report-uri https://rapports.exemple.test/csp?ctx=[caviardé]; frame-ancestors 'none'",
      `VERT · la CSP garde ses directives et le séparateur « ; » ; seule la valeur de ctx dans report-uri est remplacée (obtenu ${h["content-security-policy"]})`);
    ok(h["reporting-endpoints"] === 'default="https://rapports.exemple.test/r?ref=[caviardé]"',
      `VERT · Reporting-Endpoints garde son nom de groupe, l'hôte, le chemin et ref (obtenu ${h["reporting-endpoints"]})`);
    ok(h.nel === '{"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}' && h["access-control-allow-origin"] === "https://app.exemple.test"
      && h["x-content-type-options"] === "nosniff" && cap?.status === 302 && cap?.redirections_suivies === false,
      "VERT · les en-têtes sans paramètre d'URL (NEL, origine autorisée, nosniff) et le statut sortent octet pour octet");
    // Exploitable : oracle-exposition lit la CSP caviardée (ni EX-1, ni EX-2) et ne recopie aucune valeur.
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    ok(jug.verdict !== "ILLISIBLE" && !aRegle(jug, "EX-1") && !aRegle(jug, "EX-2") && !TOUS.some((s) => JSON.stringify(jug).includes(s)),
      `VERT · la capture caviardée reste exploitable : oracle-exposition lit la CSP (ni EX-1 ni EX-2) sans recopier de valeur (obtenu ${jug.verdict})`);
    // Bords, sur les fonctions : position contre forme, JSON échappé, séparateurs, userinfo et paramètre de chemin, idempotence.
    const { caviarderUrl, caviarderUrlEnTete, caviarderEnTetes } = await import(pathToFileURL(path.join(HERE, "..", "scripts", "caviarder-jetons.mjs")).href);
    const bordsEnTete = [
      ["/x?a=1&b=2#f=3&g", "/x?a=[caviardé]&b=[caviardé]#f=[caviardé]&g"],
      ["https://h.test/p/a", "https://h.test/p/a"],
      ["https://h.test/p?", "https://h.test/p?"],
      ["https://h.test/p#section", "https://h.test/p#section"],
      ["https://h.test/p?r=https%3A%2F%2Fa.test%2Fcb%3Fcode%3DSEC&x=1", "https://h.test/p?r=[caviardé]&x=[caviardé]"],
      ["https://h.test/p?a=1;b=SEC", "https://h.test/p?a=[caviardé]"],
      ["https://u:pw@h.test/p;jsessionid=X?z=1", "https://[caviardé]@h.test/p;jsessionid=[caviardé]?z=[caviardé]"],
      ["https://h.test/p?vide=&drapeau&k=v", "https://h.test/p?vide=[caviardé]&drapeau&k=[caviardé]"],
      ["https://h.test/p?a=[caviardé]", "https://h.test/p?a=[caviardé]"],
    ];
    const ecartsEnTete = bordsEnTete.filter(([e, s]) => caviarderUrlEnTete(e) !== s || caviarderUrlEnTete(caviarderUrlEnTete(e)) !== s)
      .map(([e, s]) => `${e} → ${caviarderUrlEnTete(e)} (attendu ${s})`);
    ok(ecartsEnTete.length === 0, `bords de l'URL d'en-tête : relative, sans requête, requête vide, fragment sans paramètre, valeur encodée, séparateur « ; », identifiant et paramètre de chemin, drapeau sans valeur, idempotent (écarts : ${ecartsEnTete.length}${ecartsEnTete.length ? " · " + ecartsEnTete[0] : ""})`);
    // TF-2390 : l'URL DEMANDÉE suit la règle de position elle aussi (voir le banc suivant). Le caviardage par forme de nom
    // (`caviarderUrl`) subsiste pour les valeurs imbriquées et reste exporté, inchangé : il est ici jugé seul.
    const urlParForme = caviarderUrl("https://h.test/p?page=2&meta=SEC&token=SEC");
    ok(urlParForme === "https://h.test/p?page=2&meta=SEC&token=[caviardé]", `le caviardage par forme de nom de la fonction caviarderUrl est inchangé (il ne sert plus à l'adresse capturée, TF-2390) (obtenu ${urlParForme})`);
    const e3 = caviarderEnTetes({
      "REPORT-TO": ['{"endpoints":[{"url":"https:\\/\\/a.test\\/r?s=SEC\\u0026t=2"}]}'], "Reporting-Endpoints": 'a="https://x.test/r?k=SEC", b="https://y.test/r?k=SEC"',
      "Content-Security-Policy": "report-uri https://r.test/c?ctx=SEC; script-src 'self'", "Alt-Svc": 'h3=":443"; ma=86400', Via: "1.1 proxy",
      "Access-Control-Allow-Origin": "https://app.test", "X-Autre": "garde?code=1", Location: ["/a?x=1", "/b?y=2"],
    });
    const e3Ok = e3["REPORT-TO"][0] === '{"endpoints":[{"url":"https:\\/\\/a.test\\/r?s=[caviardé]\\u0026t=[caviardé]"}]}'
      && e3["Reporting-Endpoints"] === 'a="https://x.test/r?k=[caviardé]", b="https://y.test/r?k=[caviardé]"'
      && e3["Content-Security-Policy"] === "report-uri https://r.test/c?ctx=[caviardé]; script-src 'self'"
      && e3["Alt-Svc"] === 'h3=":443"; ma=86400' && e3.Via === "1.1 proxy" && e3["Access-Control-Allow-Origin"] === "https://app.test"
      && e3["X-Autre"] === "garde?code=1" && e3.Location.join() === "/a?x=[caviardé],/b?y=[caviardé]";
    ok(e3Ok, `bords des en-têtes : JSON à barres échappées et \\u0026, liste d'URL entre guillemets, « ; » de la CSP, Alt-Svc, Via, origine, valeur en tableau (${e3Ok ? "tous tenus" : JSON.stringify(e3)})`);
  } finally {
    origine.close();
    fs.rmSync(tmpCap, { recursive: true, force: true });
  }
}

// ── TF-2390 · l'URL DEMANDÉE se caviarde elle aussi PAR POSITION (suite de TF-2306) ───────────────
// TF-2306 a mis les URL portées par un en-tête en caviardage par position ; le champ `url` de la capture (l'adresse passée
// en argument) et le message d'échec gardaient le caviardage par forme de nom. Un lien d'accès passé en argument
// (`?meta=<JWT>`, `?s=<signature>`, `#id=<valeur>`) y entrait donc en clair : aucun de ces noms n'est « de forme jeton ».
// Le banc lance le VRAI capturer.mjs sur une adresse qui porte ces valeurs, sur une réponse qui aboutit puis sur un port
// fermé (message d'échec), et juge dans les deux sens : ROUGE si une valeur survit ; VERT si schéma, hôte, chemin et NOMS
// des paramètres restent lisibles. Les faux jetons sont ASSEMBLÉS À L'EXÉCUTION (aucun jeton de test en clair au source).
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2390 : l'adresse capturée est caviardée par position, comme les en-têtes)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const b64 = (o) => Buffer.from(typeof o === "string" || Buffer.isBuffer(o) ? o : JSON.stringify(o)).toString("base64url");
  const enteteJwt = b64({ alg: "RS256", typ: "JWT", kid: "cle-de-test" });
  const signatureJwt = b64(Buffer.from(Array.from({ length: 256 }, (_, i) => (i * 11 + 5) % 256)));
  let charge = "";
  for (let n = 0; enteteJwt.length + charge.length + signatureJwt.length + 2 < 684; n++) {
    charge = b64({ aud: "app.exemple.test", marque: "SECRET-ADRESSE-META-7c1e", bourrage: "x".repeat(n) });
  }
  const jetonMeta = `${enteteJwt}.${charge}.${signatureJwt}`;
  const signatureS = b64("SECRET-ADRESSE-S-" + "4d2f".repeat(8));
  const valeurFragment = b64("SECRET-ADRESSE-FRAGMENT-" + "6a".repeat(10));
  const valeurRetour = b64("SECRET-ADRESSE-RETOUR-" + "3c".repeat(10));
  const SECRETS = { "meta (JWT de 684 caractères)": [jetonMeta, charge, signatureJwt], "s (signature)": [signatureS], "id (fragment)": [valeurFragment], "retour (nom ordinaire)": [valeurRetour] };
  const TOUS = Object.values(SECRETS).flat();
  const origine = http.createServer((req, res) => {
    res.statusCode = 200;
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.end("");
  });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${origine.address().port}/`;
  const parametres = `kid=cle-acces-id&meta=${jetonMeta}&s=${signatureS}&retour=${valeurRetour}&page=2`;
  const adresse = `${base}acces/ouvrir?${parametres}#id=${valeurFragment}&vue=liste`;
  const adresseAttendue = `${base}acces/ouvrir?kid=[caviardé]&meta=[caviardé]&s=[caviardé]&retour=[caviardé]&page=[caviardé]#id=[caviardé]&vue=[caviardé]`;
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-adresse-"));
  const lancer = (cible, args) => new Promise((resolve) => execFile(process.execPath, [CAPTURER, cible, ...args], { encoding: "utf8", timeout: 30000 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
  try {
    const fichier = path.join(tmpCap, "capture.json");
    const viaFichier = await lancer(adresse, ["--sortie", fichier]);
    const brut = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : "";
    const viaStdout = await lancer(adresse, []);
    ok(viaFichier.code === 0 && viaStdout.code === 0 && brut.length > 0,
      `capturer.mjs capture l'origine locale par une adresse qui porte meta, s, retour et un fragment, par fichier et par sortie standard (codes ${viaFichier.code} / ${viaStdout.code})`);
    // ROUGE : par paramètre, aucune valeur ne survit ni dans le fichier, ni sur la sortie standard, ni dans les messages.
    const sortie = brut + viaStdout.stdout + viaFichier.stderr + viaStdout.stderr;
    for (const [nom, secrets] of Object.entries(SECRETS)) {
      const survivants = secrets.filter((s) => sortie.includes(s));
      ok(survivants.length === 0, `ROUGE · la valeur de « ${nom} » de l'adresse capturée est caviardée (valeurs survivantes : ${survivants.length}/${secrets.length})`);
    }
    // VERT : schéma, hôte, chemin et NOMS des paramètres restent lisibles ; seules les valeurs sont remplacées.
    let cap = null;
    try { cap = JSON.parse(brut); } catch { /* les contrôles suivants le disent */ }
    ok(cap?.url === adresseAttendue,
      `VERT · l'adresse capturée garde schéma, hôte, chemin et les NOMS de ses paramètres (requête et fragment), chaque valeur est remplacée par position (obtenu ${cap?.url})`);
    ok(cap?.status === 200 && cap?.headers?.["x-content-type-options"] === "nosniff" && cap?.redirections_suivies === false,
      "VERT · le reste de la capture (statut, en-tête, drapeau de redirection) sort intact");
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    ok(jug.verdict !== "ILLISIBLE" && !TOUS.some((s) => JSON.stringify(jug).includes(s)),
      `VERT · la capture reste exploitable : oracle-exposition la lit (schéma de l'adresse conservé) sans recopier de valeur (obtenu ${jug.verdict})`);
    // Le message d'échec : même règle, l'adresse reste reconnaissable.
    const libre = http.createServer(); await new Promise((r) => libre.listen(0, "127.0.0.1", r));
    const portMort = libre.address().port; await new Promise((r) => libre.close(r));
    const echec = await lancer(`http://127.0.0.1:${portMort}/acces/ouvrir?${parametres}#id=${valeurFragment}`, []);
    const survivantsEchec = TOUS.filter((s) => echec.stderr.includes(s));
    ok(echec.code === 1 && /capture échouée/.test(echec.stderr) && survivantsEchec.length === 0,
      `ROUGE · le message d'échec ne recopie aucune valeur de l'adresse demandée (code ${echec.code}, valeurs survivantes : ${survivantsEchec.length})`);
    ok(echec.stderr.includes("/acces/ouvrir?kid=[caviardé]&meta=[caviardé]&s=[caviardé]&retour=[caviardé]&page=[caviardé]#id=[caviardé]"),
      `VERT · le message d'échec garde l'hôte, le chemin et les noms des paramètres : l'adresse reste reconnaissable (obtenu ${echec.stderr.trim().slice(0, 220)})`);
    // Le MOTIF de l'échec peut recopier l'adresse : `fetch` refuse un identifiant « utilisateur:mot-de-passe@ » ou une adresse
    // mal formée en citant l'adresse EN CLAIR dans son message. Le banc juge ces deux messages réels du moteur.
    const secretIdentifiant = "SECRET-ADRESSE-MOTDEPASSE-" + "e7".repeat(6);
    const secretChemin = "SECRET-ADRESSE-JSESSION-" + "1b".repeat(6);
    const avecIdentifiant = await lancer(`http://utilisateur:${secretIdentifiant}@127.0.0.1:${portMort}/p;jsessionid=${secretChemin}?${parametres}#id=${valeurFragment}`, []);
    const malFormee = await lancer(`http://127.0.0.1 :${portMort}/p?${parametres}#id=${valeurFragment}`, []);
    const aTester = [["avec identifiant (refus de fetch)", avecIdentifiant], ["mal formée (refus de fetch)", malFormee]];
    for (const [nom, r] of aTester) {
      const survivants = [...TOUS, secretIdentifiant, secretChemin].filter((s) => r.stderr.includes(s));
      ok(r.code === 1 && /capture échouée/.test(r.stderr) && survivants.length === 0,
        `ROUGE · le motif de l'échec d'une adresse ${nom} ne recopie ni l'identifiant, ni le paramètre de chemin, ni aucune valeur (code ${r.code}, valeurs survivantes : ${survivants.length})`);
    }
    ok(/Request cannot be constructed|Failed to parse URL/.test(avecIdentifiant.stderr + malFormee.stderr) && /meta=\[caviardé\]/.test(avecIdentifiant.stderr + malFormee.stderr),
      "VERT · le motif de l'échec garde la cause du moteur (refus de l'identifiant, adresse mal formée) et les noms des paramètres : seul le contenu des valeurs disparaît");
    // Sans paramètre, la capture est octet pour octet celle d'avant : rien n'est caviardé à tort.
    const nue = await lancer(`${base}accueil`, ["--sortie", path.join(tmpCap, "nue.json")]);
    const capNue = fs.existsSync(path.join(tmpCap, "nue.json")) ? JSON.parse(fs.readFileSync(path.join(tmpCap, "nue.json"), "utf8")) : null;
    ok(nue.code === 0 && capNue?.url === `${base}accueil`, `VERT · une adresse sans paramètre sort octet pour octet (obtenu ${capNue?.url})`);
  } finally {
    origine.close();
    fs.rmSync(tmpCap, { recursive: true, force: true });
  }
}

// ── TF-2394 (D-197 (c)) · le caviardage juge aussi le NOM : motif token, key, secret, auth, session, password ────────────
// Les caviardages de TF-2107 et TF-2133 ne reconnaissaient par nom qu'un seul en-tête (X-Auth-Token) et des noms de
// paramètre à liste exacte ou à suffixe : `X-API-Key`, `X-CSRF-Token`, `X-Access-Token` et `x-amz-security-token`
// sortaient en clair d'une capture versionnée avec le produit, et `?a=1;token=…` échappait à la lecture par « & ».
// Chaque forme fautive est ici une recette ROUGE avant le code, VERTE après. Les valeurs sont factices, ASSEMBLÉES À
// L'EXÉCUTION (aucun jeton de test en clair au source). Les témoins verts : les en-têtes neutres restent lisibles.
console.log("\nSELF-TEST forge-websec — caviarder-jetons.mjs (TF-2394 : masquage par motif de nom, en-têtes et paramètres d'URL)\n");
{
  const { caviarderEnTetes, caviarderUrl, estNomDeJeton } = await import(pathToFileURL(path.join(HERE, "..", "scripts", "caviarder-jetons.mjs")).href);
  const V = ["valeur", "factice", "ab12".repeat(3)].join("-");
  const M = "[caviardé]";
  const enTetesRouges = ["X-API-Key", "X-CSRF-Token", "X-Access-Token", "x-amz-security-token", "X-API-KEY", "X-Session-Id", "X-Client-Secret", "X-Password", "X-Authorization-Extra"];
  for (const nom of enTetesRouges) {
    const sortie = caviarderEnTetes({ [nom]: V });
    ok(sortie[nom] === M && !JSON.stringify(sortie).includes(V), `ROUGE · l'en-tête « ${nom} » est masqué par son nom, casse comprise (obtenu ${sortie[nom]})`);
  }
  const tableau = caviarderEnTetes({ "X-Api-Key": [V, V + "2"] });
  ok(Array.isArray(tableau["X-Api-Key"]) && tableau["X-Api-Key"].every((v) => v === M) && tableau["X-Api-Key"].length === 2,
    `ROUGE · un en-tête à nom suspect porté en tableau est masqué élément par élément (obtenu ${JSON.stringify(tableau["X-Api-Key"])})`);
  const urlsRouges = [
    [`https://h.test/p?a=1;token=${V}`, `https://h.test/p?a=1;token=${M}`, "« ; » après un paramètre ordinaire"],
    [`https://h.test/p?a=1&b=2;key=${V}&c=3`, `https://h.test/p?a=1&b=2;key=${M}&c=3`, "« ; » au milieu d'une requête séparée par « & »"],
    [`https://h.test/p?mysecretvalue=${V}&page=2`, `https://h.test/p?mysecretvalue=${M}&page=2`, "motif au milieu du nom (secret)"],
    [`https://h.test/p?auth_code=${V}`, `https://h.test/p?auth_code=${M}`, "motif en début de nom (auth)"],
    [`https://h.test/p?x=1#a=2;session_state=${V}`, `https://h.test/p?x=1#a=2;session_state=${M}`, "« ; » dans le fragment, motif session"],
    [`https://h.test/p;authx=${V}/q?z=1`, `https://h.test/p;authx=${M}/q?z=1`, "paramètre de chemin"],
    [`https://h.test/p?r=https%3A%2F%2Fa.test%2Fcb%3Fa%3D1%3Bapikey%3D${V}`, `https://h.test/p?r=https%3A%2F%2Fa.test%2Fcb%3Fa%3D1%3Bapikey%3D${M}`, "URL imbriquée encodée, « ; » comprise (le marqueur reste lisible)"],
  ];
  for (const [entree, attendu, libelle] of urlsRouges) {
    const sortie = caviarderUrl(entree);
    ok(sortie === attendu && !sortie.includes(V) && caviarderUrl(sortie) === sortie, `ROUGE · URL, ${libelle} : la valeur disparaît, idempotent (obtenu ${sortie.replace(V, "<V>")})`);
  }
  const neutres = { "Content-Type": "text/html; charset=utf-8", Accept: "text/html,*/*;q=0.8", "Cache-Control": "no-store, max-age=0", "User-Agent": "Mozilla/5.0", "Keep-Alive": "timeout=5, max=1000", "Content-Length": "123", "X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=63072000", "Content-Security-Policy": "default-src 'self'" };
  const sortieNeutres = caviarderEnTetes(neutres);
  ok(JSON.stringify(sortieNeutres) === JSON.stringify(neutres), `VERT · les en-têtes neutres (Content-Type, Accept, Cache-Control, User-Agent, Keep-Alive, CSP, HSTS…) sortent octet pour octet (${Object.keys(neutres).filter((k) => sortieNeutres[k] !== neutres[k]).join(", ") || "aucun masqué"})`);
  const dejaCouverts = caviarderEnTetes({ Authorization: `Bearer ${V}`, "Proxy-Authorization": `Basic ${V}`, Cookie: `sid=${V}; theme=clair`, "Set-Cookie": [`sid=${V}; Path=/; HttpOnly`], "X-Auth-Token": V, "WWW-Authenticate": 'Bearer realm="api", error="invalid_token"' });
  ok(dejaCouverts.Authorization === `Bearer ${M}` && dejaCouverts["Proxy-Authorization"] === `Basic ${M}` && !JSON.stringify(dejaCouverts).includes(V) && dejaCouverts["X-Auth-Token"] === M,
    `VERT · les cas déjà couverts restent masqués, schéma d'Authorization conservé (obtenu ${JSON.stringify(dejaCouverts).replace(V, "<V>")})`);
  ok(dejaCouverts["WWW-Authenticate"] === 'Bearer realm="api", error="invalid_token"', `VERT · WWW-Authenticate garde son défi (schéma, realm, error) : le motif ne l'efface pas en entier (obtenu ${dejaCouverts["WWW-Authenticate"]})`);
  const urlNeutre = "https://h.test/p?page=2&lang=fr&state=abc&q=a;b&sort=asc";
  ok(caviarderUrl(urlNeutre) === urlNeutre, `VERT · une URL sans nom suspect sort octet pour octet par caviarderUrl, « ; » compris (obtenu ${caviarderUrl(urlNeutre)})`);
  // Faux positifs mesurés le 10/11/2026 sur le registre IANA des champs HTTP (260 noms, field-names.csv) : 14 noms hors
  // Authorization, Cookie, Set-Cookie et Proxy-Authorization sont masqués par le motif. Aucun n'est lu par un oracle de
  // la forge. Le choix est de les laisser masqués, sans liste d'exemption (une liste est l'endroit où un secret se glisse).
  // Les noms ci-dessous épinglent ce choix ; le contraire, un en-tête usuel masqué à tort, fait échouer le témoin suivant.
  const usuels = ["Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Accept-Ranges", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Access-Control-Max-Age", "Age", "Allow", "Alt-Svc", "Cache-Control",
    "Clear-Site-Data", "Connection", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Length", "Content-Location", "Content-Range",
    "Content-Security-Policy", "Content-Type", "Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Date", "ETag", "Expect",
    "Expires", "Forwarded", "From", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "Keep-Alive", "Last-Modified", "Link", "Max-Forwards", "NEL", "Origin",
    "Permissions-Policy", "Pragma", "Range", "Referer", "Referrer-Policy", "Refresh", "Retry-After", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
    "Sec-WebSocket-Accept", "Server", "Server-Timing", "Strict-Transport-Security", "TE", "Timing-Allow-Origin", "Trailer", "Transfer-Encoding", "Upgrade",
    "Upgrade-Insecure-Requests", "User-Agent", "Vary", "Via", "Warning", "X-Content-Type-Options", "X-Frame-Options", "X-Powered-By", "X-Request-Id", "X-XSS-Protection"];
  const usuelsMasques = usuels.filter((n) => caviarderEnTetes({ [n]: "valeur-neutre" })[n] === M);
  ok(usuelsMasques.length === 0, `VERT · ${usuels.length} en-têtes usuels du registre IANA ne sont pas masqués par le motif, dont Keep-Alive (« keep » ne contient pas « key ») (masqués à tort : ${usuelsMasques.join(", ") || "aucun"})`);
  const excesAssumes = ["Public-Key-Pins", "Sec-WebSocket-Key", "Proxy-Authenticate", "Authentication-Info", "Lock-Token", "Sec-Token-Binding", "Include-Referred-Token-Binding-ID", "Optional-WWW-Authenticate", "Authentication-Control", "CMCD-Session"];
  const excesLus = excesAssumes.filter((n) => caviarderEnTetes({ [n]: "valeur-neutre" })[n] !== M);
  ok(excesLus.length === 0, `excès assumés : ${excesAssumes.length} noms du registre IANA dont le nom contient le motif sont masqués, même sans secret (clairs à tort : ${excesLus.join(", ") || "aucun"})`);
  ok(["token_type", "keyword", "author", "sessions"].every((n) => estNomDeJeton(n)) && ["page", "lang", "state", "sort", "q", "utm_source"].every((n) => !estNomDeJeton(n)),
    "excès assumé côté URL : token_type, keyword, author et sessions (le motif) sont masqués ; page, lang, state, sort, q et utm_source restent lisibles");
}

// TF-2394 · de bout en bout : le VRAI capturer.mjs, sur une réponse qui porte ces en-têtes, ne les écrit pas en clair.
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2394 : en-têtes à nom suspect d'une réponse réelle)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const V = ["valeur", "factice", "cd34".repeat(3)].join("-");
  const origine = http.createServer((req, res) => {
    res.statusCode = 200;
    for (const [n, v] of [["X-API-Key", V + "-1"], ["X-CSRF-Token", V + "-2"], ["X-Access-Token", V + "-3"], ["x-amz-security-token", V + "-4"], ["X-Session-Id", V + "-5"],
      ["X-Client-Secret", V + "-6"], ["X-Password-Hint", V + "-7"], ["X-Content-Type-Options", "nosniff"], ["Cache-Control", "no-store"], ["Keep-Alive", "timeout=5"]]) res.setHeader(n, v);
    res.end("");
  });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-nomsuspect-"));
  try {
    const fichier = path.join(tmpCap, "capture.json");
    const r = await new Promise((resolve) => execFile(process.execPath, [CAPTURER, `http://127.0.0.1:${origine.address().port}/?a=1;token=${V}-8`, "--sortie", fichier], { encoding: "utf8", timeout: 30000 },
      (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
    const brut = fs.existsSync(fichier) ? fs.readFileSync(fichier, "utf8") : "";
    ok(r.code === 0 && brut.length > 0, `capturer.mjs capture l'origine locale qui répond avec sept en-têtes à nom suspect (code ${r.code})`);
    const survivants = [1, 2, 3, 4, 5, 6, 7, 8].filter((n) => (brut + r.stdout + r.stderr).includes(`${V}-${n}`));
    ok(survivants.length === 0, `ROUGE · aucune des huit valeurs (sept en-têtes et le « ; token= » de l'adresse) ne survit dans la capture (survivantes : ${survivants.join(", ") || "aucune"})`);
    let cap = null;
    try { cap = JSON.parse(brut); } catch { /* le contrôle suivant le dit */ }
    ok(cap?.headers?.["x-api-key"] === "[caviardé]" && cap?.headers?.["x-amz-security-token"] === "[caviardé]" && cap?.headers?.["x-content-type-options"] === "nosniff"
      && cap?.headers?.["cache-control"] === "no-store" && cap?.headers?.["keep-alive"] === "timeout=5",
      `VERT · les noms restent lisibles, les valeurs suspectes sont remplacées, les en-têtes neutres sortent intacts (obtenu ${JSON.stringify(cap?.headers)})`);
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    ok(jug.verdict !== "ILLISIBLE", `VERT · la capture reste exploitable par oracle-exposition (obtenu ${jug.verdict})`);
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
