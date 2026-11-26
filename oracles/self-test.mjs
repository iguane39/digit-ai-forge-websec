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
import { execFile, execFileSync, spawn, spawnSync } from "node:child_process";
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

// Les fixtures SCA vulnérables sont rangées sous un nom que l'hébergeur ne lit pas (`<nom>.fixture`, TF-2579, D-220 (a)) : FXR(cas)
// les recopie sous leur vrai nom (`rejoue_sous`, tenu par fixtures/sca/FIXTURES-VULNERABLES.json) dans un dossier temporaire, que
// l'oracle SCA juge sans être modifié ; retirerRejeux() retire ces dossiers avant le bilan, et à la sortie quoi qu'il arrive.
const REJEUX = [];
const fichiersDeclares = (declaration) => (declaration?.fixtures_vulnerables || []).flatMap((l) => [l, ...(l.compagnons || [])]);
function FXR(cas) {
  const declaration = JSON.parse(fs.readFileSync(FX("sca", "FIXTURES-VULNERABLES.json"), "utf8"));
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), `websec-rejeu-${cas}-`));
  REJEUX.push(dossier);
  fs.cpSync(FX("sca", cas), dossier, { recursive: true });
  for (const f of fichiersDeclares(declaration)) {
    if (path.posix.dirname(f.manifeste) !== `fixtures/sca/${cas}`) continue;
    if (!fs.existsSync(path.join(dossier, path.posix.basename(f.manifeste)))) throw new Error(`fixture déclarée absente : ${f.manifeste} (rangée sous un autre nom ? la déclaration FIXTURES-VULNERABLES.json et le dossier doivent s'accorder)`);
    fs.renameSync(path.join(dossier, path.posix.basename(f.manifeste)), path.join(dossier, f.rejoue_sous));
  }
  return dossier;
}
function retirerRejeux() { for (const d of REJEUX.splice(0)) fs.rmSync(d, { recursive: true, force: true }); }
process.on("exit", retirerRejeux);

let pass = 0, echec = 0, note = 0;
const ok = (b, m) => { console.log(`  [${b ? "PASS" : "FAIL"}] ${m}`); b ? pass++ : echec++; };
const skipNote = (m) => { console.log(`  [SKIP] ${m}`); note++; };

// `delai` : l'oracle-sca laisse 240 s à pip-audit direct comme à uvx (TF-2455 ; uvx : résolution de django 1.4 dans un environnement isolé, 159 s mesurées le
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
  const r = runJson(ORACLE_SCA, [FXR("npm-vulnerable")]);
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
  const r = runJson(ORACLE_SCA, [FXR("pip-vulnerable")], undefined, 300000);
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

  let r = runJson(ORACLE_SCA, [FXR("uv-vulnerable")], viaUvx);
  ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP") && (r.findings || []).some((f) => f.regle === "SCA-PIP" && /django 1\.4/.test(f.msg)),
    `uv.lock avec django 1.4, pip-audit absent, uvx présent → FAIL avec SCA-PIP sur django 1.4 (obtenu ${r.verdict})`);
  ok(r.synthese && r.synthese.pip && r.synthese.pip.outil === "uvx pip-audit" && r.synthese.pip.total_paquets === 1,
    `uv.lock : le projet (source virtual) et le paquet git ne sont pas audités, 1 paquet de registre jugé via « uvx pip-audit » (obtenu ${JSON.stringify(r.synthese && r.synthese.pip)})`);
  ok(/paquet-git/.test(causes(r)) && !/demo-app/.test(causes(r)),
    `uv.lock : le paquet hors registre est NOMMÉ au manque, le projet lui-même n'y figure pas (obtenu « ${causes(r)} »)`);
  const appels = lireTrace().filter((a) => a.argv.includes("-r")); // hors sonde de présence (--version)
  ok(appels.length === 1 && appels[0].mode === "uvx" && appels[0].argv.includes("--no-deps") && appels[0].argv.includes("--disable-pip"),
    `uv.lock : un seul appel d'audit « uvx pip-audit … --no-deps --disable-pip », rien n'est résolu ni installé (obtenu ${JSON.stringify(appels)})`);
  // TF-2455 : l'appel uvx est épinglé à la version que nomme le remède de l'oracle (une seule source), et les deux
  // voies ont le même délai, au moins celui qu'il faut à pip-audit direct (174 s mesurées) et à uvx (159 s) sur django 1.4.
  const versionRemede = (/pip-audit==(\d+\.\d+\.\d+)/.exec(remedePipAbsent()) || [])[1];
  ok(Boolean(versionRemede) && appels[0] && appels[0].epingle === `pip-audit==${versionRemede}`,
    `l'appel uvx est épinglé à la version du remède, « uvx --from pip-audit==${versionRemede} pip-audit » (obtenu ${JSON.stringify(appels[0] && appels[0].epingle)})`);
  const delaiUvx = r.synthese && r.synthese.pip && r.synthese.pip.delai_s;
  const reqUtilise = appels[0] && appels[0].argv[appels[0].argv.indexOf("-r") + 1];
  ok(typeof reqUtilise === "string" && reqUtilise.startsWith(tmpOracle) && !reqUtilise.startsWith(FX("sca")) && fs.readdirSync(tmpOracle).length === 0,
    `le requirements dérivé du verrou est écrit dans le dossier temporaire, jamais dans la cible, et supprimé après l'audit (obtenu ${reqUtilise}, ${fs.readdirSync(tmpOracle).length} reste)`);

  r = runJson(ORACLE_SCA, [FX("sca", "uv-propre")], viaUvx);
  ok(r.verdict === "PASS" && r.synthese.pip && r.synthese.pip.total_paquets === 2 && (r.manques || []).length === 0,
    `uv.lock sans avis (2 paquets, projet editable exclu) → PASS, aucun manque (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);

  r = runJson(ORACLE_SCA, [FX("sca", "uv-versions-multiples")], viaUvx);
  ok(r.verdict === "PASS" && r.synthese.pip && r.synthese.pip.total_paquets === 3,
    `uv.lock avec deux versions du même paquet → PASS, 3 paquets jugés en deux lots (pip-audit refuse deux versions du même nom dans un fichier) (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);

  r = runJson(ORACLE_SCA, [FXR("poetry-vulnerable")], viaUvx);
  ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP") && r.synthese.pip && r.synthese.pip.total_paquets === 1 && /paquet-git/.test(causes(r)),
    `poetry.lock avec django 1.4 → FAIL avec SCA-PIP ; la table [package.dependencies] n'est pas lue comme un paquet, le paquet git est nommé au manque (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);
  r = runJson(ORACLE_SCA, [FX("sca", "poetry-propre")], viaUvx);
  ok(r.verdict === "PASS" && r.synthese.pip && r.synthese.pip.total_paquets === 2,
    `poetry.lock sans avis (2 paquets) → PASS (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip)})`);

  fs.rmSync(trace, { force: true });
  r = runJson(ORACLE_SCA, [FXR("uv-vulnerable")], direct);
  ok(r.verdict === "FAIL" && r.synthese.pip && r.synthese.pip.outil === "pip-audit" && lireTrace().length > 0 && lireTrace().every((a) => a.mode === "direct"),
    `pip-audit présent, uvx absent → pip-audit est lancé directement, sans uvx (obtenu ${r.verdict}, ${JSON.stringify(r.synthese && r.synthese.pip && r.synthese.pip.outil)})`);
  ok(typeof delaiUvx === "number" && delaiUvx >= 180 && r.synthese.pip.delai_s === delaiUvx,
    `le délai de la voie directe suit celui de la voie uvx, au moins 180 s (obtenu directe ${r.synthese.pip.delai_s} s, uvx ${delaiUvx} s)`);

  r = runJson(ORACLE_SCA, [FXR("pip-vulnerable")], viaUvx);
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

// ── un délai dépassé n'est pas un outil absent ; le délai de la sonde est réglable (TF-2413, TF-2417) ──
// Le 10/11/2026, `npm --version` a mis 39 s puis 20 s sur un poste chargé, npm 11.13.0 installé, et l'oracle a rendu deux
// SKIP « npm absent du poste ». Le banc joue le même outil SIMULÉ lent (WEBSEC_SIM_LENT_MS) sur les deux écosystèmes :
// ROUGE si la cause nommée est « absent » ou ne cite pas le délai, VERT quand la variable de délai laisse l'outil répondre.
{
  const SIM = FX("sca", "outils", "outil-simule.mjs");
  const ABSENT = path.join(os.tmpdir(), "websec-outil-absent");
  const causes = (r) => (r.manques || []).map((m) => m.cause).join(" | ");
  const remedes = (r) => (r.manques || []).map((m) => m.remede).join(" | ");
  const VAR = "WEBSEC_SCA_DELAI_OUTIL_S";
  const npmSim = (env) => ({ WEBSEC_SCA_NPM: SIM, ...env });
  const pipSim = (env) => ({ WEBSEC_SCA_PIP_AUDIT: SIM, WEBSEC_SCA_UVX: SIM, ...env });

  // npm lent (2,5 s), délai de la sonde ramené à 1 s : la sonde expire, la cause nommée est le délai, jamais l'absence.
  let r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")], npmSim({ WEBSEC_SIM_LENT_MS: "2500", [VAR]: "1" }));
  ok(r.verdict === "SKIP" && /n'a pas répondu en 1 s/.test(causes(r)) && /délai dépassé/.test(causes(r)) && !/absent du poste/.test(causes(r)) && causes(r).includes(VAR),
    `ROUGE · npm qui répond en 2,5 s avec un délai de sonde de 1 s → SKIP dont le manque nomme le délai dépassé et la variable, pas « absent du poste » (obtenu ${r.verdict}, « ${causes(r)} »)`);
  ok(remedes(r).includes(`${VAR}=`) && !/installer Node/.test(remedes(r)),
    `ROUGE · le remède d'un délai dépassé propose de régler le délai, pas d'installer l'outil (obtenu « ${remedes(r)} »)`);
  // le remède joué : le délai que le remède nomme laisse l'outil répondre, la sonde est passée (l'audit simulé, lui, échoue ensuite)
  r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")], npmSim({ WEBSEC_SIM_LENT_MS: "2500", [VAR]: "6" }));
  ok(!/n'a pas répondu/.test(causes(r)) && !/absent/.test(causes(r)) && /npm présent mais audit indisponible/.test(causes(r)),
    `VERT · le même npm lent avec le délai de 6 s (le remède joué) passe la sonde et atteint l'audit (obtenu « ${causes(r)} »)`);
  r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")], npmSim({ WEBSEC_SIM_LENT_MS: "1500" }));
  ok(/npm présent mais audit indisponible/.test(causes(r)),
    `VERT · sans variable, le délai par défaut reste de 10 s : un npm qui répond en 1,5 s passe la sonde (obtenu « ${causes(r)} »)`);
  // un outil réellement absent garde son message et son remède
  r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")], npmSim({ WEBSEC_SCA_NPM: ABSENT }));
  ok(r.verdict === "SKIP" && /npm absent du poste/.test(causes(r)) && /installer Node\.js\/npm/.test(remedes(r)) && !/délai/.test(causes(r)),
    `VERT · un npm réellement absent reste « absent du poste », avec le remède d'installation (obtenu « ${causes(r)} »)`);
  // un outil qui répond en erreur n'est ni absent ni lent : le code est nommé
  r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")], npmSim({ WEBSEC_SIM_VERSION_CODE: "3" }));
  ok(r.verdict === "SKIP" && /rend le code 3/.test(causes(r)) && !/n'a pas répondu/.test(causes(r)),
    `VERT · un npm qui répond par le code 3 est nommé tel quel, ni absent ni lent (obtenu « ${causes(r)} »)`);

  // pip : les deux voies lentes (2,5 s), délai de 1 s → la cause est le délai, plus « ni pip-audit ni uvx sur le poste »
  r = runJson(ORACLE_SCA, [FX("sca", "pip-clean")], pipSim({ WEBSEC_SIM_LENT_MS: "2500", [VAR]: "1" }));
  ok(r.verdict === "SKIP" && /pip-audit --version » n'a pas répondu en 1 s/.test(causes(r)) && /uvx --version » n'a pas répondu en 1 s/.test(causes(r)) && !/ni pip-audit ni uvx/.test(causes(r)),
    `ROUGE · pip-audit et uvx lents avec un délai de 1 s → SKIP dont le manque nomme le délai de CHAQUE voie, pas « ni pip-audit ni uvx » (obtenu « ${causes(r)} »)`);
  ok(remedes(r).includes(`${VAR}=`), `ROUGE · le remède pip d'un délai dépassé propose de régler le délai (obtenu « ${remedes(r)} »)`);
  // mélange : pip-audit réellement absent, uvx lent → chaque voie dit sa propre cause
  r = runJson(ORACLE_SCA, [FX("sca", "pip-clean")], { WEBSEC_SCA_PIP_AUDIT: ABSENT, WEBSEC_SCA_UVX: SIM, WEBSEC_SIM_LENT_MS: "2500", [VAR]: "1" });
  ok(/pip-audit absent du poste/.test(causes(r)) && /uvx --version » n'a pas répondu en 1 s/.test(causes(r)),
    `VERT · pip-audit absent et uvx lent : chaque voie nomme sa cause (obtenu « ${causes(r)} »)`);
  r = runJson(ORACLE_SCA, [FX("sca", "pip-clean")], pipSim({ WEBSEC_SIM_LENT_MS: "2500", [VAR]: "6" }));
  ok(r.verdict === "PASS" && (r.manques || []).length === 0,
    `VERT · les mêmes voies lentes avec le délai de 6 s, le remède joué → l'audit a lieu, PASS (obtenu ${r.verdict}, « ${causes(r)} »)`);

  // une valeur de délai illisible est refusée net, jamais remplacée en silence par le défaut
  for (const valeur of ["abc", "0", "-5"]) {
    r = runJson(ORACLE_SCA, [FX("sca", "npm-clean")], npmSim({ [VAR]: valeur }));
    ok(r.verdict === "FAIL" && (r.findings || []).some((f) => f.sev === "bloquant" && f.msg.includes(VAR)),
      `${VAR}=${valeur} → FAIL qui nomme la variable, aucun défaut implicite (obtenu ${r.verdict})`);
  }
}

// ── verrous avec l'outil RÉEL du poste (pip-audit, sinon uvx) et le réseau ───────
{
  if (!pipVoie) {
    skipNote(`ni pip-audit ni uvx sur le poste — sens rouge SCA-PIP sur uv.lock / poetry.lock non démontré avec l'outil réel ; pour le jouer : ${remedePipAbsent()}`);
  } else {
    for (const cas of ["uv-vulnerable", "poetry-vulnerable"]) {
      const r = runJson(ORACLE_SCA, [FXR(cas)]);
      if (r.verdict === "SKIP") skipNote(`${cas} : audit indisponible avec l'outil réel (probable absence réseau) — sens rouge non démontré cette exécution : ${r.motif}`);
      else ok(r.verdict === "FAIL" && aRegle(r, "SCA-PIP"), `${cas} (django 1.4) → FAIL avec SCA-PIP, outil réel « ${r.synthese && r.synthese.pip && r.synthese.pip.outil} » (obtenu ${r.verdict})`);
    }
    // la voie uvx RÉELLE : pip-audit déclaré absent (chemin injouable), uvx du poste lancé pour de bon
    if (uvxDispo) {
      const r = runJson(ORACLE_SCA, [FXR("uv-vulnerable")], { WEBSEC_SCA_PIP_AUDIT: path.join(os.tmpdir(), "websec-outil-absent") });
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
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === "zap-baseline.mjs" && r.synthese.balayage.scan === "passif" && optionsZ(lignes) === "-config 'spider.processform=false' -config 'spider.postform=false'",
      `mode passif → la passe baseline, une fois, avec pour seules options les deux réglages d'araignée qui coupent les formulaires (TF-2498) (obtenu ${r.verdict}, ${lignes.map((l) => l.script).join(",")}, « ${optionsZ(lignes)} »)`);
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
    // TF-2649 : Cloudflare Access n'accepte le jeton de service en un seul en-tête que sous « Authorization » (13/11/2026, Produit-84-dev)
    ["jeton de service Access sous un nom X-…", { en_tete_acces: { nom: "X-Produit-84-Access", valeur_env: "WEBSEC_DAST_TEST_ACCES", jeton_service_access: true } }, "refusé pour un jeton de service Cloudflare Access"],
    ["jeton de service Access sous un autre nom usuel", { en_tete_acces: { nom: "CF-Access-Token", valeur_env: "WEBSEC_DAST_TEST_ACCES", jeton_service_access: true } }, "Access ne lit ce jeton que dans « Authorization »"],
    ["jeton_service_access qui n'est pas un booléen", { en_tete_acces: { nom: "Authorization", valeur_env: "WEBSEC_DAST_TEST_ACCES", jeton_service_access: "oui" } }, "jeton_service_access"],
  ];
  for (const [libelle, variante, motif] of rouges) {
    const f = path.join(dossier, "autorisation-rouge.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, ...variante }));
    const { r, lignes } = lancer(ZAP.complet, f, "actif");
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-CHAMPS") && msgs(r).includes(motif) && lignes.length === 0,
      `${libelle} → FAIL DAST-AUTZ-CHAMPS qui cite « ${motif} », rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  // TF-2649 · le remède que le refus propose, joué : « Authorization » + valeur JSON, déclarés jeton de service Access → PASS.
  // La valeur est assemblée à l'exécution (aucun identifiant ni secret, même fictif, n'est écrit dans le dépôt).
  for (const nomEnTete of ["Authorization", "authorization"]) {
    const f = path.join(dossier, "autorisation-access.json");
    const jeton = JSON.stringify({ "cf-access-client-id": "fixture-id", "cf-access-client-secret": ["fixture", "non", "secret"].join("-") });
    fs.writeFileSync(f, JSON.stringify({ ...valide, en_tete_acces: { nom: nomEnTete, valeur_env: "WEBSEC_DAST_TEST_ACCES", jeton_service_access: true } }));
    const { r, lignes } = lancer(ZAP.complet, f, "actif", { WEBSEC_DAST_TEST_ACCES: jeton });
    ok(r.verdict === "PASS" && lignes.length === 1 && dedans(optionsZ(lignes), `replacer.full_list(0).matchstr=${nomEnTete}`) && !JSON.stringify(r).includes("fixture-non-secret"),
      `TF-2649 · VERT — jeton de service Access sous « ${nomEnTete} » avec sa valeur JSON → balayage lancé, valeur jamais reprise dans le verdict (obtenu ${r.verdict}, ${lignes.length} lancement)`);
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

  // ── TF-2655 · un rapport ZAP à 0 site n'est pas un PASS : rien n'a été exploré ───────────────────
  // Classe couverture-calculee-sur-enumeration-incomplete : le 13/11/2026, chez un produit, ZAP a balayé la racine d'une API
  // (404, aucun lien), rendu un rapport à 0 site et 0 alerte en 60 s, et l'oracle a rendu PASS.
  {
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-vide.json")]);
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-RIEN-EXPLORE") && r.synthese.zap.sites === 0,
      `TF-2655 · ROUGE — rapport fourni à 0 site → SKIP DAST-RIEN-EXPLORE, plus un PASS (obtenu ${r.verdict}, ${(r.findings || []).map((x) => x.regle).join(",")})`);
  }
  {
    const { r, lignes } = lancer(ZAP.baseline, AUTZ("autorisation-valide.json"), "passif", { WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-vide.json") });
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-RIEN-EXPLORE") && lignes.length === 1,
      `TF-2655 · ROUGE — balayage dont ZAP rend un rapport à 0 site → SKIP DAST-RIEN-EXPLORE, pas un PASS (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    // Le plancher est « 0 site », pas « 0 alerte » : un site exploré sans aucune alerte est un rapport propre, et reste un PASS.
    const f = path.join(dossier, "rapport-un-site-sans-alerte.json");
    fs.writeFileSync(f, JSON.stringify({ "@programName": "ZAP", "@version": "2.17.0", site: [{ "@name": CIBLE_OK, "@host": "recette.exemple.tld", "@port": "443", "@ssl": "true", alerts: [] }] }));
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", f]);
    ok(r.verdict === "PASS" && r.synthese.zap.sites === 1 && !aRegle(r, "DAST-RIEN-EXPLORE"),
      `TF-2655 · VERT — un site exploré sans aucune alerte reste un PASS : le plancher est 0 site, pas 0 alerte (obtenu ${r.verdict}, ${r.synthese.zap && r.synthese.zap.sites} site)`);
  }

  // ── TF-2485 · la forme prescrite sur la plateforme, jouée par un VRAI script qui enveloppe le ZAP simulé ──
  // Classe oracle-chemin-prescrit-inoperant-sur-sa-cible : le 12/11/2026, chez un produit, zap.bat ne partait
  // pas (Node v24.16.0 refuse un .bat sans shell : EINVAL) et l'oracle rendait « lancé… sortie vide ». Le
  // banc ne jouait que des .mjs, lancés par node : la forme prescrite n'y passait jamais. Ici, zap.bat sur
  // Windows, zap.sh ailleurs, avec les options qui portent les caractères que cmd.exe interpréterait hors
  // guillemets (espace et apostrophe dans l'en-tête, `^ ( ) $ \` dans les expressions).
  const enveloppe = (nomDossier) => {
    const d = path.join(dossier, nomDossier);
    fs.mkdirSync(d);
    const coeur = path.join(d, "zap-simule.mjs");
    fs.copyFileSync(AUTZ("zap-simule.mjs"), coeur);
    if (process.platform === "win32") {
      const f = path.join(d, "zap.bat");
      fs.writeFileSync(f, `@"${process.execPath}" "${coeur}" %*\r\n`);
      return f;
    }
    const f = path.join(d, "zap.sh");
    fs.writeFileSync(f, `#!/bin/sh\nexec "${process.execPath}" "${coeur}" "$@"\n`, { mode: 0o755 });
    return f;
  };
  const ZAP_REEL = enveloppe("zap-natif");
  const forme = path.basename(ZAP_REEL);
  {
    const { r, lignes } = lancer(ZAP_REEL, AUTZ("autorisation-actif-options.json"), "actif");
    const a = (lignes[0] && lignes[0].argv) || [];
    const iDir = a.indexOf("-dir");
    ok(r.verdict === "PASS" && lignes.length === 1 && r.synthese.balayage.forme === "rapide",
      `TF-2485 · VERT — ${forme} réel (forme prescrite sur ${process.platform}) lancé, son rapport jugé (obtenu ${r.verdict}, ${lignes.length} lancement${r.verdict !== "PASS" ? ", " + msgs(r).slice(0, 200) : ""})`);
    ok(a.includes(`replacer.full_list(0).replacement=${ACCES}`) && a.includes("replacer.full_list(0).url=^https://recette\\.exemple\\.tld(/.*)?$"),
      `TF-2485 · VERT — à travers ${forme}, chaque argument arrive intact (espace, apostrophe, ^ ( ) $ \\)`);
    ok(lignes[0] && path.resolve(lignes[0].cwd).toLowerCase() === path.dirname(ZAP_REEL).toLowerCase() && iDir >= 0 && /zap-home$/.test(a[iDir + 1] || ""),
      `TF-2485 · VERT — ZAP natif tourne dans son propre dossier, avec -dir vers un dossier jetable (cwd ${lignes[0] && lignes[0].cwd})`);
  }
  if (process.platform === "win32") {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", `${CIBLE_OK}/a%20b`, "--autorisation", AUTZ("autorisation-actif.json"), "--mode", "actif"], {
      WEBSEC_DAST_ZAP: ZAP_REEL, WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"),
    });
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-LANCEMENT") && !fs.existsSync(trace),
      `TF-2485 · ROUGE — un argument qui porte « % » n'est jamais réécrit pour cmd.exe : SKIP DAST-LANCEMENT, rien de lancé (obtenu ${r.verdict})`);
  } else skipNote("TF-2485 · ROUGE « % » pour cmd.exe : propre à Windows, non joué sur ce poste");
  {
    const faux = path.join(dossier, process.platform === "win32" ? "zap.exe" : "zap");
    fs.writeFileSync(faux, "pas un binaire\n", { mode: 0o644 });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-actif.json"), "--mode", "actif"], { WEBSEC_DAST_ZAP: faux });
    ok(r.verdict === "SKIP" && /refusé de lancer la commande \(\S+\)/.test(msgs(r)) && r.synthese.balayage.execution.erreur && !/ lancé mais /.test(msgs(r)),
      `TF-2485 · ROUGE — un lancement refusé par le système est dit avec son code (${r.synthese && r.synthese.balayage && r.synthese.balayage.execution && r.synthese.balayage.execution.erreur}), jamais « lancé… sortie vide »`);
  }

  // ── TF-2486 · le délai de ZAP suit le débit du mandat, et un délai dépassé arrête tout l'arbre ──
  // Le 12/11/2026 : délai fixe de 30 min, quel que soit le débit. À 10 requêtes par minute, environ 299
  // requêtes en 30 min, contre 891 mesurées au banc pour 4 routes : le balayage aurait fini sans rapport.
  {
    const f = path.join(dossier, "autorisation-debit-lent.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, debit_max_requetes_par_seconde: 10 / 60 }));
    const { r } = lancer(ZAP.complet, f, "actif");
    ok(r.verdict === "PASS" && r.synthese.balayage.delai_max_minutes === 105 && /1000 requêtes × 6000 ms/.test(r.synthese.balayage.delai_source),
      `TF-2486 · VERT — 10 requêtes par minute : délai déduit de 1000 × 6 000 ms + 5 min = 105 min, plus 30 (obtenu ${r.synthese.balayage && r.synthese.balayage.delai_max_minutes} min)`);
  }
  {
    const f = path.join(dossier, "autorisation-plafond.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, debit_max_requetes_par_seconde: 10 / 60, plafond_requetes: 3000 }));
    const { r } = lancer(ZAP.complet, f, "actif");
    ok(r.verdict === "PASS" && r.synthese.balayage.delai_max_minutes === 305, `TF-2486 · VERT — plafond_requetes: 3000 au même débit → 305 min (obtenu ${r.synthese.balayage && r.synthese.balayage.delai_max_minutes})`);
  }
  {
    const f = path.join(dossier, "autorisation-duree.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, duree_max_minutes: 240 }));
    const { r } = lancer(ZAP.complet, f, "actif");
    ok(r.verdict === "PASS" && r.synthese.balayage.delai_max_minutes === 240 && /duree_max_minutes/.test(r.synthese.balayage.delai_source),
      `TF-2486 · VERT — duree_max_minutes: 240 prime sur le débit (obtenu ${r.synthese.balayage && r.synthese.balayage.delai_max_minutes})`);
  }
  {
    const f = path.join(dossier, "autorisation-fenetre-courte.json");
    const finProche = new Date(Date.now() + 10 * 60000).toISOString();
    fs.writeFileSync(f, JSON.stringify({ ...valide, duree_max_minutes: 240, fenetre: { debut: "2026-01-01", fin: finProche } }));
    const { r } = lancer(ZAP.complet, f, "actif");
    const d = r.synthese.balayage && r.synthese.balayage.delai_max_minutes;
    ok(r.verdict === "PASS" && d <= 10 && d > 9 && /fin de la fenêtre/.test(r.synthese.balayage.delai_source),
      `TF-2486 · VERT — fenêtre qui finit dans 10 min : le délai s'y borne (obtenu ${d} min)`);
  }
  {
    const f = path.join(dossier, "autorisation-courte.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, duree_max_minutes: 0.03 }));
    const fin = path.join(dossier, "fin-simule.txt");
    const debut = Date.now();
    const { r } = lancer(ZAP_REEL, f, "actif", { WEBSEC_DAST_SIMULE_ATTENTE_MS: "6000", WEBSEC_DAST_SIMULE_FIN: fin });
    const duree = Date.now() - debut;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, 7000 - duree));
    ok(r.verdict === "SKIP" && aRegle(r, "DAST-DELAI") && /1,8 s|0\.03 min/.test(msgs(r)) && r.synthese.balayage.execution.coupe_par_le_delai === true,
      `TF-2486 · ROUGE — délai dépassé : SKIP DAST-DELAI qui dit la durée et sa source (obtenu ${r.verdict}, ${(r.findings || []).map((x) => x.regle).join(",")})`);
    ok(!fs.existsSync(fin) && duree < 5500,
      `TF-2486 · ROUGE — l'arbre entier est arrêté : le ZAP simulé, petit-enfant par ${forme}, n'a jamais fini (oracle rendu en ${duree} ms, marqueur de fin ${fs.existsSync(fin) ? "PRÉSENT" : "absent"})`);
  }
  for (const [libelle, variante, motif] of [
    ["durée à 0", { duree_max_minutes: 0 }, "duree_max_minutes"],
    ["durée en texte", { duree_max_minutes: "30" }, "duree_max_minutes"],
    ["durée au-delà de 24 h", { duree_max_minutes: 2000 }, "duree_max_minutes"],
    ["plafond à 0", { plafond_requetes: 0 }, "plafond_requetes"],
    ["plafond non entier", { plafond_requetes: 1.5 }, "plafond_requetes"],
    ["plafond sans débit", { plafond_requetes: 500, debit_max_requetes_par_seconde: undefined }, "sans debit_max_requetes_par_seconde"],
  ]) {
    const f = path.join(dossier, "autorisation-rouge.json");
    fs.writeFileSync(f, JSON.stringify({ ...valide, ...variante }));
    const { r, lignes } = lancer(ZAP.complet, f, "actif");
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-AUTZ-CHAMPS") && msgs(r).includes(motif) && lignes.length === 0,
      `TF-2486 · ROUGE — ${libelle} → FAIL DAST-AUTZ-CHAMPS qui cite « ${motif} », rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  fs.rmSync(dossier, { recursive: true, force: true });
}

// ── TF-2853 · une API se balaie depuis sa définition OpenAPI locale, sous garde-fou de périmètre ───────────────
// Classe couverture-calculee-sur-enumeration-incomplete (RP-74, lot de retours du 25/11/2026) : TF-2655 rend SKIP un rapport à 0 site,
// mais une API dont la racine rend 404 sans lien n'avait aucun point de départ, et chaque balayage rendait ce SKIP. `--openapi-fichier`
// donne sa définition à zap-api-scan.py ; le garde-fou la juge AVANT tout lancement : chaque serveur sur une origine de `cibles`, chaque
// URL hors des `exclusions`, références internes seulement, GET et HEAD seuls en mode passif. Un ZAP SIMULÉ (zap-simule.mjs, copié sous le
// nom zap-api-scan.mjs) et un Docker SIMULÉ (docker-simule.mjs) enregistrent la ligne de commande : aucun cas n'émet rien vers une cible.
// Chaque refus est prouvé « rien de lancé » (trace vide). Chaque cas VERT juge ce que seule la voie OpenAPI produit (-f openapi, la
// synthèse de la définition) : sur l'oracle 0.4.0, qui ignorait l'option, aucun ne passe.
console.log("\nSELF-TEST forge-websec — oracle-dast (TF-2853 : définition OpenAPI locale, garde-fou de périmètre)\n");
{
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "websec-dast-openapi-"));
  const simule = (nom) => { const f = path.join(dossier, `${nom}.mjs`); fs.copyFileSync(AUTZ("zap-simule.mjs"), f); return f; };
  const ZAP = { api: simule("zap-api-scan"), baseline: simule("zap-baseline"), complet: simule("zap-full-scan") };
  const trace = path.join(dossier, "trace.jsonl");
  const lireTrace = () => (fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  // `definition` à null : aucune option --openapi-fichier ; `args` complète la ligne de commande.
  const lancer = (definition, { zap = ZAP.api, autz = AUTZ("autorisation-valide.json"), mode = "passif", env = {}, args = [] } = {}) => {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", autz, "--mode", mode, ...(definition === null ? [] : ["--openapi-fichier", definition]), ...args], {
      WEBSEC_DAST_ZAP: zap, WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"), ...env,
    });
    return { r, lignes: lireTrace() };
  };
  const ecrire = (nom, contenu) => { const f = path.join(dossier, nom); fs.writeFileSync(f, typeof contenu === "string" ? contenu : JSON.stringify(contenu, null, 2)); return f; };
  const lireFixture = (nom) => JSON.parse(fs.readFileSync(AUTZ(nom), "utf8"));
  const variante = (nom, modifier, depuis = "openapi-dans-perimetre.json") => { const d = lireFixture(depuis); modifier(d); return ecrire(nom, d); };
  const autorisation = (nom, ajout) => ecrire(nom, { ...lireFixture("autorisation-valide.json"), ...ajout });
  const msgs = (r) => (r.findings || []).map((f) => f.msg).join(" ");
  const regles = (r) => (r.findings || []).map((f) => f.regle).join(",");
  const argv = (lignes) => (lignes[0] && lignes[0].argv) || [];
  const apres = (a, option) => { const i = a.indexOf(option); return i >= 0 ? a[i + 1] : undefined; };
  const refuse = (r, lignes, regle) => r.verdict === "FAIL" && aRegle(r, regle) && lignes.length === 0;
  const DEF = AUTZ("openapi-dans-perimetre.json");
  const AUTZ_EXCLUSIONS = autorisation("autorisation-exclusions.json", { exclusions: ["/deconnexion", "/admin/supprimer"] });

  // ── sens VERT : la définition jugée part, une fois, par zap-api-scan, et c'est elle que ZAP reçoit ──
  {
    const { r, lignes } = lancer(DEF);
    const a = argv(lignes);
    const transmise = apres(a, "-t") || "";
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === "zap-api-scan.mjs" && apres(a, "-f") === "openapi" && a.includes("-S") && a.includes("-I") && Boolean(apres(a, "-J")),
      `TF-2853 · VERT — mode passif, définition dans le périmètre : zap-api-scan, une fois, avec -f openapi et -S (mode sûr, aucune attaque active) (obtenu ${r.verdict}, ${lignes.length} lancement, « ${a.join(" ").slice(0, 160)} »)`);
    ok(/definition-openapi\.json$/.test(transmise) && fs.existsSync(transmise) && JSON.stringify(JSON.parse(fs.readFileSync(transmise, "utf8"))) === JSON.stringify(lireFixture("openapi-dans-perimetre.json")),
      `TF-2853 · VERT — ZAP reçoit la définition jugée, copiée dans le dossier de travail de l'oracle (obtenu « ${transmise} »)`);
    ok(apres(a, "-f") === "openapi" && apres(a, "-z") === "-config 'spider.processform=false' -config 'spider.postform=false'" && !a.includes("-O"),
      `TF-2853 · VERT — en passif, la voie OpenAPI garde dans -z les deux réglages qui coupent les formulaires, et -O n'est pas passé : ZAP part des serveurs jugés (obtenu « ${apres(a, "-z")} »)`);
    const o = r.synthese && r.synthese.openapi;
    ok(r.synthese?.balayage?.forme === "api" && o && o.operations === 3 && JSON.stringify(o.origines) === JSON.stringify(["https://recette.exemple.tld"]) && o.methodes.GET === 2 && o.methodes.HEAD === 1
      && /GET et HEAD/.test(r.synthese.balayage.openapi?.requetes || ""),
      `TF-2853 · VERT — le verdict consigne la forme api, les 3 opérations, leurs méthodes et l'origine balayée (obtenu ${JSON.stringify(o)})`);
  }
  {
    const { r, lignes } = lancer(DEF, { autz: AUTZ("autorisation-actif.json"), mode: "actif" });
    const a = argv(lignes);
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === "zap-api-scan.mjs" && apres(a, "-f") === "openapi" && !a.includes("-S") && !a.includes("-z"),
      `TF-2853 · VERT — mode actif autorisé : zap-api-scan sans -S, son attaque active a lieu (obtenu ${r.verdict}, « ${a.join(" ").slice(0, 160)} »)`);
  }
  {
    const yaml = AUTZ("openapi-dans-perimetre.yaml");
    const { r, lignes } = lancer(yaml);
    const transmise = apres(argv(lignes), "-t") || "";
    ok(r.verdict === "PASS" && lignes.length === 1 && /definition-openapi\.yaml$/.test(transmise) && fs.existsSync(transmise)
      && fs.readFileSync(transmise, "utf8") === fs.readFileSync(yaml, "utf8").replace(/^﻿/, "")
      && r.synthese?.openapi?.version === "2.0" && r.synthese.openapi.format === "yaml" && r.synthese.openapi.operations === 2,
      `TF-2853 · VERT — Swagger 2.0 en YAML (host, basePath, schemes) : jugé, puis transmis tel quel à ZAP (obtenu ${r.verdict}, ${JSON.stringify(r.synthese?.openapi)})`);
  }
  {
    const deux = autorisation("autorisation-deux-cibles.json", { cibles: [CIBLE_OK, "https://autre.exemple.tld"], exclusions: ["/deconnexion"] });
    const { r, lignes } = lancer(variante("deux-origines.json", (d) => { d.servers.push({ url: "https://autre.exemple.tld/rest/v1" }); }), { autz: deux });
    const z = apres(argv(lignes), "-z") || "";
    ok(r.verdict === "PASS" && lignes.length === 1 && JSON.stringify(r.synthese?.openapi?.origines) === JSON.stringify(["https://recette.exemple.tld", "https://autre.exemple.tld"])
      && z.includes("globalexcludeurl.url_list.url(0).regex=^https://recette\\.exemple\\.tld/deconnexion.*") && z.includes("globalexcludeurl.url_list.url(1).regex=^https://autre\\.exemple\\.tld/deconnexion.*"),
      `TF-2853 · VERT — deux serveurs, chacun sur une origine de cibles : admis, et ZAP reçoit l'exclusion du mandat sur chaque origine (obtenu ${r.verdict}, « ${z.slice(0, 220)} »)`);
  }

  // ── sens ROUGE : un serveur ou un chemin hors périmètre refuse TOUT le lancement, en le nommant ; rien n'est émis ──
  {
    const { r, lignes } = lancer(AUTZ("openapi-hors-perimetre.json"));
    ok(refuse(r, lignes, "DAST-OPENAPI-HORS-PERIMETRE") && msgs(r).includes("https://autre.exemple.tld") && !msgs(r).includes("« https://recette.exemple.tld/rest/v1 »"),
      `TF-2853 · ROUGE — un serveur sur une origine hors des cibles (autre.exemple.tld) refuse tout, nommé, rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement, ${regles(r)})`);
  }
  {
    const { r, lignes } = lancer(AUTZ("openapi-chemin-exclu.json"), { autz: AUTZ_EXCLUSIONS });
    const m = msgs(r);
    ok(refuse(r, lignes, "DAST-OPENAPI-HORS-PERIMETRE") && m.includes("https://recette.exemple.tld/deconnexion") && m.includes("https://recette.exemple.tld/admin/supprimer/tout") && !m.includes("https://recette.exemple.tld/fiches"),
      `TF-2853 · ROUGE — deux chemins sous les exclusions (/deconnexion, et /admin/supprimer par préfixe) : chacun nommé, tout refusé, rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement, ${regles(r)})`);
    // le remède que le message propose : retirer les chemins exclus ; ZAP reçoit toujours les exclusions du mandat
    const remede = variante("sans-exclus.json", (d) => { delete d.paths["/deconnexion"]; delete d.paths["/admin/supprimer/tout"]; }, "openapi-chemin-exclu.json");
    const v = lancer(remede, { autz: AUTZ_EXCLUSIONS });
    ok(v.r.verdict === "PASS" && v.lignes.length === 1 && apres(argv(v.lignes), "-f") === "openapi" && (apres(argv(v.lignes), "-z") || "").includes("globalexcludeurl.url_list.url(0).regex=^https://recette\\.exemple\\.tld/deconnexion.*"),
      `TF-2853 · VERT — le remède joué : sans les chemins exclus, le balayage part, et ZAP reçoit toujours les exclusions du mandat (obtenu ${v.r.verdict}, ${v.lignes.length} lancement)`);
  }
  {
    const ecriture = AUTZ("openapi-ecriture.json");
    const { r, lignes } = lancer(ecriture);
    const m = msgs(r);
    ok(refuse(r, lignes, "DAST-OPENAPI-METHODE")
      && ["POST https://recette.exemple.tld/rest/v1/fiches", "PATCH https://recette.exemple.tld/rest/v1/fiches", "DELETE https://recette.exemple.tld/rest/v1/fiches", "POST https://recette.exemple.tld/rest/v1/rpc/compter_fiches"].every((x) => m.includes(x))
      && !m.includes("GET https://"),
      `TF-2853 · ROUGE — mode passif et opérations qui écrivent : chacune nommée (POST, PATCH, DELETE), tout refusé, rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement, ${regles(r)})`);
    const actif = lancer(ecriture, { autz: AUTZ("autorisation-actif.json"), mode: "actif" });
    ok(actif.r.verdict === "PASS" && actif.lignes.length === 1 && apres(argv(actif.lignes), "-f") === "openapi" && !argv(actif.lignes).includes("-S") && actif.r.synthese?.openapi?.methodes?.DELETE === 1,
      `TF-2853 · VERT — le remède joué : la même définition en mode actif, sous actif_autorise: true, part (obtenu ${actif.r.verdict}, ${actif.lignes.length} lancement)`);
    const lecture = variante("lecture.json", (d) => {
      for (const p of Object.values(d.paths)) for (const k of Object.keys(p)) if (k !== "get") delete p[k];
      for (const [k, p] of Object.entries(d.paths)) if (!Object.keys(p).length) delete d.paths[k];
    }, "openapi-ecriture.json");
    const passif = lancer(lecture);
    ok(passif.r.verdict === "PASS" && passif.lignes.length === 1 && argv(passif.lignes).includes("-S") && passif.r.synthese?.openapi?.operations === 1,
      `TF-2853 · VERT — l'autre remède joué : la définition réduite à ses lectures (GET) part en mode passif (obtenu ${passif.r.verdict}, ${passif.lignes.length} lancement)`);
    const sansAutz = lancer(ecriture, { mode: "actif" });
    ok(sansAutz.r.verdict === "FAIL" && aRegle(sansAutz.r, "DAST-AUTZ-MODE") && sansAutz.lignes.length === 0,
      `TF-2853 · garde inchangée — le mode actif sans actif_autorise reste refusé avec une définition (DAST-AUTZ-MODE), rien de lancé (obtenu ${sansAutz.r.verdict})`);
  }
  // fichier absent, illisible, ou qui n'est pas une définition : refus net
  for (const [libelle, chemin, motif] of [
    ["fichier absent", path.join(dossier, "absente.json"), /introuvable/],
    ["un dossier au lieu d'un fichier", dossier, /illisible/],
    ["JSON invalide", ecrire("invalide.json", "{ \"openapi\": \"3.0.3\", "), /JSON invalide/],
    ["YAML à ancre, que le lecteur de l'oracle refuse", ecrire("ancre.yaml", "swagger: \"2.0\"\nhost: &h recette.exemple.tld\nschemes: [https]\npaths:\n  /fiches:\n    get: {}\n"), /ancre/],
    ["version non prise en charge (Swagger 1.2)", ecrire("v12.json", { swaggerVersion: "1.2", apis: [] }), /version non prise en charge/],
    ["définition sans chemin", variante("sans-chemin.json", (d) => { d.paths = {}; }), /sans chemin/],
    ["méthode écrite en majuscules", variante("majuscules.json", (d) => { d.paths["/fiches"].POST = { responses: {} }; }), /clé « POST » inattendue/],
  ]) {
    const { r, lignes } = lancer(chemin);
    ok(refuse(r, lignes, "DAST-OPENAPI-ILLISIBLE") && motif.test(msgs(r)),
      `TF-2853 · ROUGE — ${libelle} → FAIL DAST-OPENAPI-ILLISIBLE qui le dit, rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement, « ${msgs(r).slice(0, 140)} »)`);
  }
  {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--openapi-fichier"], { WEBSEC_DAST_ZAP: ZAP.api, WEBSEC_DAST_SIMULE_TRACE: trace });
    ok(refuse(r, lireTrace(), "DAST-OPENAPI-ILLISIBLE") && /non désignée/.test(msgs(r)), `TF-2853 · ROUGE — --openapi-fichier sans chemin → refus net, rien de lancé (obtenu ${r.verdict}, ${regles(r)})`);
  }
  {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-propre.json"), "--openapi-fichier", DEF], { WEBSEC_DAST_ZAP: ZAP.api, WEBSEC_DAST_SIMULE_TRACE: trace });
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-OPENAPI-USAGE") && lireTrace().length === 0, `TF-2853 · ROUGE — --openapi-fichier avec --rapport : les deux s'excluent, refus net (obtenu ${r.verdict}, ${regles(r)})`);
  }
  // serveurs, chemins et références que le garde-fou ne peut pas rattacher au périmètre
  const SWAGGER = { swagger: "2.0", info: { title: "API de fixture", version: "1.0.0" }, host: "recette.exemple.tld", basePath: "/rest/v1", schemes: ["https"], paths: { "/fiches": { get: { responses: { 200: { description: "les fiches" } } } } } };
  const swagger = (nom, modifier) => { const d = JSON.parse(JSON.stringify(SWAGGER)); modifier(d); return ecrire(nom, d); };
  {
    const { r, lignes } = lancer(swagger("swagger-vert.json", () => {}));
    ok(r.verdict === "PASS" && lignes.length === 1 && r.synthese?.openapi?.version === "2.0" && JSON.stringify(r.synthese.openapi.serveurs) === JSON.stringify(["https://recette.exemple.tld/rest/v1"]),
      `TF-2853 · VERT — Swagger 2.0 en JSON : le serveur se lit de host, basePath et schemes (obtenu ${r.verdict}, ${JSON.stringify(r.synthese?.openapi?.serveurs)})`);
  }
  for (const [libelle, fabriquer, motif] of [
    ["serveur relatif", () => variante("rouge.json", (d) => { d.servers = [{ url: "/rest/v1" }]; }), /« \/rest\/v1 » : URL relative/],
    ["aucun serveur déclaré", () => variante("rouge.json", (d) => { delete d.servers; }), /aucun serveur/],
    ["serveur à variables", () => variante("rouge.json", (d) => { d.servers = [{ url: "https://{hote}/rest/v1", variables: { hote: { default: "recette.exemple.tld" } } }]; }), /variables/],
    ["serveur avec un identifiant dans l'autorité", () => variante("rouge.json", (d) => { d.servers = [{ url: "https://jeton@recette.exemple.tld/rest/v1" }]; }), /autorité/],
    ["serveur avec « \\ » dans l'autorité", () => variante("rouge.json", (d) => { d.servers = [{ url: "https://recette.exemple.tld\\@autre.exemple.tld/rest/v1" }]; }), /autorité/],
    ["serveur d'un chemin hors des cibles", () => variante("rouge.json", (d) => { d.paths["/fiches"].servers = [{ url: "https://autre.exemple.tld/v2" }]; }), /« https:\/\/autre\.exemple\.tld\/v2 »/],
    ["serveur d'une opération hors des cibles", () => variante("rouge.json", (d) => { d.paths["/rpc/compter_fiches"].get.servers = [{ url: "http://recette.exemple.tld/rest/v1" }]; }), /« http:\/\/recette\.exemple\.tld »/],
    ["chemin à segment « .. »", () => variante("rouge.json", (d) => { d.paths["/fiches/../deconnexion"] = { get: { responses: {} } }; }), /segment « \. » ou « \.\. »/],
    ["chemin qui commence par « // »", () => variante("rouge.json", (d) => { d.paths["//autre.exemple.tld/x"] = { get: { responses: {} } }; }), /porte « \/\/ »/],
    ["chemin encodé (%2e)", () => variante("rouge.json", (d) => { d.paths["/%2e%2e/deconnexion"] = { get: { responses: {} } }; }), /« % »/],
    ["référence externe par URL", () => variante("rouge.json", (d) => { d.paths["/fiches"].get.responses["200"].content["application/json"].schema = { $ref: "https://autre.exemple.tld/schemas.json#/Fiches" }; }), /référence « https:\/\/autre\.exemple\.tld\/schemas\.json#\/Fiches »/],
    ["référence externe par fichier", () => variante("rouge.json", (d) => { d.components.schemas.Fiches.items = { $ref: "./schemas.yaml#/Fiche" }; }), /référence « \.\/schemas\.yaml#\/Fiche »/],
    ["élément de chemin par référence", () => variante("rouge.json", (d) => { d.paths["/autres"] = { $ref: "#/components/pathItems/Autres" }; }), /par référence/],
    ["rappels (callbacks)", () => variante("rouge.json", (d) => { d.paths["/fiches"].get.callbacks = { suivi: {} }; }), /rappels/],
    ["webhooks", () => variante("rouge.json", (d) => { d.webhooks = { suivi: { post: { responses: {} } } }; }), /webhooks/],
    ["Swagger 2.0 en http, origine non autorisée", () => swagger("rouge.json", (d) => { d.schemes = ["http"]; }), /« http:\/\/recette\.exemple\.tld »/],
    ["Swagger 2.0 sur un autre hôte", () => swagger("rouge.json", (d) => { d.host = "autre.exemple.tld"; }), /« https:\/\/autre\.exemple\.tld »/],
    ["Swagger 2.0 sans host", () => swagger("rouge.json", (d) => { delete d.host; }), /sans « host »/],
    ["Swagger 2.0 sans schemes", () => swagger("rouge.json", (d) => { delete d.schemes; }), /« schemes »/],
    ["Swagger 2.0, schemes d'une opération hors des cibles", () => swagger("rouge.json", (d) => { d.paths["/fiches"].get.schemes = ["http"]; }), /« http:\/\/recette\.exemple\.tld »/],
  ]) {
    const { r, lignes } = lancer(fabriquer());
    ok(refuse(r, lignes, "DAST-OPENAPI-HORS-PERIMETRE") && motif.test(msgs(r)),
      `TF-2853 · ROUGE — ${libelle} → FAIL DAST-OPENAPI-HORS-PERIMETRE qui le nomme, rien de lancé (obtenu ${r.verdict}, ${lignes.length} lancement, « ${msgs(r).slice(0, 160)} »)`);
  }
  {
    const variable = variante("variable.json", (d) => { d.paths["/fiches/{id}"] = { get: { parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }], responses: { 200: { description: "une fiche" } } } }; });
    const sans = lancer(variable);
    ok(sans.r.verdict === "PASS" && sans.lignes.length === 1 && sans.r.synthese?.openapi?.operations === 4,
      `TF-2853 · VERT — un chemin à segment variable ({id}) est admis quand le mandat ne déclare aucune exclusion : l'origine est fixée par le serveur (obtenu ${sans.r.verdict})`);
    const avec = lancer(variable, { autz: AUTZ_EXCLUSIONS });
    ok(refuse(avec.r, avec.lignes, "DAST-OPENAPI-HORS-PERIMETRE") && /segment variable/.test(msgs(avec.r)) && msgs(avec.r).includes("https://recette.exemple.tld/rest/v1/fiches/{id}"),
      `TF-2853 · ROUGE — le même chemin sous un mandat qui déclare des exclusions : refusé, la valeur de {id} n'est pas connue du garde-fou (obtenu ${avec.r.verdict}, ${avec.lignes.length} lancement)`);
  }
  // ── formes de ZAP : une définition ne se lit que par zap-api-scan, et zap-api-scan ne part que d'une définition ──
  {
    const base = lancer(DEF, { zap: ZAP.baseline });
    ok(base.r.verdict === "SKIP" && aRegle(base.r, "DAST-API-IMPOSSIBLE") && base.lignes.length === 0,
      `TF-2853 · ROUGE — définition fournie et ZAP baseline seul : SKIP DAST-API-IMPOSSIBLE, il partirait de la racine, rien de lancé (obtenu ${base.r.verdict}, ${base.lignes.length} lancement)`);
    const complet = lancer(DEF, { zap: ZAP.complet, autz: AUTZ("autorisation-actif.json"), mode: "actif" });
    ok(complet.r.verdict === "SKIP" && aRegle(complet.r, "DAST-API-IMPOSSIBLE") && complet.lignes.length === 0,
      `TF-2853 · ROUGE — définition fournie et zap-full-scan en actif : SKIP DAST-API-IMPOSSIBLE, rien de lancé (obtenu ${complet.r.verdict}, ${complet.lignes.length} lancement)`);
    const sansDef = lancer(null);
    ok(sansDef.r.verdict === "SKIP" && aRegle(sansDef.r, "DAST-API-IMPOSSIBLE") && sansDef.lignes.length === 0 && /--openapi-fichier/.test(msgs(sansDef.r)),
      `TF-2853 · ROUGE — zap-api-scan sans définition : SKIP qui dit --openapi-fichier, rien de lancé (obtenu ${sansDef.r.verdict}, ${sansDef.lignes.length} lancement)`);
  }
  // ── voie Docker : l'image épinglée lance zap-api-scan.py sur la définition du dossier monté ──
  const zapApiAuPath = spawnSync(process.platform === "win32" ? "where" : "sh", process.platform === "win32" ? ["zap-api-scan.py"] : ["-c", "command -v zap-api-scan.py"], { encoding: "utf8" }).status === 0;
  if (zapApiAuPath) skipNote("TF-2853 · zap-api-scan.py figure dans le PATH de ce poste : la voie Docker simulée ne peut pas être isolée, ses cas ne sont pas joués");
  else {
    const dockerSimule = path.join(dossier, "docker-simule.mjs");
    fs.copyFileSync(AUTZ("docker-simule.mjs"), dockerSimule);
    const IMAGE = (fs.readFileSync(ORACLE_DAST, "utf8").match(/const IMAGE_DEFAUT = "([^"]+)"/) || [])[1];
    const parDocker = (images, mode, autz) => {
      fs.rmSync(trace, { force: true });
      const r = runDast(["--cible", CIBLE_OK, "--autorisation", autz, "--mode", mode, "--openapi-fichier", DEF], {
        WEBSEC_DAST_ZAP: "", WEBSEC_DAST_IMAGE: "", WEBSEC_DAST_DOCKER: dockerSimule, WEBSEC_DAST_SIMULE_IMAGES: images.join(","),
        WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"),
      });
      return { r, run: lireTrace().filter((l) => l.argv[0] === "run") };
    };
    {
      const { r, run } = parDocker([IMAGE], "passif", AUTZ("autorisation-valide.json"));
      const a = (run[0] && run[0].argv) || [];
      const i = a.indexOf(IMAGE);
      const montage = (apres(a, "-v") || "").replace(/:\/zap\/wrk(:\w+)?$/, "");
      ok(r.verdict === "PASS" && run.length === 1 && i > 0 && a[i + 1] === "zap-api-scan.py" && apres(a, "-t") === "definition-openapi.json" && apres(a, "-f") === "openapi"
        && apres(a, "-J") === "zap-rapport.json" && a.includes("-S") && /^-silent /.test(apres(a, "-z") || "") && !/addon(update|install)/i.test(a.join(" ")),
        `TF-2853 · VERT — voie Docker en passif : l'image épinglée lance zap-api-scan.py sur la définition du dossier monté, -f openapi, -S, -silent, aucune mise à jour de module (obtenu ${r.verdict}, « ${a.slice(Math.max(i, 0)).join(" ").slice(0, 200)} »)`);
      ok(Boolean(montage) && fs.existsSync(path.join(montage, "definition-openapi.json"))
        && JSON.stringify(JSON.parse(fs.readFileSync(path.join(montage, "definition-openapi.json"), "utf8"))) === JSON.stringify(lireFixture("openapi-dans-perimetre.json")),
        `TF-2853 · VERT — le dossier monté sur /zap/wrk porte la définition jugée (obtenu « ${montage} »)`);
      ok(r.synthese?.balayage?.forme === "api" && JSON.stringify(r.synthese.balayage.regles_beta?.modules) === JSON.stringify(["pscanrulesBeta"]) && r.synthese.balayage.regles_beta.jouees === false,
        `TF-2853 · VERT — zap-api-scan.py n'installait que pscanrulesBeta : c'est le seul module bêta dit non joué (obtenu ${r.synthese?.balayage?.forme}, ${JSON.stringify(r.synthese?.balayage?.regles_beta?.modules)})`);
    }
    {
      const { r, run } = parDocker([IMAGE], "actif", AUTZ("autorisation-actif.json"));
      const a = (run[0] && run[0].argv) || [];
      ok(r.verdict === "PASS" && run.length === 1 && a.includes("zap-api-scan.py") && apres(a, "-f") === "openapi" && !a.includes("-S") && JSON.stringify(r.synthese?.balayage?.regles_beta?.modules) === JSON.stringify(["pscanrulesBeta"]),
        `TF-2853 · VERT — voie Docker en actif : zap-api-scan.py sans -S (obtenu ${r.verdict}, ${run.length} lancement)`);
    }
    {
      const { r, run } = parDocker([], "passif", AUTZ("autorisation-valide.json"));
      ok(r.verdict === "SKIP" && aRegle(r, "DAST-SKIP") && run.length === 0 && /zap-api-scan\.py absent du PATH/.test(msgs(r)),
        `TF-2853 · ROUGE — ni zap-api-scan.py ni l'image : SKIP qui nomme zap-api-scan.py, rien de lancé (obtenu ${r.verdict}, « ${msgs(r).slice(0, 120)} »)`);
    }
  }
  // ── les alertes des deux scripts que zap-api-scan.py charge depuis l'image ne sont pas « hors image » ──
  // Mesuré le 25/11/2026 avec le vrai ZAP (voie OpenAPI, mode actif, cible de fixture locale) : « A Client Error response code was returned
  // by the server » et « Unexpected Content-Type was returned » étaient signalées DAST-REGLE-HORS-IMAGE, avec une cause fausse.
  {
    const rapport = ecrire("rapport-scripts-api.json", { "@programName": "ZAP", "@version": "2.17.0", site: [{ "@name": CIBLE_OK, "@host": "recette.exemple.tld", "@port": "443", "@ssl": "true", alerts: [
      { alert: "A Client Error response code was returned by the server", riskcode: "0", count: "2" },
      { alert: "Unexpected Content-Type was returned", riskcode: "1", count: "1" },
    ] }] });
    const api = lancer(DEF, { env: { WEBSEC_DAST_SIMULE_RAPPORT: rapport } });
    ok(api.r.verdict === "PASS" && !aRegle(api.r, "DAST-REGLE-HORS-IMAGE")
      && JSON.stringify(api.r.synthese?.zap?.regles_image?.alertes_des_scripts_de_zap_api_scan) === JSON.stringify(["A Client Error response code was returned by the server", "Unexpected Content-Type was returned"]),
      `TF-2853 · VERT — les alertes des scripts que zap-api-scan.py charge depuis l'image ne sont pas dites hors image, et le verdict les nomme (obtenu ${api.r.verdict}, ${regles(api.r)})`);
    const base = lancer(null, { zap: ZAP.baseline, env: { WEBSEC_DAST_SIMULE_RAPPORT: rapport } });
    ok(base.r.verdict === "PASS" && (base.r.findings || []).filter((f) => f.regle === "DAST-REGLE-HORS-IMAGE").length === 2,
      `TF-2853 · TÉMOIN — les mêmes alertes venues de zap-baseline, qui ne charge pas ces scripts, restent signalées hors image (obtenu ${base.r.verdict}, ${regles(base.r)})`);
  }
  // ── le message d'un rapport à 0 site et non_juge disent la nouvelle voie ──
  {
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-vide.json")]);
    const f = (r.findings || []).find((x) => x.regle === "DAST-RIEN-EXPLORE");
    ok(r.verdict === "SKIP" && Boolean(f) && /--openapi-fichier/.test(f.msg) && !/ne passe pas encore/.test(f.msg),
      `TF-2853 · VERT — DAST-RIEN-EXPLORE dit la voie d'une API, --openapi-fichier (obtenu « ${f ? f.msg.slice(-220) : "aucun constat"} »)`);
    const nj = (r.non_juge || []).join(" ");
    ok(/--openapi-fichier/.test(nj) && /--graine/.test(nj) && !/ne passe pas la définition OpenAPI/.test(nj),
      "TF-2853 · VERT — non_juge dit la voie --openapi-fichier, ce qu'elle ne couvre pas, et que la graine d'URL n'est pas prise en charge");
    const { r: vide } = lancer(DEF, { env: { WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-vide.json") } });
    const g = (vide.findings || []).find((x) => x.regle === "DAST-RIEN-EXPLORE");
    ok(vide.verdict === "SKIP" && Boolean(g) && /définition OpenAPI fournie/.test(g.msg),
      `TF-2853 · ROUGE — un balayage parti d'une définition et rendu à 0 site reste un SKIP, qui le dit (obtenu ${vide.verdict}, « ${g ? g.msg.slice(0, 120) : "aucun constat"} »)`);
  }
  fs.rmSync(dossier, { recursive: true, force: true });
}

// ── TF-2884 · un script ZAP natif tire lui-même l'image weekly : le verdict le dit ───────────────────────────
// Classe audit-mute-l-arbre-audite (relevé du 25/11/2026 dans l'image 2.17.0) : lancés hors d'un conteneur, zap-baseline.py, zap-full-scan.py
// et zap-api-scan.py exécutent `docker pull ghcr.io/zaproxy/zaproxy:weekly` (zap_common.start_docker_zap), sans option pour désigner une autre
// image : les règles qui jugent la cible ne sont ni épinglées ni listées par referentiels/zap-regles.json. L'oracle ne peut pas leur passer l'image
// épinglée, il émet donc DAST-IMAGE-MOBILE au verdict, pour les trois scripts. Un ZAP SIMULÉ (zap-simule.mjs, copié sous le nom de chaque script)
// enregistre la ligne de commande : rien n'est émis vers une cible. Le témoin est la voie Docker de l'oracle, qui reste sans constat.
console.log("\nSELF-TEST forge-websec — oracle-dast (TF-2884 : un script ZAP natif tire lui-même l'image weekly)\n");
{
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "websec-dast-natif-weekly-"));
  const simule = (nom) => { const f = path.join(dossier, `${nom}.mjs`); fs.copyFileSync(AUTZ("zap-simule.mjs"), f); return f; };
  const ZAP = { baseline: simule("zap-baseline"), complet: simule("zap-full-scan"), api: simule("zap-api-scan"), rapide: simule("zap") };
  const trace = path.join(dossier, "trace.jsonl");
  const lireTrace = () => (fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  const lancer = (zap, mode, autz, rapport = "rapport-zap-propre.json", definition = null) => {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ(autz), "--mode", mode, ...(definition ? ["--openapi-fichier", definition] : [])], {
      WEBSEC_DAST_ZAP: zap, WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ(rapport),
    });
    return { r, lignes: lireTrace() };
  };
  const constat = (r) => (r.findings || []).find((f) => f.regle === "DAST-IMAGE-MOBILE");
  const dit = (f) => Boolean(f) && /ghcr\.io\/zaproxy\/zaproxy:weekly/.test(f.msg) && /voie Docker de l'oracle/.test(f.msg) && /aucune option|pas d'option/.test(f.msg);
  // ── ROUGE : les trois scripts natifs rendent le constat, avec la cause et le remède ──
  for (const [nom, zap, mode, autz, definition, script] of [
    ["zap-baseline, mode passif", ZAP.baseline, "passif", "autorisation-valide.json", null, "zap-baseline.mjs"],
    ["zap-full-scan, mode actif", ZAP.complet, "actif", "autorisation-actif.json", null, "zap-full-scan.mjs"],
    ["zap-api-scan, mode passif, depuis une définition OpenAPI", ZAP.api, "passif", "autorisation-valide.json", AUTZ("openapi-dans-perimetre.json"), "zap-api-scan.mjs"],
  ]) {
    const { r, lignes } = lancer(zap, mode, autz, "rapport-zap-propre.json", definition);
    const f = constat(r);
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === script && dit(f) && f.sev === "info" && f.msg.includes(script.replace(/\.mjs$/, "")),
      `TF-2884 · ROUGE — ${nom} lancé hors conteneur : DAST-IMAGE-MOBILE au verdict, qui nomme le script, l'image weekly tirée et le remède « voie Docker de l'oracle » (obtenu ${r.verdict}, ${lignes.length} lancement, « ${f ? f.msg.slice(0, 110) : "aucun constat"} »)`);
  }
  // le constat ne change pas la sévérité des alertes : un rapport vulnérable reste FAIL, et porte le constat
  {
    const { r } = lancer(ZAP.baseline, "passif", "autorisation-valide.json", "rapport-zap-vulnerable.json");
    ok(r.verdict === "FAIL" && aRegle(r, "DAST-SEUIL") && dit(constat(r)),
      `TF-2884 · VERT — le constat s'ajoute aux alertes sans les masquer : un rapport vulnérable reste FAIL (DAST-SEUIL) et porte DAST-IMAGE-MOBILE (obtenu ${r.verdict})`);
  }
  // la synthèse consigne l'image tirée par le script ; synthese.balayage.image reste réservée à la voie Docker de l'oracle
  {
    const { r } = lancer(ZAP.baseline, "passif", "autorisation-valide.json");
    const i = r.synthese?.balayage?.image_tiree_par_le_script;
    ok(i && i.reference === "ghcr.io/zaproxy/zaproxy:weekly" && i.epinglee === false && r.synthese.balayage.image === undefined,
      `TF-2884 · VERT — la synthèse consigne l'image que le script tire (reference, epinglee=false), sans annoncer d'image de l'oracle (obtenu ${JSON.stringify(i)})`);
  }
  // ── TÉMOINS : ce qui ne tire pas l'image weekly ne reçoit pas le constat ──
  {
    const { r, lignes } = lancer(ZAP.rapide, "actif", "autorisation-actif.json");
    ok(r.verdict === "PASS" && lignes.length === 1 && lignes[0].script === "zap.mjs" && !constat(r),
      `TF-2884 · TÉMOIN — zap.sh / zap.bat (forme rapide), qui ne passe par aucun script d'image, ne reçoit pas le constat (obtenu ${r.verdict}, ${lignes.length} lancement)`);
  }
  {
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-propre.json")]);
    ok(r.verdict === "PASS" && !constat(r), `TF-2884 · TÉMOIN — un rapport fourni (--rapport) n'a lancé aucun script : pas de constat (obtenu ${r.verdict})`);
  }
  // voie Docker de l'oracle : l'image épinglée, aucun constat
  const auPath = ["zap-baseline.py", "zap-full-scan.py", "zap-api-scan.py"].filter((s) => spawnSync(process.platform === "win32" ? "where" : "sh", process.platform === "win32" ? [s] : ["-c", `command -v ${s}`], { encoding: "utf8" }).status === 0);
  if (auPath.length) skipNote(`TF-2884 · ${auPath.join(", ")} figure dans le PATH de ce poste : la voie Docker simulée ne peut pas être isolée, son témoin n'est pas joué`);
  else {
    const dockerSimule = path.join(dossier, "docker-simule.mjs");
    fs.copyFileSync(AUTZ("docker-simule.mjs"), dockerSimule);
    const IMAGE = (fs.readFileSync(ORACLE_DAST, "utf8").match(/const IMAGE_DEFAUT = "([^"]+)"/) || [])[1];
    for (const [mode, autz] of [["passif", "autorisation-valide.json"], ["actif", "autorisation-actif.json"]]) {
      fs.rmSync(trace, { force: true });
      const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ(autz), "--mode", mode], {
        WEBSEC_DAST_ZAP: "", WEBSEC_DAST_IMAGE: "", WEBSEC_DAST_DOCKER: dockerSimule, WEBSEC_DAST_SIMULE_IMAGES: IMAGE,
        WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"),
      });
      const run = lireTrace().filter((l) => l.argv[0] === "run");
      ok(r.verdict === "PASS" && run.length === 1 && !constat(r) && r.synthese?.balayage?.image?.epinglee === true && r.synthese.balayage.image_tiree_par_le_script === undefined,
        `TF-2884 · TÉMOIN — voie Docker de l'oracle en ${mode} : l'image épinglée lance le script, aucun DAST-IMAGE-MOBILE (obtenu ${r.verdict}, ${run.length} lancement)`);
    }
  }
  // non_juge nomme les trois scripts et le constat
  {
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-propre.json")]);
    const nj = (r.non_juge || []).join(" ");
    ok(/zap-baseline\.py, zap-full-scan\.py et zap-api-scan\.py lancés hors d'un conteneur/.test(nj) && /DAST-IMAGE-MOBILE/.test(nj) && /weekly/.test(nj),
      "TF-2884 · VERT — non_juge nomme les trois scripts natifs, l'image weekly qu'ils tirent et le constat DAST-IMAGE-MOBILE");
  }
  try { fs.rmSync(dossier, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* nettoyage du banc : un verrou Windows passager n'est pas un échec de preuve */ }
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

// TF-2518 · la forme que la table d'usage du README prescrit (`capturer.mjs <url> <capture.json>`) écrit le fichier.
// Avant, le second argument était ignoré : la capture partait sur la sortie standard, le fichier n'existait pas et
// oracle-exposition rendait SKIP « capture introuvable ». ROUGE sur l'ancien code, VERT sur le nouveau ; deux refus propres.
console.log("\nSELF-TEST forge-websec — capturer.mjs (TF-2518 : le fichier se nomme en second argument, comme la table d'usage le prescrit)\n");
{
  const CAPTURER = path.join(HERE, "..", "scripts", "capturer.mjs");
  const origine = http.createServer((req, res) => { res.setHeader("X-Content-Type-Options", "nosniff"); res.end("ok"); });
  await new Promise((r) => origine.listen(0, "127.0.0.1", r));
  const urlOrigine = `http://127.0.0.1:${origine.address().port}/`;
  const tmpCap = fs.mkdtempSync(path.join(os.tmpdir(), "forge-websec-positionnel-"));
  const lancer = (args) => new Promise((resolve) => execFile(process.execPath, [CAPTURER, ...args], { encoding: "utf8", timeout: 30000 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr })));
  try {
    const fichier = path.join(tmpCap, "capture.json");
    const prescrit = await lancer([urlOrigine, fichier]);
    ok(prescrit.code === 0 && fs.existsSync(fichier) && prescrit.stdout === "",
      `ROUGE · la forme prescrite <url> <capture.json> écrit le fichier et ne met rien sur la sortie standard (code ${prescrit.code}, fichier ${fs.existsSync(fichier) ? "présent" : "absent"}, ${prescrit.stdout.length} octet(s) sur la sortie)`);
    let cap = null;
    try { cap = JSON.parse(fs.readFileSync(fichier, "utf8")); } catch { /* le contrôle suivant le dit */ }
    ok(cap?.status === 200 && cap?.headers?.["x-content-type-options"] === "nosniff",
      `VERT · la capture écrite par la forme prescrite est celle de l'origine locale (status ${cap?.status})`);
    const jug = runJson(ORACLE_EXPOSITION, [fichier]);
    ok(jug.verdict !== "SKIP" && jug.verdict !== "ILLISIBLE", `VERT · oracle-exposition lit ce fichier, la suite de la table d'usage tient (verdict ${jug.verdict})`);
    const viaOption = path.join(tmpCap, "option.json");
    const option = await lancer([urlOrigine, "--sortie", viaOption]);
    ok(option.code === 0 && fs.existsSync(viaOption), `VERT · la forme --sortie garde son comportement (code ${option.code})`);
    const memeNom = path.join(tmpCap, "meme.json");
    const identique = await lancer([urlOrigine, memeNom, "--sortie", memeNom]);
    ok(identique.code === 0 && fs.existsSync(memeNom), `VERT · le même fichier nommé deux fois, par position et par --sortie, est accepté (code ${identique.code})`);
    const deux = await lancer([urlOrigine, path.join(tmpCap, "a.json"), "--sortie", path.join(tmpCap, "b.json")]);
    ok(deux.code === 2 && !fs.existsSync(path.join(tmpCap, "a.json")) && !fs.existsSync(path.join(tmpCap, "b.json")),
      `ROUGE · deux fichiers différents (position et --sortie) sont refusés, code 2, aucun fichier écrit (code ${deux.code})`);
    const entrop = await lancer([urlOrigine, path.join(tmpCap, "c.json"), "en-trop"]);
    ok(entrop.code === 2 && !fs.existsSync(path.join(tmpCap, "c.json")), `ROUGE · un troisième argument positionnel est refusé, code 2, aucun fichier écrit (code ${entrop.code})`);
    const delai = await lancer(["--timeout-ms", "20000", urlOrigine]);
    ok(delai.code === 0 && delai.stdout.includes('"status": 200'), `VERT · l'URL se lit même derrière --timeout-ms <n> (code ${delai.code})`);
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

// ── TF-2460 · le référentiel des cas WSTG suit la version et les modes d'oracle-dast ─────────────
// Classe documentation-d-outil-differente-de-sa-sortie : le 12/11/2026, wstg-cas.md disait qu'oracle-dast
// ne lève que ce qu'une passe passive voit, alors que sa version 0.2.0 lance un balayage actif. Le
// référentiel porte maintenant la version d'oracle-dast qu'il décrit (`oracle_dast` du frontmatter) ;
// une version d'oracle qui change sans que le référentiel soit relu fait échouer ce contrôle. Chaque
// ligne de cas qui cite oracle-dast nomme aussi le mode (passif ou actif) qui la lève.
{
  const lire = (...p) => fs.readFileSync(path.join(HERE, "..", ...p), "utf8");
  const sourceDast = fs.readFileSync(ORACLE_DAST, "utf8");
  const versionDast = (sourceDast.match(/const VERSION = "([^"]+)"/) || [])[1];
  const modesDast = ((sourceDast.match(/\[--mode ([a-z|]+)\]/) || [])[1] || "").split("|").filter(Boolean);
  // Rend la liste des défauts d'un texte de référentiel face à la version et aux modes de l'oracle.
  const defautsWstgDast = (texte) => {
    const defauts = [];
    const declaree = (texte.match(/^oracle_dast:\s*"?([0-9][^\s"]*)"?\s*$/m) || [])[1];
    if (!declaree) defauts.push("frontmatter sans `oracle_dast` : le référentiel ne dit pas quelle version d'oracle-dast il décrit");
    else if (declaree !== versionDast) defauts.push(`frontmatter \`oracle_dast: ${declaree}\` ≠ version de l'oracle (${versionDast}) : relire la section du mode actif puis aligner`);
    for (const ligne of texte.split("\n")) {
      if (!/^\|\s*\**WSTG-/.test(ligne)) continue;
      const cellules = ligne.split("|").map((c) => c.trim());
      const outillage = cellules[cellules.length - 2] || "";
      const id = (cellules[1] || "").replace(/\*/g, "");
      if (/oracle-dast/.test(outillage) && !modesDast.some((m) => new RegExp(`\\b${m}\\b`).test(outillage))) {
        defauts.push(`${id} cite oracle-dast sans nommer son mode (${modesDast.join(" | ")})`);
      }
    }
    return defauts;
  };
  ok(versionDast && modesDast.length === 2, `TF-2460 · l'oracle déclare sa version (${versionDast}) et ses deux modes (${modesDast.join(", ")})`);
  const reel = lire("referentiels", "wstg-cas.md");
  const defReel = defautsWstgDast(reel);
  ok(defReel.length === 0, `TF-2460 · VERT — referentiels/wstg-cas.md décrit la version courante d'oracle-dast et nomme un mode à chaque cas qu'il lui confie${defReel.length ? " (défauts : " + defReel.join(" ; ") + ")" : ""}`);
  // `[^\r\n]*` et non `.*` : le fichier peut être lu en CRLF (autocrlf), et `.` ne franchit pas `\r`.
  const sansChamp = reel.replace(/^oracle_dast:[^\r\n]*\r?\n/m, "");
  ok(sansChamp !== reel && defautsWstgDast(sansChamp).some((d) => /sans `oracle_dast`/.test(d)), "TF-2460 · ROUGE — un frontmatter sans `oracle_dast` est refusé (l'état du référentiel avant correction)");
  const perime = reel.replace(/^oracle_dast:.*$/m, "oracle_dast: 0.1.0");
  ok(defautsWstgDast(perime).some((d) => /0\.1\.0/.test(d)), "TF-2460 · ROUGE — une version d'oracle-dast décrite qui n'est plus la courante est refusée");
  const sansMode = reel.replace(/^(\| WSTG-INPV-05 \|.*\| )[^|]*oracle-dast[^|]*\|\s*$/m, "$1oracle-dast |");
  ok(sansMode !== reel && defautsWstgDast(sansMode).some((d) => /WSTG-INPV-05 cite oracle-dast sans nommer son mode/.test(d)), "TF-2460 · ROUGE — un cas confié à oracle-dast sans mode nommé est refusé");
}

// ── TF-2477 · l'image ZAP est épinglée, la mise à jour des modules est coupée, les règles sont listées ─────
// Classe recette-verdict-non-prononcable : le 12/11/2026, un balayage a levé une alerte high (« Source Code
// Disclosure - File Inclusion ») dont aucune extension de l'image n'avait la règle. L'image suivait l'étiquette
// mobile `stable`, et zap-baseline.py / zap-full-scan.py lancent `-addonupdate` puis installent pscanrulesBeta
// et ascanrulesBeta depuis le réseau sauf si `-silent` figure dans -z. Un Docker SIMULÉ (docker-simule.mjs,
// désigné par WEBSEC_DAST_DOCKER) enregistre la ligne de commande et ne lance aucun conteneur.
{
  const source = fs.readFileSync(ORACLE_DAST, "utf8");
  const imageEpinglee = (source.match(/const IMAGE_DEFAUT = "([^"]+)"/) || [])[1] || "";
  const regles = JSON.parse(fs.readFileSync(path.join(HERE, "..", "referentiels", "zap-regles.json"), "utf8"));
  ok(/^ghcr\.io\/zaproxy\/zaproxy@sha256:[0-9a-f]{64}$/.test(imageEpinglee), `TF-2477 · l'image par défaut d'oracle-dast est épinglée par empreinte, pas par étiquette (obtenu « ${imageEpinglee} »)`);
  ok(regles.image && regles.image.reference === imageEpinglee, "TF-2477 · referentiels/zap-regles.json décrit l'image par défaut d'oracle-dast (même référence, même empreinte) : changer l'une sans l'autre est refusé");
  const nbActives = Object.values(regles.actives || {}).flat().length;
  const nbPassives = Object.values(regles.passives || {}).flat().length;
  ok(nbActives >= 40 && nbPassives >= 60 && (regles.modules || []).every((m) => m.versions_presentes.includes(m.version)),
    `TF-2477 · la liste des règles porte des noms actifs (${nbActives}) et passifs (${nbPassives}) et, pour chaque add-on, la version chargée parmi celles de l'image`);

  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "websec-dast-image-"));
  const dockerSimule = path.join(dossier, "docker-simule.mjs");
  fs.copyFileSync(AUTZ("zap-simule.mjs"), path.join(dossier, "zap-baseline.mjs"));
  fs.copyFileSync(FX("dast", "docker-simule.mjs"), dockerSimule);
  const trace = path.join(dossier, "trace.jsonl");
  const zapNatifAuPath = ["zap-baseline.py", "zap-full-scan.py"].some((c) => spawnSync(process.platform === "win32" ? "where" : "sh", process.platform === "win32" ? [c] : ["-c", `command -v ${c}`], { encoding: "utf8" }).status === 0);
  const lancerDocker = (images, env, mode = "passif", autz = "autorisation-valide.json", rapport = "rapport-zap-propre.json") => {
    fs.rmSync(trace, { force: true });
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ(autz), "--mode", mode], {
      WEBSEC_DAST_ZAP: "", WEBSEC_DAST_IMAGE: "", WEBSEC_DAST_DOCKER: dockerSimule, WEBSEC_DAST_SIMULE_IMAGES: images.join(","),
      WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ(rapport), ...(env || {}),
    });
    const lignes = fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
    return { r, run: lignes.filter((l) => l.argv[0] === "run") };
  };
  const optionsZ = (run) => { const a = (run[0] && run[0].argv) || []; const i = a.indexOf("-z"); return i >= 0 ? a[i + 1] : ""; };
  if (zapNatifAuPath) {
    skipNote("TF-2477 · un ZAP natif (zap-baseline.py ou zap-full-scan.py) figure dans le PATH de ce poste : la voie Docker simulée ne peut pas être isolée, ses cas ne sont pas joués");
  } else {
    // sens VERT : l'image épinglée est celle qui part, sans mise à jour de modules
    {
      const { r, run } = lancerDocker([imageEpinglee]);
      const a = (run[0] && run[0].argv) || [];
      ok(r.verdict === "PASS" && run.length === 1 && a.includes(imageEpinglee) && a.includes("zap-baseline.py") && !a.some((x) => /:stable$/.test(x)),
        `TF-2477 · VERT — voie Docker sans réglage : l'image épinglée par empreinte part, une fois, jamais l'étiquette stable (obtenu ${r.verdict}, ${run.length} lancement)`);
      ok(/^-silent( |$)/.test(optionsZ(run)) && r.synthese?.balayage?.image?.epinglee === true && /^coupée/.test(r.synthese?.balayage?.maj_modules),
        "TF-2477 · VERT — `-silent` est passé à ZAP (mise à jour des modules coupée) et le verdict le consigne, image épinglée = oui");
      ok(/^-silent -config 'spider\.processform=false' -config 'spider\.postform=false'$/.test(optionsZ(run)),
        `TF-2498 · VERT — voie Docker en mode passif : -silent puis les deux réglages qui coupent les formulaires, rien d'autre (obtenu « ${optionsZ(run)} »)`);
      // TF-2499 : aucune règle bêta n'est réactivée par le réseau, et le verdict dit ce que -silent retire
      ok(!/addon(update|install)/i.test(a.join(" ")),
        `TF-2499 · VERT — aucune règle n'est réactivée par le réseau : ni -addonupdate ni -addoninstall dans la ligne de commande de l'image (obtenu « ${a.join(" ").slice(0, 200)} »)`);
      const beta = r.synthese?.balayage?.regles_beta;
      ok(beta && beta.jouees === false && JSON.stringify(beta.modules) === JSON.stringify(["pscanrulesBeta"]) && beta.liste_lue === false && beta.reactivees_par_le_reseau === false,
        `TF-2499 · VERT — le verdict du mode passif consigne que pscanrulesBeta n'est pas joué, que sa liste n'a pas été lue et qu'aucune règle n'est réactivée (obtenu ${JSON.stringify(beta)})`);
      const titreRenvoye = (/section « ([^»]+) »/.exec((beta && beta.cas_par_cas) || "") || [])[1];
      ok(Boolean(titreRenvoye) && new RegExp(`^## ${titreRenvoye.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\r?$`, "m").test(fs.readFileSync(path.join(HERE, "..", "referentiels", "wstg-cas.md"), "utf8")),
        `TF-2499 · VERT — la section que le verdict nomme existe dans referentiels/wstg-cas.md (obtenu « ${titreRenvoye} »)`);
      ok(!aRegle(r, "DAST-IMAGE-MOBILE") && !aRegle(r, "DAST-REGLE-HORS-IMAGE") && r.synthese?.zap?.regles_image?.comparees === true,
        "TF-2477 · VERT — image épinglée et alertes toutes listées : ni DAST-IMAGE-MOBILE ni DAST-REGLE-HORS-IMAGE");
    }
    {
      const { r, run } = lancerDocker([imageEpinglee], { WEBSEC_DAST_TEST_ACCES: "Bearer fixture-image" }, "actif", "autorisation-actif-options.json");
      ok(r.verdict === "PASS" && run.length === 1 && run[0].argv.includes("zap-full-scan.py") && /^-silent -config /.test(optionsZ(run)) && optionsZ(run).includes("scanner.delayInMs=200"),
        `TF-2477 · VERT — en mode actif, -silent précède les options du mandat dans -z, qui les porte toujours (obtenu ${r.verdict})`);
      ok(JSON.stringify(r.synthese?.balayage?.regles_beta?.modules) === JSON.stringify(["pscanrulesBeta", "ascanrulesBeta"]) && r.synthese.balayage.regles_beta.jouees === false,
        `TF-2499 · VERT — le verdict du mode actif nomme les deux modules bêta non joués, pscanrulesBeta et ascanrulesBeta (obtenu ${JSON.stringify(r.synthese?.balayage?.regles_beta?.modules)})`);
      ok(!/spider\.(processform|postform)/.test(optionsZ(run)),
        `TF-2498 · le mode actif garde le comportement de ZAP : aucun réglage de formulaire dans -z (obtenu « ${optionsZ(run)} »)`);
    }
    // sens ROUGE : l'étiquette mobile, désignée par l'opérateur, est dite au verdict ; elle n'est jamais le défaut
    {
      const { r, run } = lancerDocker(["ghcr.io/zaproxy/zaproxy:stable"], { WEBSEC_DAST_IMAGE: "ghcr.io/zaproxy/zaproxy:stable" });
      ok(r.verdict === "PASS" && run.length === 1 && aRegle(r, "DAST-IMAGE-MOBILE") && r.synthese?.balayage?.image?.epinglee === false && /^-silent/.test(optionsZ(run)),
        `TF-2477 · ROUGE — une image désignée par l'étiquette stable est dite mobile (DAST-IMAGE-MOBILE) et son identifiant local est consigné, -silent reste passé (obtenu ${r.verdict})`);
    }
    {
      const { r } = lancerDocker(["ghcr.io/zaproxy/zaproxy:2.17.0"], { WEBSEC_DAST_IMAGE: "ghcr.io/zaproxy/zaproxy:2.17.0" });
      ok(r.verdict === "PASS" && !aRegle(r, "DAST-IMAGE-MOBILE") && r.synthese?.balayage?.image?.epinglee === true, "TF-2477 · VERT — une version complète (:2.17.0) vaut épinglage : aucune alerte d'étiquette mobile");
    }
    {
      const { r, run } = lancerDocker(["ghcr.io/zaproxy/zaproxy:stable"]);
      ok(r.verdict === "SKIP" && aRegle(r, "DAST-SKIP") && run.length === 0 && (r.findings || []).some((f) => f.msg.includes(imageEpinglee)),
        `TF-2477 · ROUGE — image épinglée absente du poste alors que stable y est : SKIP qui nomme la référence à tirer, aucun repli sur stable, rien de lancé (obtenu ${r.verdict}, ${run.length} lancement)`);
    }
    // règles : une alerte hors de la liste de l'image est signalée, par exécution comme par rapport fourni
    {
      const { r } = lancerDocker([imageEpinglee], {}, "passif", "autorisation-valide.json", "rapport-zap-regle-levee.json");
      const f = (r.findings || []).find((x) => x.regle === "DAST-REGLE-HORS-IMAGE");
      ok(r.verdict === "FAIL" && aRegle(r, "DAST-SEUIL") && f && /Source Code Disclosure - File Inclusion/.test(f.msg) && /image épinglée ne porte pas cette règle/.test(f.msg)
        && JSON.stringify(r.synthese?.zap?.regles_image?.hors_liste) === JSON.stringify(["Source Code Disclosure - File Inclusion"]),
        `TF-2477 · ROUGE — une règle levée hors de l'image (« Source Code Disclosure - File Inclusion ») est signalée, nommée, et le seuil la juge (obtenu ${r.verdict})`);
    }
    {
      const { r } = lancerDocker([imageEpinglee], {}, "passif", "autorisation-valide.json", "rapport-zap-regle-variante.json");
      ok(r.verdict === "PASS" && !aRegle(r, "DAST-REGLE-HORS-IMAGE") && r.synthese?.zap?.regles_image?.alertes_comparees === 1,
        `TF-2477 · VERT — « Charset Mismatch (Header Versus Meta Content-Type Charset) » est une variante d'une règle listée : non signalée (obtenu ${r.verdict})`);
    }
    // ZAP natif simulé : la mise à jour des modules n'est pas maîtrisée, et le verdict le dit
    {
      fs.rmSync(trace, { force: true });
      const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--mode", "passif"], {
        WEBSEC_DAST_ZAP: path.join(dossier, "zap-baseline.mjs"), WEBSEC_DAST_SIMULE_TRACE: trace, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"),
      });
      ok(r.verdict === "PASS" && /^non maîtrisée/.test(r.synthese?.balayage?.maj_modules) && r.synthese?.balayage?.image === undefined,
        `TF-2477 · ZAP natif simulé : la mise à jour des modules est dite non maîtrisée, aucune image n'est annoncée (obtenu ${r.verdict})`);
      ok(r.synthese?.balayage?.regles_beta?.jouees === "indéterminé" && r.synthese.balayage.regles_beta.liste_lue === false && r.synthese.balayage.regles_beta.modules === undefined,
        `TF-2499 · ZAP natif simulé : le verdict ne prétend pas savoir si des règles bêta ont tourné (« indéterminé »), sans nommer de module (obtenu ${JSON.stringify(r.synthese?.balayage?.regles_beta)})`);
    }
  }
  // rapport fourni : la comparaison a lieu aussi, avec une cause qui ne prétend pas connaître l'image
  {
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-regle-levee.json")]);
    const f = (r.findings || []).find((x) => x.regle === "DAST-REGLE-HORS-IMAGE");
    ok(f && /ne vient pas, ou pas avec certitude, de l'image épinglée/.test(f.msg), "TF-2477 · ROUGE — un rapport fourni (--rapport) qui porte une règle hors liste la signale avec une cause qui ne présume pas de l'image");
    const connu = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-vulnerable.json")]);
    ok(!aRegle(connu, "DAST-REGLE-HORS-IMAGE"), "TF-2477 · VERT — les trois alertes du rapport vulnérable de référence sont des règles de l'image : aucun signal");
  }
  // liste illisible : dite, jamais silencieuse
  {
    const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ("autorisation-valide.json"), "--rapport", AUTZ("rapport-zap-propre.json")], { WEBSEC_DAST_REGLES: path.join(dossier, "absente.json") });
    ok(r.verdict === "PASS" && aRegle(r, "DAST-REGLES-ILLISIBLES") && r.synthese?.zap?.regles_image?.comparees === false,
      `TF-2477 · ROUGE — une liste de règles introuvable est dite (DAST-REGLES-ILLISIBLES), la comparaison n'est pas faite et le verdict ne s'en trouve pas changé (obtenu ${r.verdict})`);
  }
  fs.rmSync(dossier, { recursive: true, force: true });
}

// ── TF-2498 · le mode passif d'oracle-dast ne soumet aucun formulaire ─────────────────────────────────────────
// Classe audit-mute-l-arbre-audite : le 13/11/2026, la passe passive du vrai ZAP a POSTÉ le formulaire de /connexion d'une cible de
// fixture (corps identifiant=ZAP&secret=ZAP) : un mode qui « n'attaque pas » n'était pas en lecture seule. Le banc sert la cible de
// fixture locale (fixtures/dast/cible-passive.mjs, 127.0.0.1, dans un processus à part qui journalise chaque requête) à un ZAP SIMULÉ
// qui joue l'araignée selon les réglages que l'oracle lui passe (fixtures/dast/zap-simule.mjs) : ROUGE si une requête POST atteint
// la cible en mode passif, VERT quand aucune n'arrive alors que la page du formulaire est toujours lue. Le témoin est le mode actif,
// qui garde son comportement : sans lui, un zéro POST ne prouverait pas que le banc sait en voir un.
console.log("\nSELF-TEST forge-websec — oracle-dast (TF-2498 : le mode passif ne soumet aucun formulaire)\n");
{
  const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "websec-dast-formulaire-"));
  const journal = path.join(dossier, "cible.jsonl");
  const cible = spawn(process.execPath, [FX("dast", "cible-passive.mjs"), "--journal", journal], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    const port = await new Promise((resolve, reject) => {
      cible.stdout.once("data", (d) => resolve(JSON.parse(String(d)).port));
      cible.once("error", reject);
      cible.once("exit", (c) => reject(new Error(`cible-passive sortie prématurément (${c})`)));
    });
    const simule = (nom) => { const f = path.join(dossier, `${nom}.mjs`); fs.copyFileSync(AUTZ("zap-simule.mjs"), f); return f; };
    const ZAP = { baseline: simule("zap-baseline"), complet: simule("zap-full-scan") };
    const lancer = (zap, mode, autorisation) => {
      fs.rmSync(journal, { force: true });
      const r = runDast(["--cible", CIBLE_OK, "--autorisation", AUTZ(autorisation), "--mode", mode], {
        WEBSEC_DAST_ZAP: zap, WEBSEC_DAST_SIMULE_ORIGINE: `http://127.0.0.1:${port}`, WEBSEC_DAST_SIMULE_RAPPORT: AUTZ("rapport-zap-propre.json"),
      });
      const requetes = fs.existsSync(journal) ? fs.readFileSync(journal, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
      return { r, requetes, posts: requetes.filter((q) => q.methode === "POST") };
    };
    // témoin : le balayage actif garde le comportement de ZAP, l'araignée envoie le formulaire — le banc sait voir un POST
    const actif = lancer(ZAP.complet, "actif", "autorisation-actif.json");
    ok(actif.r.verdict === "PASS" && actif.posts.length === 1 && actif.posts[0].url === "/connexion" && /identifiant=ZAP/.test(actif.posts[0].corps),
      `TF-2498 · TÉMOIN — le mode actif n'est pas modifié : l'araignée simulée envoie le formulaire, le banc voit ce POST sur /connexion (obtenu ${actif.r.verdict}, ${actif.posts.length} POST)`);
    // ROUGE puis VERT : le mode passif, mêmes pages, même cible
    const passif = lancer(ZAP.baseline, "passif", "autorisation-valide.json");
    ok(passif.r.verdict === "PASS" && passif.posts.length === 0,
      `TF-2498 · ROUGE — en mode passif aucune requête POST n'atteint la cible : l'araignée ne soumet rien (obtenu ${passif.r.verdict}, ${passif.posts.length} POST : ${passif.posts.map((p) => p.url).join(", ") || "aucun"})`);
    ok(passif.requetes.some((q) => q.methode === "GET" && q.url === "/connexion"),
      `TF-2498 · VERT — le formulaire reste LU (GET /connexion) : les règles passives le voient toujours, il n'est seulement pas envoyé (requêtes reçues : ${passif.requetes.map((q) => `${q.methode} ${q.url}`).join(", ")})`);
    ok(/ni traités ni envoyés/.test(passif.r.synthese?.balayage?.formulaires || "") && /spider\.postform=false/.test(passif.r.synthese?.balayage?.formulaires || "") && /réglage par défaut/.test(actif.r.synthese?.balayage?.formulaires || ""),
      `TF-2498 · le verdict consigne le traitement des formulaires de chaque mode (obtenu passif « ${passif.r.synthese?.balayage?.formulaires} »)`);
  } finally {
    cible.kill();
    try { fs.rmSync(dossier, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* nettoyage du banc : un verrou Windows passager n'est pas un échec de preuve */ }
  }
}

// ── TF-2476 · les règles que wstg-cas.md cite pour oracle-dast sont des règles de l'image épinglée ───────────
// Classe oracle-perimetre-de-non-mesure-non-publie : wstg-cas.md ne disait pas, cas par cas, ce que relève le
// mode passif d'oracle-dast (cookies, CORS, jeton CSRF pour SESS-02, CLNT-07 et SESS-05), alors que TF-2460
// l'avait fait pour le mode actif. Chaque nom de règle cité entre « » dans la colonne « Outillage » d'un cas
// confié à oracle-dast se rattache au mot de mode (passif, actif) qui le précède dans la cellule ; il doit
// figurer, avec exactement ce nom, parmi les règles passives (ou actives) de referentiels/zap-regles.json,
// qui décrit l'image épinglée. Un cas confié au mode passif nomme au moins une règle passive.
{
  const lire = (...p) => fs.readFileSync(path.join(HERE, "..", ...p), "utf8");
  const regles = JSON.parse(lire("referentiels", "zap-regles.json"));
  const CAS_PASSIFS_ATTENDUS = ["WSTG-SESS-02", "WSTG-CLNT-07", "WSTG-SESS-05"];
  const defautsReglesDast = (texte, liste) => {
    const defauts = [];
    const passives = new Set(Object.values(liste.passives).flat());
    const actives = new Set(Object.values(liste.actives).flat());
    const tous = new Set([...passives, ...actives, ...Object.values(liste.autres || {}).flat()]);
    const passifsParCas = {};
    for (const ligne of texte.split("\n")) {
      if (!/^\|\s*\**WSTG-/.test(ligne)) continue;
      const cellules = ligne.split("|").map((c) => c.trim());
      const id = (cellules[1] || "").replace(/\*/g, "");
      const outillage = cellules[cellules.length - 2] || "";
      if (!/oracle-dast/.test(outillage)) continue;
      const noms = { passif: [], actif: [] };
      let mode = null;
      for (const m of outillage.matchAll(/\b(passif|actif)\b|«\s*([^»]+?)\s*»/g)) {
        if (m[1]) mode = m[1];
        else if (mode === null) defauts.push(`${id} cite « ${m[2]} » avant d'avoir nommé son mode`);
        else noms[mode].push(m[2]);
      }
      if (/\bpassif\b/.test(outillage) && noms.passif.length === 0) defauts.push(`${id} confie le mode passif à oracle-dast sans nommer la règle passive qui le lève`);
      for (const n of noms.passif) if (!passives.has(n)) defauts.push(`${id} cite « ${n} » en mode passif : ce n'est pas une règle passive de l'image ${liste.image.zap}`);
      for (const n of noms.actif) if (!actives.has(n)) defauts.push(`${id} cite « ${n} » en mode actif : ce n'est pas une règle active de l'image ${liste.image.zap}`);
      passifsParCas[id] = noms.passif;
    }
    for (const id of CAS_PASSIFS_ATTENDUS) {
      if (!(passifsParCas[id] || []).length) defauts.push(`${id} doit citer au moins une règle passive d'oracle-dast : la décision du 13/11/2026 le recense (cookies, CORS, jeton CSRF)`);
    }
    // La section dédiée au mode passif ne cite, entre « », que des règles de l'image.
    const section = (texte.match(/## Ce que le mode passif d'oracle-dast couvre\r?\n([\s\S]*?)(?=\r?\n## )/) || [])[1];
    if (section === undefined) defauts.push("section « Ce que le mode passif d'oracle-dast couvre » absente");
    // un nom coupé par un retour à la ligne du texte reste le même nom : les blancs se normalisent avant la comparaison
    else for (const m of section.matchAll(/«\s*([^»]+?)\s*»/g)) { const nom = m[1].replace(/\s+/g, " "); if (!tous.has(nom)) defauts.push(`la section du mode passif cite « ${nom} » : ce n'est une règle d'aucun add-on listé de l'image`); }
    return defauts;
  };
  const reel = lire("referentiels", "wstg-cas.md");
  const defReel = defautsReglesDast(reel, regles);
  ok(defReel.length === 0, `TF-2476 · VERT — chaque règle que wstg-cas.md cite pour oracle-dast est une règle de l'image épinglée, au bon mode, et SESS-02, CLNT-07 et SESS-05 nomment une règle passive${defReel.length ? " (défauts : " + defReel.join(" ; ") + ")" : ""}`);
  const casPassifs = reel.split("\n").filter((l) => /^\|\s*\**WSTG-/.test(l) && /oracle-dast \(passif/.test(l)).length;
  ok(casPassifs >= 4, `TF-2476 · le référentiel confie ${casPassifs} cas au mode passif d'oracle-dast (les trois de la décision, plus INPV-01)`);

  // ROUGE : le nom cité n'est pas celui de l'image (faute de frappe ou règle retirée)
  const faute = reel.replace("« Cookie No HttpOnly Flag »", "« Cookie Sans HttpOnly »");
  ok(faute !== reel && defautsReglesDast(faute, regles).some((d) => /SESS-02 cite « Cookie Sans HttpOnly » en mode passif/.test(d)), "TF-2476 · ROUGE — un nom de règle passive qui n'est pas celui de l'image est refusé");
  // ROUGE : une règle active citée comme passive
  const melange = reel.replace("« Absence of Anti-CSRF Tokens »", "« SQL Injection »");
  ok(melange !== reel && defautsReglesDast(melange, regles).some((d) => /SESS-05 cite « SQL Injection » en mode passif/.test(d)), "TF-2476 · ROUGE — une règle active citée au mode passif est refusée");
  // ROUGE : l'état d'avant la décision, SESS-05 sans règle passive
  const avant = reel.replace(/^(\| WSTG-SESS-05 \|.*\| )[^|]*\|\s*$/m, "$1manuel |");
  ok(avant !== reel && defautsReglesDast(avant, regles).some((d) => /WSTG-SESS-05 doit citer au moins une règle passive/.test(d)), "TF-2476 · ROUGE — SESS-05 sans règle passive nommée (l'état d'avant) est refusé");
  // ROUGE : un mode passif annoncé sans règle
  const sansRegle = reel.replace("passif : règles « User Controllable HTML Element Attribute (Potential XSS) » et « User Controllable JavaScript Event (XSS) », qui signalent un reflet, exploitation non prouvée", "passif : reflet signalé, exploitation non prouvée");
  ok(sansRegle !== reel && defautsReglesDast(sansRegle, regles).some((d) => /WSTG-INPV-01 confie le mode passif à oracle-dast sans nommer/.test(d)), "TF-2476 · ROUGE — un cas confié au mode passif sans règle nommée est refusé");
  // ROUGE : la règle cesse d'exister dans l'image (la liste est relue), le référentiel qui la cite est refusé
  const listeSansCsrf = JSON.parse(JSON.stringify(regles));
  for (const k of Object.keys(listeSansCsrf.passives)) listeSansCsrf.passives[k] = listeSansCsrf.passives[k].filter((n) => n !== "Absence of Anti-CSRF Tokens");
  ok(defautsReglesDast(reel, listeSansCsrf).some((d) => /SESS-05 cite « Absence of Anti-CSRF Tokens » en mode passif/.test(d)), "TF-2476 · ROUGE — une règle absente de la liste de l'image, citée par le référentiel, est refusée");
  // ROUGE : une règle citée dans la section du mode passif qui n'est d'aucun add-on listé
  const sectionFausse = reel.replace(/(## Ce que le mode passif d'oracle-dast couvre\r?\n)/, "$1\nLa règle « Règle Inventée » ne figure dans aucun add-on.\n");
  ok(sectionFausse !== reel && defautsReglesDast(sectionFausse, regles).some((d) => /section du mode passif cite « Règle Inventée »/.test(d)), "TF-2476 · ROUGE — la section du mode passif qui cite une règle inventée est refusée");
}

// ── TF-2499 · le référentiel dit, cas par cas, ce que la voie Docker ne joue plus depuis -silent ──────────────
// Classe oracle-perimetre-de-non-mesure-non-publie : depuis TF-2477, `-silent` empêche zap-baseline.py et zap-full-scan.py d'installer
// pscanrulesBeta et ascanrulesBeta depuis le réseau ; la couverture que cela retire n'était dite ni cas par cas ni au verdict. La section
// « Ce que la voie Docker ne joue plus depuis -silent » de wstg-cas.md doit nommer CHAQUE cas confié à oracle-dast (l'oubli ne se tait pas),
// avec son mode, le module bêta non joué et la règle retirée constatée ; le verdict, lui, est jugé dans le volet TF-2477 (voie Docker simulée).
{
  const TITRE = "Ce que la voie Docker ne joue plus depuis -silent";
  const cellules = (l) => l.split("|").map((c) => c.trim());
  const modesDe = (texte) => [/\bpassif\b/.test(texte) ? "passif" : null, /\bactif\b/.test(texte) ? "actif" : null].filter(Boolean).join("+");
  const casConfies = (texte) => {
    const m = new Map();
    for (const l of texte.split("\n")) {
      if (!/^\|\s*\**WSTG-/.test(l)) continue;
      const c = cellules(l);
      const outillage = c[c.length - 2] || "";
      if (/oracle-dast/.test(outillage)) m.set(c[1].replace(/\*/g, ""), modesDe(outillage.slice(outillage.indexOf("oracle-dast"))));
    }
    return m;
  };
  const defautsBeta = (texte) => {
    const section = (texte.match(new RegExp(`## ${TITRE}\\r?\\n([\\s\\S]*?)(?=\\r?\\n## |$)`)) || [])[1];
    if (section === undefined) return [`section « ${TITRE} » absente`];
    const d = [];
    const confies = casConfies(texte);
    const dites = new Map(section.split("\n").filter((l) => /^\|\s*WSTG-/.test(l)).map(cellules).map((c) => [c[1], c]));
    for (const [id, modes] of confies) {
      const c = dites.get(id);
      if (!c) { d.push(`${id} est confié à oracle-dast mais la section ne le dit pas`); continue; }
      if (modesDe(c[2]) !== modes) d.push(`${id} : la section dit « ${c[2]} », la colonne Outillage dit « ${modes} »`);
      if (!/pscanrulesBeta|ascanrulesBeta/.test(c[3])) d.push(`${id} : aucun module bêta nommé`);
      if (!c[4]) d.push(`${id} : la règle retirée constatée n'est pas dite`);
    }
    for (const id of dites.keys()) if (!confies.has(id)) d.push(`${id} figure dans la section sans être confié à oracle-dast`);
    if (!/n'a jamais été lue/.test(section)) d.push("la section ne dit pas que la liste des règles bêta n'a jamais été lue");
    return d;
  };
  const reel = fs.readFileSync(path.join(HERE, "..", "referentiels", "wstg-cas.md"), "utf8");
  const defReel = defautsBeta(reel);
  ok(defReel.length === 0 && casConfies(reel).size >= 14,
    `TF-2499 · VERT — la section nomme chacun des ${casConfies(reel).size} cas confiés à oracle-dast, avec son mode, son module bêta et sa règle retirée constatée${defReel.length ? " (défauts : " + defReel.join(" ; ") + ")" : ""}`);
  // ROUGE : un cas confié à oracle-dast omis de la section
  const sansCas = reel.replace(/^\| WSTG-INPV-12 \| actif \|.*\r?\n/m, "");
  ok(sansCas !== reel && defautsBeta(sansCas).some((x) => /WSTG-INPV-12 est confié à oracle-dast mais la section ne le dit pas/.test(x)), "TF-2499 · ROUGE — un cas confié à oracle-dast omis de la section est refusé");
  // ROUGE : un cas confié à oracle-dast après coup, que la section n'a jamais vu (l'oubli de demain)
  const nouveauCas = reel.replace(/^(\| WSTG-CRYP-03 \|.*\| )[^|]*\|\s*$/m, "$1oracle-dast (passif : règle fictive) |");
  ok(nouveauCas !== reel && defautsBeta(nouveauCas).some((x) => /WSTG-CRYP-03 est confié à oracle-dast mais la section ne le dit pas/.test(x)), "TF-2499 · ROUGE — un cas nouvellement confié à oracle-dast sans ligne dans la section est refusé");
  // ROUGE : un module bêta non nommé, une section absente, un mode qui diverge
  const sansModule = reel.replace(/^(\| WSTG-SESS-05 \| passif \| )`pscanrulesBeta`/m, "$1aucun");
  ok(sansModule !== reel && defautsBeta(sansModule).some((x) => /WSTG-SESS-05 : aucun module bêta nommé/.test(x)), "TF-2499 · ROUGE — une ligne sans module bêta nommé est refusée");
  const sansSection = reel.replace(`## ${TITRE}`, "## Autre titre");
  ok(sansSection !== reel && defautsBeta(sansSection).some((x) => /section « .* » absente/.test(x)), "TF-2499 · ROUGE — l'absence de la section est refusée");
  const mauvaisMode = reel.replace(/^(\| WSTG-CLNT-07 \| )passif( \|)/m, "$1actif$2");
  ok(mauvaisMode !== reel && defautsBeta(mauvaisMode).some((x) => /WSTG-CLNT-07 : la section dit « actif »/.test(x)), "TF-2499 · ROUGE — un mode de la section qui diverge de la colonne Outillage est refusé");
}

// ── TF-2490 · le README ne porte aucun compte de recette en dur, et ne dit pas « oracles M-1…M-5 » ───────────
// Le 13/11/2026 le README annonçait 229 PASS pour une recette qui en rendait 236 (puis 277 sur main), et disait le gate
// consommé par des « oracles M-1…M-5 » du pilot, qui sont des étapes de ETAPE-MEP.md exécutées par la session, pas des oracles.
// Un compte recopié à la main périme à chaque cas ajouté : le README renvoie à la dernière ligne de cette sortie.
{
  const defautsReadme = (texte) => {
    const defauts = [];
    for (const m of texte.matchAll(/\b(\d+)\s+(PASS|FAIL|SKIP|cas de self-test)\b/g)) defauts.push(`compte de recette en dur « ${m[0]} »`);
    if (/oracles?\s+M-1/i.test(texte)) defauts.push("les étapes M-1…M-5 du pilot sont dites des oracles");
    return defauts;
  };
  const readme = fs.readFileSync(path.join(HERE, "..", "README.md"), "utf8");
  const defReadme = defautsReadme(readme);
  ok(defReadme.length === 0, `TF-2490 · VERT — le README ne porte ni compte de recette en dur ni « oracles M-1…M-5 »${defReadme.length ? " : " + defReadme.join(" ; ") : ""}`);
  ok(defautsReadme("**prouvé** — 229 PASS, 0 FAIL, 0 SKIP à la dernière exécution").length === 3, "TF-2490 · ROUGE — « 229 PASS, 0 FAIL, 0 SKIP » est refusé (3 comptes en dur)");
  ok(defautsReadme("prouvés par 41 cas de self-test").some((d) => /41 cas de self-test/.test(d)), "TF-2490 · ROUGE — « 41 cas de self-test » est refusé");
  ok(defautsReadme("gate optionnel consommé par les oracles M-1…M-5 du pilot").some((d) => /M-1…M-5/.test(d)), "TF-2490 · ROUGE — « oracles M-1…M-5 du pilot » est refusé");
}

// ── TF-2539 · chaque manifeste vulnérable est une fixture déclarée, et le dépôt n'a aucune dépendance réelle non traitée ──────
// Le 14/11/2026 l'hébergeur signalait 155 alertes de dépendances (dont 18 critiques) sur ce dépôt : toutes portées par les quatre
// manifestes volontairement vulnérables de fixtures/sca/, aucune par une dépendance réelle. Rien ne le disait. fixtures/sca/FIXTURES-VULNERABLES.json
// le déclare (date, motif, épingle, compte relevé) ; ce bloc la tient exacte : un manifeste `*-vulnerable` ajouté sans déclaration, une
// déclaration sans manifeste, une épingle qui a changé, un motif ou une date vides, des comptes qui ne s'additionnent plus, ou un manifeste
// hors fixtures/sca non déclaré parmi les dépendances réelles sont refusés. Le compte de l'hébergeur est rapporté, non rejoué (le self-test ne le contacte pas).
// TF-2579 (D-220 (a), 15/11/2026) : chaque manifeste vulnérable est rangé sous un nom que l'hébergeur ne lit pas (`<nom>.fixture`) et déclare le
// nom sous lequel la recette le rejoue (`rejoue_sous`) ; la liste des noms que l'hébergeur lit est déclarée avec sa source, et un manifeste de
// fixture rangé sous l'un d'eux (le vrai nom repris) est refusé.
{
  const MANIFESTES_VERROU = new Set(["package-lock.json", "requirements.txt", "uv.lock", "poetry.lock", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock"]);
  const estManifeste = (nom) => MANIFESTES_VERROU.has(nom) || nom === "package.json" || nom === "pyproject.toml" || /^requirements.*\.txt$/.test(nom);
  const racineDepot = path.join(HERE, "..");
  const versLire = (...p) => p.join("/");
  // Ce que le disque porte : le texte de chaque fichier des dossiers `*-vulnerable`, et les manifestes hors fixtures/sca.
  const lireDisque = (racine) => {
    const vulnerables = {};
    const dossierSca = path.join(racine, "fixtures", "sca");
    for (const d of fs.existsSync(dossierSca) ? fs.readdirSync(dossierSca, { withFileTypes: true }) : []) {
      if (!d.isDirectory() || !/-vulnerable$/.test(d.name)) continue;
      for (const f of fs.readdirSync(path.join(dossierSca, d.name))) vulnerables[versLire("fixtures", "sca", d.name, f)] = fs.readFileSync(path.join(dossierSca, d.name, f), "utf8");
    }
    const horsFixtures = [];
    const marcher = (dir, rel) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) { if (e.name !== ".git" && e.name !== "node_modules" && r !== "fixtures/sca") marcher(path.join(dir, e.name), r); }
        else if (estManifeste(e.name)) horsFixtures.push(r);
      }
    };
    marcher(racine, "");
    return { vulnerables, horsFixtures: horsFixtures.sort() };
  };
  // Les noms que l'hébergeur lit comme manifeste, tels que la déclaration les porte (une donnée sourcée, pas du code) : noms exacts et motifs.
  const luParHebergeur = (declaration) => {
    const noms = new Set((declaration?.noms_lus_par_hebergeur?.noms || []).map((n) => n.toLowerCase()));
    const motifs = (declaration?.noms_lus_par_hebergeur?.motifs || []).map((m) => new RegExp(m, "i"));
    return (nom) => noms.has(nom.toLowerCase()) || motifs.some((r) => r.test(nom));
  };
  const defautsDeclaration = (declaration, disque) => {
    const d = [];
    const lignes = declaration?.fixtures_vulnerables;
    if (!Array.isArray(lignes)) return ["fixtures_vulnerables absent ou illisible"];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(declaration.declare_le || "")) d.push("declare_le n'est pas une date AAAA-MM-JJ");
    const hebergeur = declaration.noms_lus_par_hebergeur || {};
    if (!Array.isArray(hebergeur.noms) || !hebergeur.noms.length || !String(hebergeur.source || "").trim() || !/^\d{4}-\d{2}-\d{2}$/.test(hebergeur.relevee_le || "")) d.push("noms_lus_par_hebergeur : liste, source ou date de relevé vide");
    const lu = luParHebergeur(declaration);
    const declares = new Map(fichiersDeclares(declaration).map((l) => [l.manifeste, l]));
    for (const m of Object.keys(disque.vulnerables)) {
      if (!declares.has(m)) d.push(`${m} est un manifeste vulnérable non déclaré`);
      if (lu(path.posix.basename(m))) d.push(`${m} est un manifeste de fixture rangé sous un nom que l'hébergeur lit (le ranger sous « ${path.posix.basename(m)}.fixture » et le déclarer avec rejoue_sous)`);
    }
    for (const [m, l] of declares) {
      const texte = disque.vulnerables[m];
      if (texte === undefined) { d.push(`${m} est déclaré mais absent des dossiers *-vulnerable`); continue; }
      if (!String(l.motif || "").trim()) d.push(`${m} : motif vide`);
      if (!String(l.rejoue_sous || "").trim()) d.push(`${m} : rejoue_sous vide (le nom sous lequel la recette le rejoue)`);
      else if (path.posix.basename(m) !== `${l.rejoue_sous}.fixture`) d.push(`${m} : le nom rangé doit être « ${l.rejoue_sous}.fixture » (nom rejoué suivi de .fixture)`);
      if (!lignes.includes(l)) continue; // un compagnon n'a ni épingle ni compte d'alertes : il suit son manifeste
      const { paquet, version } = l.epingle || {};
      const epingle = paquet && version && new RegExp(`${paquet}[\\s\\S]{0,40}(?<![\\d.])${version.replace(/\./g, "\\.")}(?![\\d.])`, "i");
      if (!epingle || !epingle.test(texte)) d.push(`${m} : l'épingle déclarée « ${paquet} ${version} » n'y figure plus`);
    }
    const rel = declaration.releve_hebergeur || {};
    const somme = (cle) => lignes.reduce((s, l) => s + (l.alertes_hebergeur?.[cle] ?? 0), 0);
    if (rel.alertes_ouvertes !== somme("total") + (rel.hors_fixtures ?? 0)) d.push(`alertes : le relevé dit ${rel.alertes_ouvertes}, les fixtures en portent ${somme("total")} et ${rel.hors_fixtures ?? 0} hors fixtures`);
    if (rel.dont_critiques !== somme("critiques")) d.push(`critiques : le relevé dit ${rel.dont_critiques}, les fixtures en portent ${somme("critiques")}`);
    const reelles = declaration.dependances_reelles?.manifestes;
    if (!Array.isArray(reelles)) d.push("dependances_reelles.manifestes absent");
    else {
      for (const m of disque.horsFixtures) if (!reelles.includes(m)) d.push(`${m} est un manifeste hors fixtures/sca, non déclaré parmi les dépendances réelles`);
      for (const m of reelles) if (!disque.horsFixtures.includes(m)) d.push(`${m} est déclaré dépendance réelle mais absent du dépôt`);
    }
    return d;
  };
  const declaration = JSON.parse(fs.readFileSync(FX("sca", "FIXTURES-VULNERABLES.json"), "utf8"));
  const disque = lireDisque(racineDepot);
  const defReel = defautsDeclaration(declaration, disque);
  ok(defReel.length === 0 && Object.keys(disque.vulnerables).length >= 5,
    `TF-2539 · VERT — les ${Object.keys(disque.vulnerables).length} manifestes vulnérables de fixtures/sca sont déclarés (date, motif, épingle, compte relevé, nom rejoué), aucun n'est rangé sous un nom que l'hébergeur lit, et le dépôt ne porte aucune dépendance réelle hors fixtures${defReel.length ? " (défauts : " + defReel.join(" ; ") + ")" : ""}`);
  const copie = (o) => JSON.parse(JSON.stringify(o));
  const disqueCopie = () => ({ vulnerables: { ...disque.vulnerables }, horsFixtures: [...disque.horsFixtures] });
  // ROUGE : un manifeste vulnérable ajouté sans déclaration (l'oubli de demain)
  const avecNouveau = disqueCopie(); avecNouveau.vulnerables["fixtures/sca/go-vulnerable/requirements.txt.fixture"] = "django==1.4\n";
  ok(defautsDeclaration(declaration, avecNouveau).some((x) => /go-vulnerable\/requirements\.txt\.fixture est un manifeste vulnérable non déclaré/.test(x)), "TF-2539 · ROUGE — un manifeste *-vulnerable sans déclaration est refusé");
  // ROUGE : une déclaration sans manifeste
  const sansManifeste = disqueCopie(); delete sansManifeste.vulnerables["fixtures/sca/uv-vulnerable/uv.lock.fixture"];
  ok(defautsDeclaration(declaration, sansManifeste).some((x) => /uv-vulnerable\/uv\.lock\.fixture est déclaré mais absent/.test(x)), "TF-2539 · ROUGE — une déclaration dont le manifeste a disparu est refusée");
  // ROUGE : l'épingle a changé (la fixture n'est plus vulnérable comme déclarée) ; le texte voisin « 1.4.2 » ne vaut pas « 1.4 »
  const autreVersion = disqueCopie(); autreVersion.vulnerables["fixtures/sca/pip-vulnerable/requirements.txt.fixture"] = "django==1.4.2\n";
  ok(defautsDeclaration(declaration, autreVersion).some((x) => /pip-vulnerable\/requirements\.txt\.fixture : l'épingle déclarée « django 1\.4 » n'y figure plus/.test(x)), "TF-2539 · ROUGE — une épingle déclarée que le manifeste ne porte plus est refusée (1.4.2 n'est pas 1.4)");
  // ROUGE : motif vide, date invalide
  const sansMotif = copie(declaration); sansMotif.fixtures_vulnerables[0].motif = "  ";
  ok(defautsDeclaration(sansMotif, disque).some((x) => /npm-vulnerable\/package-lock\.json\.fixture : motif vide/.test(x)), "TF-2539 · ROUGE — une fixture déclarée sans motif est refusée");
  // TF-2579 · ROUGE : une fixture qui reprend son vrai nom (l'hébergeur la relirait comme dépendance) ; VERT une fois rangée sous « .fixture » (le remède du message)
  const deplacer = (o, de, vers) => { o.vulnerables[vers] = o.vulnerables[de]; delete o.vulnerables[de]; return o; };
  for (const [cas, nom] of [["pip-vulnerable", "requirements.txt"], ["uv-vulnerable", "uv.lock"], ["poetry-vulnerable", "poetry.lock"], ["npm-vulnerable", "package-lock.json"], ["npm-vulnerable", "package.json"]]) {
    const reprise = deplacer(disqueCopie(), `fixtures/sca/${cas}/${nom}.fixture`, `fixtures/sca/${cas}/${nom}`);
    ok(defautsDeclaration(declaration, reprise).some((x) => new RegExp(`${cas}/${nom.replace(/\./g, "\\.")} est un manifeste de fixture rangé sous un nom que l'hébergeur lit`).test(x)),
      `TF-2579 · ROUGE — ${cas}/${nom} rangé sous son vrai nom est refusé (l'hébergeur le lirait comme une dépendance du dépôt)`);
    const remede = deplacer(reprise, `fixtures/sca/${cas}/${nom}`, `fixtures/sca/${cas}/${nom}.fixture`);
    ok(defautsDeclaration(declaration, remede).length === 0, `TF-2579 · VERT — ${cas}/${nom} rangé sous « ${nom}.fixture » (le remède que le message propose) est accepté`);
  }
  // TF-2579 · ROUGE : un nom rangé qui n'est pas « nom rejoué + .fixture », un nom rejoué absent, une liste de noms lus sans source
  const autreRejeu = copie(declaration); autreRejeu.fixtures_vulnerables[1].rejoue_sous = "requirements-dev.txt";
  ok(defautsDeclaration(autreRejeu, disque).some((x) => /pip-vulnerable\/requirements\.txt\.fixture : le nom rangé doit être « requirements-dev\.txt\.fixture »/.test(x)), "TF-2579 · ROUGE — un nom rangé qui n'est pas le nom rejoué suivi de .fixture est refusé");
  const sansRejeu = copie(declaration); delete sansRejeu.fixtures_vulnerables[2].rejoue_sous;
  ok(defautsDeclaration(sansRejeu, disque).some((x) => /uv-vulnerable\/uv\.lock\.fixture : rejoue_sous vide/.test(x)), "TF-2579 · ROUGE — une fixture déclarée sans nom rejoué est refusée");
  const sansSource = copie(declaration); sansSource.noms_lus_par_hebergeur.source = " ";
  ok(defautsDeclaration(sansSource, disque).some((x) => /noms_lus_par_hebergeur : liste, source ou date de relevé vide/.test(x)), "TF-2579 · ROUGE — la liste des noms lus par l'hébergeur sans source est refusée");
  const sansDate = copie(declaration); sansDate.declare_le = "hier";
  ok(defautsDeclaration(sansDate, disque).some((x) => /declare_le n'est pas une date/.test(x)), "TF-2539 · ROUGE — une déclaration sans date valide est refusée");
  // ROUGE : les comptes du relevé ne s'additionnent plus
  const mauvaisTotal = copie(declaration); mauvaisTotal.releve_hebergeur.alertes_ouvertes = 156;
  ok(defautsDeclaration(mauvaisTotal, disque).some((x) => /alertes : le relevé dit 156, les fixtures en portent 155/.test(x)), "TF-2539 · ROUGE — un total d'alertes qui n'est pas la somme des fixtures est refusé");
  const mauvaisCritiques = copie(declaration); mauvaisCritiques.releve_hebergeur.dont_critiques = 17;
  ok(defautsDeclaration(mauvaisCritiques, disque).some((x) => /critiques : le relevé dit 17, les fixtures en portent 18/.test(x)), "TF-2539 · ROUGE — un compte de critiques qui n'est pas la somme des fixtures est refusé");
  // ROUGE : une dépendance réelle apparue hors fixtures, non déclarée ; puis VERT une fois déclarée (le remède joué)
  const avecReelle = disqueCopie(); avecReelle.horsFixtures.push("package.json");
  ok(defautsDeclaration(declaration, avecReelle).some((x) => /package\.json est un manifeste hors fixtures\/sca, non déclaré/.test(x)), "TF-2539 · ROUGE — un manifeste réel apparu hors fixtures/sca et non déclaré est refusé");
  const reelleDeclaree = copie(declaration); reelleDeclaree.dependances_reelles.manifestes = ["package.json"];
  ok(defautsDeclaration(reelleDeclaree, avecReelle).length === 0, "TF-2539 · VERT — le même manifeste réel, une fois déclaré parmi les dépendances réelles, est accepté (le remède que le message propose passe)");
  ok(defautsDeclaration(reelleDeclaree, disque).some((x) => /package\.json est déclaré dépendance réelle mais absent du dépôt/.test(x)), "TF-2539 · ROUGE — une dépendance réelle déclarée mais absente du dépôt est refusée");
}

// ── TF-2579 · le rejeu sous le vrai nom : recopié dans un dossier temporaire, jamais dans le dépôt, puis retiré ──────────────
{
  const declaration = JSON.parse(fs.readFileSync(FX("sca", "FIXTURES-VULNERABLES.json"), "utf8"));
  for (const cas of ["pip-vulnerable", "uv-vulnerable", "poetry-vulnerable", "npm-vulnerable"]) {
    const dossier = FXR(cas);
    const attendus = fichiersDeclares(declaration).filter((f) => path.posix.dirname(f.manifeste) === `fixtures/sca/${cas}`);
    ok(attendus.length > 0 && attendus.every((f) => fs.existsSync(path.join(dossier, f.rejoue_sous)) && !fs.existsSync(path.join(dossier, path.posix.basename(f.manifeste)))),
      `TF-2579 · VERT — ${cas} est rejoué sous ${attendus.map((f) => f.rejoue_sous).join(" + ")}, sans copie « .fixture » dans le dossier de rejeu`);
    ok(attendus.every((f) => !fs.existsSync(FX("sca", cas, f.rejoue_sous))) && !path.resolve(dossier).startsWith(path.resolve(HERE, "..")),
      `TF-2579 · VERT — ${cas} : le vrai nom n'est jamais écrit dans le dépôt, le dossier de rejeu est hors de l'arbre`);
  }
  const tous = [...REJEUX]; // ceux des cas SCA ci-dessus et les quatre de ce bloc
  retirerRejeux();
  ok(tous.length >= 4 &&tous.every((d) => !fs.existsSync(d)) && REJEUX.length === 0, `TF-2579 · VERT — les ${tous.length} dossiers de rejeu sont retirés avant le bilan (aucun reste)`);
}

console.log(`\nSelf-test forge-websec : ${pass} PASS, ${echec} FAIL, ${note} SKIP motivé (outillage/réseau du poste, non comptés)`);
process.exit(echec ? 1 : 0);
