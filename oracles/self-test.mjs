#!/usr/bin/env node
// self-test.mjs — preuve par le geste (double sens) : rejoue TOUTES les fixtures des trois
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
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
