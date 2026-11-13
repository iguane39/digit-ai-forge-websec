#!/usr/bin/env node
// preuve-dast-passif — preuve RÉELLE de ce que relève la passe PASSIVE d'oracle-dast (TF-2476), hors self-test :
// le self-test ne lance jamais de scan. Ce banc lance le vrai ZAP (image Docker épinglée par l'oracle, déjà
// présente, jamais téléchargée) en mode passif contre UNE cible : fixtures/dast/cible-passive.mjs, démarrée
// ici sur 127.0.0.1, joignable du conteneur par host.docker.internal. Aucune autre cible n'existe dans ce
// script. Deux lectures :
//   · le JOURNAL de la cible : une passe passive ne lui envoie rien hors de ses routes connues. Elle lui envoie
//     pourtant un POST : l'araignée soumet le formulaire de /connexion (constaté le 13/11/2026). Le mode passif
//     n'attaque pas, mais il n'est pas en lecture seule : un formulaire qui agit se protège par `exclusions` ;
//   · les ALERTES du verdict, nom par nom : ce que ZAP relève sans attaquer. Les seuils sont posés à 0 pour
//     que les alertes de risque bas (cookies) figurent au verdict.
// Il rend, pour chaque cas WSTG que referentiels/wstg-cas.md confie au mode passif (SESS-02, CLNT-07, SESS-05),
// la règle attendue et si elle a été levée : « constaté » ou « non constaté » (un nom de règle lu dans l'image
// ne prouve pas qu'elle lève une alerte).
//
// Usage : node scripts/preuve-dast-passif.mjs [--oracle <oracle-dast.mjs>]
// Le JSON sort sur stdout, l'avancement sur stderr. Exit 0 = assertions tenues · 1 = une échoue · 2 = SKIP motivé.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (nom, defaut) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : defaut; };
const ORACLE = path.resolve(opt("--oracle", path.join(ICI, "..", "oracles", "oracle-dast.mjs")));
const CIBLE = path.join(ICI, "..", "fixtures", "dast", "cible-passive.mjs");
const IMAGE = process.env.WEBSEC_DAST_IMAGE || (fs.readFileSync(ORACLE, "utf8").match(/const IMAGE_DEFAUT = "([^"]+)"/) || [])[1];
const log = (m) => process.stderr.write(`[${new Date().toISOString().slice(11, 19)}] ${m}\n`);

const docker = spawnSync("docker", ["image", "inspect", IMAGE], { encoding: "utf8", timeout: 30000 });
if (docker.error || docker.status !== 0) {
  process.stdout.write(JSON.stringify({ verdict: "SKIP", motif: `Docker ou image ${IMAGE} absents du poste — la preuve réelle ne s'installe rien` }) + "\n");
  process.exit(2);
}

// Les cas confiés au mode passif et la règle de l'image qui doit les lever (noms lus dans referentiels/zap-regles.json).
const CAS = [
  { cas: "WSTG-SESS-02", regle: "Cookie No HttpOnly Flag", ce_que_la_cible_offre: "cookie de session sans HttpOnly" },
  { cas: "WSTG-SESS-02", regle: "Cookie without SameSite Attribute", ce_que_la_cible_offre: "cookie de session sans SameSite" },
  { cas: "WSTG-SESS-02", regle: "Cookie Without Secure Flag", ce_que_la_cible_offre: "cookie de session sans Secure, servi en HTTP" },
  { cas: "WSTG-CLNT-07", regle: "Cross-Domain Misconfiguration", ce_que_la_cible_offre: "Access-Control-Allow-Origin: * et origine reflétée avec identifiants" },
  { cas: "WSTG-SESS-05", regle: "Absence of Anti-CSRF Tokens", ce_que_la_cible_offre: "formulaire POST sans jeton" },
];
const CONNUES = new Set(["/", "/connexion", "/api/donnees", "/api/profil", "/robots.txt", "/sitemap.xml", "/favicon.ico"]);

const travail = fs.mkdtempSync(path.join(os.tmpdir(), "preuve-passif-"));
const journal = path.join(travail, "cible.jsonl");
const cible = spawn(process.execPath, [CIBLE, "--journal", journal], { stdio: ["ignore", "pipe", "inherit"] });
const port = await new Promise((ok, ko) => {
  cible.stdout.once("data", (d) => ok(JSON.parse(String(d)).port));
  cible.once("error", ko);
  cible.once("exit", (c) => ko(new Error(`cible-passive sortie prématurément (${c})`)));
});
const origine = `http://host.docker.internal:${port}`;
const autorisation = path.join(travail, "autorisation.json");
const seuils = path.join(travail, "seuils.json");
fs.writeFileSync(autorisation, JSON.stringify({
  autorisation_ecrite: true, mandat: "TF-2476 — preuve réelle du mode passif, cible de fixture locale", proprietaire: "banc local (propriétaire fictif)",
  environnement: "recette", fenetre: { debut: "2026-01-01", fin: "2099-12-31" }, cibles: [origine],
}, null, 2));
fs.writeFileSync(seuils, JSON.stringify({ high: 0, medium: 0, low: 0 }));
log(`cible passive sur 127.0.0.1:${port}, image ${IMAGE}`);

const debut = Date.now();
const sortie = await new Promise((ok) => {
  const morceaux = [];
  const p = spawn(process.execPath, [ORACLE, "--cible", origine, "--autorisation", autorisation, "--seuils", seuils, "--mode", "passif", "--json-only"],
    { env: { ...process.env, WEBSEC_DAST_AUTORISATION: "" }, stdio: ["ignore", "pipe", "pipe"] });
  p.stdout.on("data", (d) => morceaux.push(d));
  p.stderr.on("data", (d) => morceaux.push(d));
  p.on("exit", (code) => ok({ code, texte: Buffer.concat(morceaux).toString("utf8") }));
});
cible.kill();
const duree = Math.round((Date.now() - debut) / 1000);
let j = null;
try { j = JSON.parse(sortie.texte); } catch { /* dit plus bas */ }
const requetes = fs.existsSync(journal) ? fs.readFileSync(journal, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
fs.rmSync(travail, { recursive: true, force: true });

const niveaux = {};
for (const f of (j && j.findings) || []) { const m = /alerte « (.+?) » de risque (\w+)/.exec(f.msg); if (m) niveaux[m[1]] = m[2]; }
const alertes = Object.keys(niveaux).sort();
const hors = (j && j.synthese && j.synthese.zap && j.synthese.zap.regles_image && j.synthese.zap.regles_image.hors_liste) || [];
const resultat = CAS.map((c) => ({ ...c, constate: alertes.includes(c.regle) }));
const sondes = requetes.filter((r) => !CONNUES.has(r.url.split("?")[0]));
const soumissions = requetes.filter((r) => r.methode === "POST");

const assertions = [];
const ok = (cond, texte) => assertions.push({ ok: Boolean(cond), texte });
ok(j && j.verdict && j.synthese && j.synthese.balayage && j.synthese.balayage.scan === "passif", `le verdict est celui d'un balayage passif (obtenu ${j && j.verdict}, exit ${sortie.code})`);
ok(j && j.synthese && j.synthese.balayage && j.synthese.balayage.image && j.synthese.balayage.image.epinglee === true && /^coupée/.test(j.synthese.balayage.maj_modules), "l'image est épinglée et la mise à jour des modules coupée, consignées au verdict");
ok(requetes.length > 0, `la cible a reçu la passe d'araignée (${requetes.length} requête(s))`);
ok(sondes.length === 0, `aucune sonde : la cible n'a reçu aucune requête hors de ses routes connues (obtenu ${sondes.length} : ${sondes.map((s) => `${s.methode} ${s.url}`).join(", ") || "aucune"})`);
ok(soumissions.every((s) => s.url === "/connexion"), `les seuls POST sont la soumission du formulaire de /connexion par l'araignée (obtenu ${soumissions.length} : ${soumissions.map((s) => `${s.url} corps « ${s.corps} »`).join(" ; ") || "aucun"})`);
ok(hors.length === 0, `toute alerte levée est une règle de l'image épinglée (hors liste : ${hors.join(", ") || "aucune"})`);
for (const c of resultat.filter((r) => r.constate)) ok(true, `${c.cas} : « ${c.regle} » levée (${c.ce_que_la_cible_offre})`);

for (const a of assertions) log(`${a.ok ? "PASS" : "FAIL"} · ${a.texte}`);
const echecs = assertions.filter((a) => !a.ok).length;
process.stdout.write(JSON.stringify({ oracle: ORACLE, image: IMAGE, duree_s: duree, requetes_recues: requetes.length, soumissions_de_formulaire: soumissions, alertes_au_verdict: alertes, niveaux_de_risque: niveaux, cas: resultat, assertions, pass: assertions.length - echecs, fail: echecs }, null, 2) + "\n");
process.exit(echecs ? 1 : 0);
