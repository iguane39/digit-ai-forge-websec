#!/usr/bin/env node
// oracle-exposition — Domaine « Exposition HTTP : configuration de sécurité d'une réponse
// livrée » (déterministe, zéro dépendance, zéro appel réseau — juge une CAPTURE, jamais
// une URL directement). Onze règles EX-1..EX-11 sur un fichier JSON {url, status, headers}
// produit par `scripts/capturer.mjs` (capture réelle) ou par une fixture synthétique :
//   EX-1  Content-Security-Policy absente ;
//   EX-2  CSP présente mais triviale/trop permissive (default-src/script-src *) ;
//   EX-3  Strict-Transport-Security absente sur une réponse HTTPS (non applicable en HTTP) ;
//   EX-4  X-Content-Type-Options absente ou différente de « nosniff » ;
//   EX-5  Anti-clickjacking absent (ni X-Frame-Options valide, ni frame-ancestors en CSP) ;
//   EX-6  Referrer-Policy absente ou réglée sur « unsafe-url » (fuite du referrer complet) ;
//   EX-7  Permissions-Policy absente ;
//   EX-8  cookie posé (Set-Cookie) sans l'attribut Secure ;
//   EX-9  cookie posé sans l'attribut HttpOnly ;
//   EX-10 cookie posé sans l'attribut SameSite déclaré explicitement ;
//   EX-11 fuite de version serveur (Server / X-Powered-By avec un numéro de version).
// Contrat : JSON {oracle, version, artefact, verdict, findings, non_juge} · exit 0/1/2.
// Usage : node oracle-exposition.mjs <capture.json> [--json-only]
import fs from "node:fs";

const VERSION = "0.1.0";
const ORACLE = "oracle-exposition";
const NON_JUGE = [
  "la couche TLS elle-même (version de protocole, suites de chiffrement, validité et chaîne du certificat) — capturer.mjs fait un fetch applicatif, pas un scan TLS",
  "DAST / fuzzing d'endpoints, injection, logique métier — hors périmètre v0 (ZAP consigné en v1, cf. README)",
  "CORS (Access-Control-*) — hors périmètre v0",
  "le corps de la réponse au-delà des en-têtes capturés",
  "disponibilité, latence, comportement runtime au-delà de l'instantané capturé",
  "conformité légale (RGPD, bannière cookies) — hors périmètre technique de cet oracle",
];

const args = process.argv.slice(2);
const cible = args.find((a) => !a.startsWith("--"));
const jsonOnly = args.includes("--json-only");
const F = [];
const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where });

function sortir(verdict, code) {
  process.stdout.write(JSON.stringify({
    oracle: ORACLE, version: VERSION, artefact: cible || null, verdict,
    findings: F.length ? F : [{ sev: "info", regle: "—", msg: "aucun défaut détecté sur les 11 règles EX-1..EX-11", where: cible }],
    non_juge: NON_JUGE,
  }, null, jsonOnly ? 0 : 2));
  process.exit(code);
}

if (!cible || !fs.existsSync(cible)) { add("info", "—", "capture introuvable", String(cible)); sortir("SKIP", 2); }

let capture;
try { capture = JSON.parse(fs.readFileSync(cible, "utf8")); }
catch (e) { add("bloquant", "—", `capture illisible (JSON invalide) : ${e.message}`, cible); sortir("FAIL", 1); }

if (typeof capture !== "object" || capture === null || typeof capture.headers !== "object" || capture.headers === null) {
  add("bloquant", "—", "capture invalide — champ « headers » (objet) attendu, absent ou mal formé", cible);
  sortir("FAIL", 1);
}

const url = typeof capture.url === "string" ? capture.url : "";
const isHttps = /^https:\/\//i.test(url);
const headersBruts = capture.headers;

// Lookup insensible à la casse — les clés HTTP ne sont pas garanties normalisées côté capture.
function get(nom) {
  const cible = nom.toLowerCase();
  for (const k of Object.keys(headersBruts)) {
    if (k.toLowerCase() === cible) return headersBruts[k];
  }
  return undefined;
}

// ── EX-1 / EX-2 · Content-Security-Policy ────────────────────────────────────
const csp = get("content-security-policy");
if (csp === undefined || String(csp).trim() === "") {
  add("bloquant", "EX-1", "Content-Security-Policy absente — aucune restriction déclarée sur les sources de contenu chargées", "headers.content-security-policy");
} else {
  const cspStr = String(csp);
  const trivial = /(default-src|script-src)\s+\*(\s|;|$)/i.test(cspStr) || /^\s*$/.test(cspStr);
  if (trivial) add("majeur", "EX-2", `CSP présente mais triviale/trop permissive (default-src ou script-src en « * ») : ${cspStr.slice(0, 120)}`, "headers.content-security-policy");
}

// ── EX-3 · Strict-Transport-Security (HTTPS uniquement) ──────────────────────
const hsts = get("strict-transport-security");
if (isHttps) {
  if (hsts === undefined || !/max-age\s*=\s*[1-9]/i.test(String(hsts))) {
    add("bloquant", "EX-3", "Strict-Transport-Security absente ou sans max-age positif sur une réponse HTTPS — downgrade HTTP possible", "headers.strict-transport-security");
  }
} else {
  add("info", "EX-3", "HSTS non applicable — URL non-HTTPS (le forcage HTTPS lui-même n'est pas jugé ici)", "url");
}

// ── EX-4 · X-Content-Type-Options ─────────────────────────────────────────────
const xcto = get("x-content-type-options");
if (xcto === undefined || String(xcto).trim().toLowerCase() !== "nosniff") {
  add("majeur", "EX-4", `X-Content-Type-Options absente ou différente de « nosniff » (obtenu : ${xcto === undefined ? "absent" : xcto})`, "headers.x-content-type-options");
}

// ── EX-5 · anti-clickjacking (X-Frame-Options ou frame-ancestors CSP) ────────
const xfo = get("x-frame-options");
const xfoValide = xfo !== undefined && /^(deny|sameorigin)$/i.test(String(xfo).trim());
const frameAncestors = csp !== undefined && /frame-ancestors/i.test(String(csp));
if (!xfoValide && !frameAncestors) {
  add("majeur", "EX-5", "aucune protection anti-clickjacking : ni X-Frame-Options (DENY/SAMEORIGIN) ni frame-ancestors dans la CSP", "headers.x-frame-options");
}

// ── EX-6 · Referrer-Policy ─────────────────────────────────────────────────────
const referrer = get("referrer-policy");
if (referrer === undefined || String(referrer).trim() === "") {
  add("majeur", "EX-6", "Referrer-Policy absente — le comportement par défaut du navigateur régit la fuite du referrer", "headers.referrer-policy");
} else if (/unsafe-url/i.test(String(referrer))) {
  add("majeur", "EX-6", "Referrer-Policy réglée sur « unsafe-url » — le referrer complet (chemin, query string) fuit vers toute destination", "headers.referrer-policy");
}

// ── EX-7 · Permissions-Policy ──────────────────────────────────────────────────
const permPolicy = get("permissions-policy");
if (permPolicy === undefined || String(permPolicy).trim() === "") {
  add("mineur", "EX-7", "Permissions-Policy absente — aucune restriction déclarée sur les API navigateur sensibles (caméra, géoloc, ...)", "headers.permissions-policy");
}

// ── EX-8 / EX-9 / EX-10 · attributs des cookies posés ────────────────────────
let cookies = get("set-cookie");
if (cookies !== undefined) {
  if (!Array.isArray(cookies)) cookies = [cookies];
  for (const c of cookies) {
    const attrs = String(c).split(";").map((s) => s.trim());
    const nomCookie = (attrs[0] || "").split("=")[0] || "(anonyme)";
    const a = (re) => attrs.some((x) => re.test(x));
    if (!a(/^secure$/i)) add("bloquant", "EX-8", `cookie « ${nomCookie} » posé sans l'attribut Secure — transmissible en clair sur HTTP`, "headers.set-cookie");
    if (!a(/^httponly$/i)) add("majeur", "EX-9", `cookie « ${nomCookie} » posé sans l'attribut HttpOnly — accessible en JavaScript (surface XSS)`, "headers.set-cookie");
    if (!a(/^samesite\s*=/i)) add("majeur", "EX-10", `cookie « ${nomCookie} » posé sans l'attribut SameSite déclaré explicitement — exposition CSRF au comportement par défaut du navigateur`, "headers.set-cookie");
  }
}

// ── EX-11 · fuite de version serveur ──────────────────────────────────────────
const versionPattern = /\d+\.\d+(\.\d+)?/;
for (const nomHeader of ["server", "x-powered-by"]) {
  const v = get(nomHeader);
  if (v !== undefined && versionPattern.test(String(v))) {
    add("majeur", "EX-11", `fuite de version via l'en-tête « ${nomHeader} » : ${v}`, `headers.${nomHeader}`);
  }
}

const durs = F.filter((f) => f.sev === "bloquant" || f.sev === "majeur");
sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0);
