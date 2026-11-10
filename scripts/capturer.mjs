#!/usr/bin/env node
// capturer — capture réelle d'une réponse HTTP(S) pour oracle-exposition.mjs.
// NE JUGE RIEN : fetch natif Node (zéro dépendance), écrit le JSON d'entrée attendu par
// l'oracle {url, status, headers, capture_ts}. Les redirections ne sont PAS suivies
// automatiquement (--suivre-redirections pour les suivre) : la configuration de sécurité
// jugée doit être celle de la réponse réellement obtenue, pas d'une destination en aval.
// La VALEUR des cookies posés est caviardée à la capture (TF-2095) : nom et attributs sont conservés.
// Les autres porteurs de jeton le sont aussi (TF-2107) : paramètres de forme jeton de l'URL et de Location,
// Authorization, Proxy-Authorization, Cookie. Le message d'échec ne recopie pas non plus l'URL en clair.
// TF-2133 : Content-Location, Link, Refresh, X-Auth-Token, WWW-Authenticate et les URL imbriquées/encodées aussi.
// TF-2306 : toute URL portée par un en-tête (Location, Report-To, Link, CSP…) perd la valeur de chacun de ses paramètres, par position.
// TF-2390 : l'adresse capturée (champ url) et l'adresse du message d'échec suivent la même règle de position.
// Usage : node capturer.mjs <url> [--sortie <fichier.json>] [--suivre-redirections] [--timeout-ms <n>]
import fs from "node:fs";
import { caviarderSetCookie } from "./caviarder-cookies.mjs";
import { caviarderEnTetes, caviarderUrlEnTete, caviarderUrlsDeValeur } from "./caviarder-jetons.mjs";

const args = process.argv.slice(2);
const url = args.find((a) => !a.startsWith("--"));
const iSortie = args.indexOf("--sortie");
const sortie = iSortie >= 0 ? args[iSortie + 1] : null;
const suivreRedirections = args.includes("--suivre-redirections");
const iTimeout = args.indexOf("--timeout-ms");
const timeoutMs = iTimeout >= 0 ? Number(args[iTimeout + 1]) : 15000;

if (!url) {
  console.error("Usage : node capturer.mjs <url> [--sortie <fichier.json>] [--suivre-redirections] [--timeout-ms <n>]");
  process.exit(2);
}
if (!/^https?:\/\//i.test(url)) {
  console.error(`URL invalide (http:// ou https:// attendu) : ${url}`);
  process.exit(2);
}

const controleur = new AbortController();
const minuteur = setTimeout(() => controleur.abort(), timeoutMs);

try {
  const res = await fetch(url, {
    redirect: suivreRedirections ? "follow" : "manual",
    signal: controleur.signal,
  });
  clearTimeout(minuteur);

  const headers = {};
  for (const [k, v] of res.headers.entries()) {
    if (k.toLowerCase() === "set-cookie") continue; // multi-valeur, traité à part ci-dessous
    headers[k] = v;
  }
  const setCookie = typeof res.headers.getSetCookie === "function"
    ? res.headers.getSetCookie()
    : (res.headers.get("set-cookie") ? [res.headers.get("set-cookie")] : []);
  // TF-2095 : la capture est versionnée avec le produit, la VALEUR d'un cookie (jeton de session ou de
  // formulaire) n'y entre jamais ; nom et attributs restent, ce sont eux que l'oracle juge.
  if (setCookie.length) headers["set-cookie"] = caviarderSetCookie(setCookie);

  const capture = {
    url: caviarderUrlEnTete(url), // TF-2107 : un jeton passé en paramètre d'URL n'entre pas non plus dans la capture ; TF-2390 : par position, comme les en-têtes
    status: res.status,
    headers: caviarderEnTetes(headers), // TF-2107 : Authorization, Proxy-Authorization, Cookie, Location (Set-Cookie : idempotent)
    capture_ts: new Date().toISOString(),
    redirections_suivies: suivreRedirections,
  };
  const json = JSON.stringify(capture, null, 2);
  if (sortie) {
    fs.writeFileSync(sortie, json, "utf8");
    console.error(`capture écrite : ${sortie} (status ${res.status})`);
  } else {
    process.stdout.write(json + "\n");
  }
} catch (e) {
  clearTimeout(minuteur);
  const urlSure = caviarderUrlEnTete(url);
  // TF-2390 : le moteur cite l'adresse EN CLAIR dans certains refus (identifiant « utilisateur:mot-de-passe@ », adresse
  // mal formée) : on la remplace par sa forme caviardée, puis toute autre adresse absolue du message passe par la même règle.
  const motifBrut = e.name === "AbortError" ? `délai dépassé (${timeoutMs}ms)` : String(e.message);
  const motif = caviarderUrlsDeValeur(motifBrut.split(url).join(urlSure));
  console.error(`capture échouée pour ${urlSure} : ${motif}`);
  process.exit(1);
}
