#!/usr/bin/env node
// capturer — capture réelle d'une réponse HTTP(S) pour oracle-exposition.mjs.
// NE JUGE RIEN : fetch natif Node (zéro dépendance), écrit le JSON d'entrée attendu par
// l'oracle {url, status, headers, capture_ts}. Les redirections ne sont PAS suivies
// automatiquement (--suivre-redirections pour les suivre) : la configuration de sécurité
// jugée doit être celle de la réponse réellement obtenue, pas d'une destination en aval.
// Usage : node capturer.mjs <url> [--sortie <fichier.json>] [--suivre-redirections] [--timeout-ms <n>]
import fs from "node:fs";

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
  if (setCookie.length) headers["set-cookie"] = setCookie;

  const capture = {
    url,
    status: res.status,
    headers,
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
  const motif = e.name === "AbortError" ? `délai dépassé (${timeoutMs}ms)` : e.message;
  console.error(`capture échouée pour ${url} : ${motif}`);
  process.exit(1);
}
