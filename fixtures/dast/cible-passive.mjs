#!/usr/bin/env node
// cible-passive — cible de fixture de la passe PASSIVE d'oracle-dast (TF-2476). Un petit serveur HTTP LOCAL,
// volontairement négligent côté cookies, CORS et formulaires, que scripts/preuve-dast-passif.mjs balaie par
// le mode passif à la place de tout service tiers. Il n'écoute que sur l'interface demandée (127.0.0.1 par
// défaut) et ne sert que des données synthétiques.
//
// Ce qu'il offre à la lecture passive de ZAP :
//   /               page d'accueil, avec les liens que l'araignée suit ; cookie de session posé sans attribut
//   /connexion      formulaire POST sans jeton anti-CSRF, cookie de session posé sans attribut
//   /api/donnees    réponse JSON qui autorise toute origine (Access-Control-Allow-Origin: *)
//   /api/profil     réponse JSON qui REFLÈTE l'en-tête Origin reçu et autorise les identifiants
// Le journal (un objet JSON par ligne, ajouté au fichier de `--journal`) note l'heure en ms, la méthode, l'URL
// et, pour un POST, les 120 premiers caractères du corps. Mesuré le 13/11/2026 : l'araignée du mode passif
// SOUMET le formulaire de /connexion (un POST, avec des valeurs que ZAP choisit) ; toute requête vers une
// route inconnue est une sonde.
//
// Usage : node cible-passive.mjs --journal <fichier> [--port N] [--hote 127.0.0.1]
// Première ligne de sortie, une fois à l'écoute : {"port":N}
import fs from "node:fs";
import http from "node:http";

const args = process.argv.slice(2);
const opt = (nom, defaut) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : defaut; };
const journal = opt("--journal", null);
const hote = opt("--hote", "127.0.0.1");
const port = Number(opt("--port", "0"));
if (!journal) { console.error("--journal <fichier> est obligatoire"); process.exit(2); }

const serveur = http.createServer((req, rep) => {
  const url = new URL(req.url, "http://cible.local");
  const entree = { t: Date.now(), methode: req.method, url: req.url };
  if (req.method === "POST") {
    let corps = "";
    req.on("data", (d) => { if (corps.length < 120) corps += d; });
    req.on("end", () => fs.appendFileSync(journal, JSON.stringify({ ...entree, corps: corps.slice(0, 120) }) + "\n"));
  } else fs.appendFileSync(journal, JSON.stringify(entree) + "\n");
  const cookie = "sessionid=jeton-de-fixture-0001; Path=/";
  const html = (code, corps, en) => { rep.writeHead(code, { "Content-Type": "text/html; charset=utf-8", ...(en || {}) }); rep.end(corps); };
  const json = (code, corps, en) => { rep.writeHead(code, { "Content-Type": "application/json; charset=utf-8", ...(en || {}) }); rep.end(JSON.stringify(corps)); };
  if (url.pathname === "/") {
    return html(200, '<html><head><title>Cible passive</title></head><body><h1>Cible de fixture passive</h1><a href="/connexion">connexion</a> <a href="/api/donnees">donnees</a> <a href="/api/profil">profil</a></body></html>', { "Set-Cookie": cookie });
  }
  if (url.pathname === "/connexion") {
    return html(200, '<html><body><form method="post" action="/connexion"><input type="text" name="identifiant"><input type="password" name="secret"><input type="submit" value="Entrer"></form></body></html>', { "Set-Cookie": cookie });
  }
  if (url.pathname === "/api/donnees") return json(200, { fiches: [1, 2, 3] }, { "Access-Control-Allow-Origin": "*" });
  if (url.pathname === "/api/profil") {
    const origine = req.headers.origin || "https://exemple.tld";
    return json(200, { profil: "synthetique" }, { "Access-Control-Allow-Origin": origine, "Access-Control-Allow-Credentials": "true", "Vary": "Origin" });
  }
  return html(404, "<html><body>introuvable</body></html>");
});
serveur.listen(port, hote, () => process.stdout.write(JSON.stringify({ port: serveur.address().port }) + "\n"));
