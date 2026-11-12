#!/usr/bin/env node
// cible-locale — cible de fixture du balayage dynamique (TF-2444). Un petit serveur HTTP LOCAL,
// volontairement faible, que la preuve réelle d'oracle-dast (scripts/preuve-dast-actif.mjs) balaie à
// la place de tout service tiers. Il n'écoute que sur l'interface demandée (127.0.0.1 par défaut) et
// ne sert que des données synthétiques.
//
// Ce qu'il offre à une sonde, et ce que le journal en garde :
//   /                      page d'accueil avec les liens que l'araignée suit (q=a, id=1)
//   /recherche?q=…         reflète `q` sans l'échapper (faille de réflexion) — appelle une sonde active
//   /donnees?id=…          rend une erreur de type SQL quand `id` contient une apostrophe — idem
//   /prive                 401 sans l'en-tête d'accès attendu, 200 avec
//   /deconnexion           chemin que le mandat exclut : toute requête reçue ici est une exclusion violée
// Le journal (un objet JSON par ligne, ajouté au fichier de `--journal`) note l'heure en ms, la méthode,
// l'URL, et si l'en-tête d'accès attendu était présent. Il ne note JAMAIS la valeur de l'en-tête.
//
// Usage : node cible-locale.mjs --journal <fichier> [--port N] [--hote 127.0.0.1] [--en-tete Authorization]
//         [--valeur <attendue>]    # la valeur attendue peut aussi venir de WEBSEC_CIBLE_VALEUR
// Première ligne de sortie, une fois à l'écoute : {"port":N}
import fs from "node:fs";
import http from "node:http";

const args = process.argv.slice(2);
const opt = (nom, defaut) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : defaut; };
const journal = opt("--journal", null);
const hote = opt("--hote", "127.0.0.1");
const port = Number(opt("--port", "0"));
const enTete = String(opt("--en-tete", "Authorization")).toLowerCase();
const valeurAttendue = opt("--valeur", process.env.WEBSEC_CIBLE_VALEUR || null);
if (!journal) { console.error("--journal <fichier> est obligatoire"); process.exit(2); }

const serveur = http.createServer((req, rep) => {
  const url = new URL(req.url, "http://cible.local");
  const recu = req.headers[enTete];
  const acces = Boolean(valeurAttendue) && recu === valeurAttendue;
  fs.appendFileSync(journal, JSON.stringify({ t: Date.now(), methode: req.method, url: req.url, acces }) + "\n");
  const envoyer = (code, corps) => { rep.writeHead(code, { "Content-Type": "text/html; charset=utf-8" }); rep.end(corps); };
  if (url.pathname === "/") {
    return envoyer(200, '<html><body><h1>Cible de fixture</h1><a href="/recherche?q=a">recherche</a> <a href="/donnees?id=1">donnees</a> <a href="/prive">prive</a> <a href="/deconnexion">deconnexion</a></body></html>');
  }
  if (url.pathname === "/recherche") return envoyer(200, `<html><body><p>Résultats pour ${url.searchParams.get("q") || ""}</p></body></html>`);
  if (url.pathname === "/donnees") {
    const id = url.searchParams.get("id") || "";
    if (id.includes("'")) return envoyer(500, "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>");
    return envoyer(200, `<html><body><p>fiche ${id.replace(/[^0-9a-z]/gi, "")}</p></body></html>`);
  }
  if (url.pathname === "/prive") return acces ? envoyer(200, '<html><body>espace privé <a href="/recherche?q=a">retour</a></body></html>') : envoyer(401, "<html><body>accès refusé</body></html>");
  if (url.pathname === "/deconnexion") return envoyer(200, "<html><body>session fermée</body></html>");
  return envoyer(404, "<html><body>introuvable</body></html>");
});
serveur.listen(port, hote, () => process.stdout.write(JSON.stringify({ port: serveur.address().port }) + "\n"));
