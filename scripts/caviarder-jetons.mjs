// caviarder-jetons — retire les JETONS que portent, hors cookies posés, l'URL et les en-têtes d'une capture (TF-2107).
// Même classe et même principe que caviarder-cookies.mjs (TF-2095) : une capture est versionnée avec le produit,
// donc un jeton en clair dans l'URL capturée, dans Location, dans Authorization, Proxy-Authorization ou Cookie
// y ferait entrer un secret réel. On caviarde avant d'écrire ; le nom, la forme et les paramètres sans jeton restent,
// car oracle-exposition ne juge que les en-têtes de sécurité et le schéma (http/https) de l'URL.
// TF-2133 : Content-Location, Link, Refresh, X-Auth-Token et WWW-Authenticate sont caviardés aussi, et une URL ou une
// liste de paramètres imbriquée dans une valeur (redirect_uri=…%3Fcode%3D…) est décodée avant d'être jugée.
// TF-2306 : dans les URL PORTÉES PAR UN EN-TÊTE (Location, Report-To, Link, CSP…), la valeur de chaque paramètre est
// remplacée par position, sans juger le nom ; seule l'URL capturée elle-même garde le caviardage par forme de nom.
import { CAVIARDE, caviarderSetCookie } from "./caviarder-cookies.mjs";

// Un nom de paramètre est « de forme jeton » s'il est dans la liste exacte ou s'il s'y termine par un mot-jeton.
// Comparaison sur le nom décodé (%5F), en minuscules, sans « - », « _ », « . » : api_key, Api-Key et apiKey se confondent.
// token_type, state, lang, page ne sont pas des jetons : ils restent lisibles.
const NOMS_EXACTS = new Set([
  "token", "code", "key", "apikey", "signature", "sig", "session", "sid", "sessid", "phpsessid", "jsessionid",
  "jwt", "auth", "authorization", "bearer", "password", "passwd", "pwd", "secret", "csrf", "xsrf", "otp",
]);
const SUFFIXES = ["token", "secret", "key", "signature", "password", "session", "sessionid", "jwt"];

export function estNomDeJeton(nom) {
  let n = String(nom);
  try { n = decodeURIComponent(n); } catch { /* nom mal encodé : comparé tel quel */ }
  n = n.toLowerCase().replace(/[-_.\s]/g, "");
  return n !== "" && (NOMS_EXACTS.has(n) || SUFFIXES.some((s) => n.endsWith(s)));
}

// Caviarde la valeur de chaque « nom=valeur » de jeton d'une liste séparée par « & ». Le nom d'un paramètre de
// fragment-route (« #/cb?token=x ») est lu après son dernier « ? » ou « / ».
function caviarderParametres(liste) {
  return liste.split("&").map((p) => {
    const i = p.indexOf("=");
    if (i < 0) return p;
    const nom = p.slice(0, i).replace(/^.*[?/]/, "");
    return estNomDeJeton(nom) ? `${p.slice(0, i)}=${CAVIARDE}` : `${p.slice(0, i + 1)}${caviarderValeurImbriquee(p.slice(i + 1))}`;
  }).join("&");
}

// TF-2133 : la valeur d'un paramètre sans nom de jeton peut elle-même être une URL ou une liste de paramètres,
// souvent percent-encodée (redirect_uri=https%3A%2F%2F…%3Fcode%3D…). On la décode (3 niveaux au plus) AVANT de juger ses
// paramètres, on la caviarde, puis on la ré-encode au même niveau ; le marqueur reste lisible. Une valeur qui ne change
// pas sort telle qu'elle est entrée, octet pour octet (pas de ré-encodage d'une valeur sans jeton).
const MARQUE = CAVIARDE;
function caviarderValeurImbriquee(valeur) {
  let decodee = valeur;
  let niveaux = 0;
  while (niveaux < 3) {
    let suite;
    try { suite = decodeURIComponent(decodee); } catch { break; } // pourcentage mal formé : on s'arrête là
    if (suite === decodee) break;
    decodee = suite;
    niveaux++;
  }
  let caviardee;
  if (/^[a-z][a-z0-9+.-]*:\/\/|^\/|[?#]/i.test(decodee)) caviardee = caviarderUrl(decodee);
  else if (/^[\w.%-]+=[^=]/.test(decodee)) caviardee = caviarderParametres(decodee);
  else return valeur;
  if (caviardee === decodee) return valeur;
  return caviardee.split(MARQUE).map((morceau) => {
    let m = morceau;
    for (let n = 0; n < niveaux; n++) m = encodeURIComponent(m);
    return m;
  }).join(MARQUE);
}

// Une URL, absolue ou relative (Location) : identifiants « user:mot-de-passe@ », paramètres de chemin
// (« ;jsessionid=… »), paramètres de requête et de fragment. Traitement par le texte, sans réécrire l'URL
// (pas de normalisation) : ce qui n'est pas un jeton sort octet pour octet.
export function caviarderUrl(entree, traiterParametres = caviarderParametres) {
  const s = String(entree);
  const iDiese = s.indexOf("#");
  const sansFragment = iDiese >= 0 ? s.slice(0, iDiese) : s;
  const fragment = iDiese >= 0 ? s.slice(iDiese + 1) : null;
  const iQ = sansFragment.indexOf("?");
  const chemin = iQ >= 0 ? sansFragment.slice(0, iQ) : sansFragment;
  const requete = iQ >= 0 ? sansFragment.slice(iQ + 1) : null;
  const cheminSur = chemin
    .replace(/^((?:[a-z][a-z0-9+.-]*:)?\/\/)[^/@]*@/i, `$1${CAVIARDE}@`)
    .replace(/;([^=;/]+)=([^;/]*)/g, (m, nom) => (estNomDeJeton(nom) ? `;${nom}=${CAVIARDE}` : m));
  return cheminSur
    + (requete !== null ? `?${traiterParametres(requete)}` : "")
    + (fragment !== null ? `#${traiterParametres(fragment)}` : "");
}

// TF-2306 : une URL PORTÉE PAR UN EN-TÊTE (Location, Report-To, Link, Reporting-Endpoints, report-uri…) est caviardée
// par POSITION : la valeur de chaque paramètre de requête ou de fragment est remplacée, quel que soit son nom. Le nom
// (`meta`, `s`, `kid`) ne dit pas qu'une valeur est un jeton : le 09/11/2026, un JWT de 684 caractères dans `meta` et la
// signature `s` de Report-To (redirection Cloudflare Access) ont traversé les listes de noms de TF-2107 et TF-2133.
// Restent lisibles : schéma, hôte, chemin et NOMS des paramètres. Un élément sans « = » est un nom (drapeau) et reste ;
// l'échappement JSON de l'esperluette (barre inverse, « u0026 ») sépare comme « & ». Identifiant et paramètres de
// chemin gardent le caviardage par nom.
function caviarderParametresParPosition(liste) {
  return liste.split(/(&|\\u0026)/i).map((p, i) => {
    if (i % 2 === 1) return p; // séparateur conservé tel quel
    const egal = p.indexOf("=");
    return egal < 0 ? p : `${p.slice(0, egal)}=${CAVIARDE}`;
  }).join("");
}
export function caviarderUrlEnTete(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderUrlEnTete(v));
  return caviarderUrl(entree, caviarderParametresParPosition);
}

// Toute valeur d'en-tête qui contient une URL absolue (`schéma://…`) : JSON de Report-To (barres `\/` et
// esperluettes échappées comprises), liste de Reporting-Endpoints, `report-uri` d'une CSP. L'URL s'arrête à un espace, un guillemet,
// `<`, `>` ou une barre inverse isolée ; « ; » et « , » n'y restent que suivis d'un caractère d'URL (le « ; » d'une CSP
// termine, le `;jsessionid=` d'un chemin continue). Le reste de la valeur sort octet pour octet.
const URL_DANS_VALEUR = /[a-z][a-z0-9+.-]*:(?:\/|\\\/){2}(?:\\\/|\\u[0-9a-f]{4}|[^\s"'<>\\;,]|[;,](?=[^\s"'<>\\;,]))+/gi;
export function caviarderUrlsDeValeur(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderUrlsDeValeur(v));
  return String(entree).replace(URL_DANS_VALEUR, (u) => caviarderUrlEnTete(u));
}

// Authorization / Proxy-Authorization : « schéma justificatifs ». Le schéma (Bearer, Basic, Digest…) n'est pas secret
// et reste ; les justificatifs sont remplacés. Une valeur d'un seul mot est un justificatif nu : caviardée entière.
export function caviarderAutorisation(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderAutorisation(v));
  const m = /^\s*([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\s+\S/.exec(String(entree));
  return m ? `${m[1]} ${CAVIARDE}` : CAVIARDE;
}

// Content-Location est une URL ; Link porte des « <URL> » (et un éventuel anchor="URL") ; Refresh « délai; url=URL »
// (le « url= » est facultatif). Les URL passent par caviarderUrl, le reste de la valeur sort tel quel (TF-2133).
export function caviarderLien(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderLien(v));
  return String(entree)
    .replace(/<([^>]*)>/g, (m, u) => `<${caviarderUrlEnTete(u)}>`)
    .replace(/(\banchor\s*=\s*")([^"]*)(")/gi, (m, a, u, f) => `${a}${caviarderUrlEnTete(u)}${f}`);
}

export function caviarderRefresh(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderRefresh(v));
  const s = String(entree);
  const m = /^(\s*[\d.]*\s*[;,]\s*(?:url\s*=\s*)?["']?)([^"']*)(["']?\s*)$/i.exec(s);
  return m ? `${m[1]}${caviarderUrlEnTete(m[2])}${m[3]}` : s;
}

// WWW-Authenticate : défis « schéma jeton68 » ou « schéma nom=valeur, … ». Restent : schémas, realm, error, scope, qop.
// Sont remplacés : un jeton68 nu (Negotiate), la valeur d'un paramètre de nom de jeton ou de défi (nonce, opaque…),
// et l'URL à jeton d'une valeur qui en est une (resource_metadata, error_uri…).
const NOMS_DEFI = new Set(["nonce", "cnonce", "nextnonce", "opaque", "response", "rspauth"]);
export function caviarderDefi(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderDefi(v));
  return String(entree)
    .replace(/(^|,\s*)([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\s+[A-Za-z0-9\-._~+/]+=*(?=\s*(?:,|$))/g, (m, sep, schema) => `${sep}${schema} ${CAVIARDE}`)
    .replace(/([A-Za-z][A-Za-z0-9_.-]*)(\s*=\s*)("(?:[^"\\]|\\.)*"|[^\s,"]*)/g, (m, nom, egal, valeur) => {
      const cite = valeur.startsWith('"');
      const interieur = cite ? valeur.slice(1, -1) : valeur;
      if (estNomDeJeton(nom) || NOMS_DEFI.has(nom.toLowerCase())) return `${nom}${egal}${cite ? `"${CAVIARDE}"` : CAVIARDE}`;
      if (/:\/\/|^\//.test(interieur)) return `${nom}${egal}${cite ? `"${caviarderUrlEnTete(interieur)}"` : caviarderUrlEnTete(interieur)}`;
      return m;
    });
}

// En-tête Cookie : « nom=valeur; nom=valeur ». Chaque paire passe par le caviardage de TF-2095.
export function caviarderCookieRequete(entree) {
  if (Array.isArray(entree)) return entree.map((v) => caviarderCookieRequete(v));
  return String(entree).split(";").map((p) => p.trim()).filter((p) => p !== "").map((p) => caviarderSetCookie(p)).join("; ");
}

// Les en-têtes d'une capture : rend une copie, noms conservés tels quels, comparés sans casse.
export function caviarderEnTetes(headers) {
  const sortie = {};
  for (const [nom, valeur] of Object.entries(headers)) {
    const cle = nom.toLowerCase();
    if (cle === "set-cookie") sortie[nom] = caviarderSetCookie(valeur);
    else if (cle === "cookie") sortie[nom] = caviarderCookieRequete(valeur);
    else if (cle === "authorization" || cle === "proxy-authorization") sortie[nom] = caviarderAutorisation(valeur);
    else if (cle === "location" || cle === "content-location") sortie[nom] = caviarderUrlEnTete(valeur);
    else if (cle === "link") sortie[nom] = caviarderLien(valeur);
    else if (cle === "refresh") sortie[nom] = caviarderRefresh(valeur);
    else if (cle === "x-auth-token") sortie[nom] = Array.isArray(valeur) ? valeur.map(() => CAVIARDE) : CAVIARDE;
    else if (cle === "www-authenticate") sortie[nom] = caviarderDefi(valeur);
    else sortie[nom] = caviarderUrlsDeValeur(valeur); // TF-2306 : toute autre valeur qui porte une URL (Report-To, CSP, Reporting-Endpoints…)
  }
  return sortie;
}
