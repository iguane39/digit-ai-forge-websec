// caviarder-cookies — retire la VALEUR des cookies d'un en-tête Set-Cookie, à la source (TF-2095).
// Une capture est versionnée avec le produit : la valeur d'un cookie (jeton de session, jeton de
// formulaire) y ferait entrer un secret réel dans le dépôt. Le nom et tous les attributs restent,
// car ce sont eux qu'oracle-exposition juge (EX-8, EX-9, EX-10). Même principe que la capture DOM
// de forge-tests : on caviarde avant d'écrire, on ne compte pas sur un nettoyage en aval.
export const CAVIARDE = "[caviardé]";

// Une ligne Set-Cookie : « nom=valeur; Attr; Attr=x ». Seule la valeur du premier segment est remplacée.
// Sans « = », la ligne entière est la valeur d'un cookie sans nom (RFC 6265bis) : nom vide, valeur caviardée.
// Une liste est caviardée ligne à ligne ; toute autre entrée passe par String().
export function caviarderSetCookie(entree) {
  if (Array.isArray(entree)) return entree.map((c) => caviarderSetCookie(c));
  const [paire, ...attributs] = String(entree).split(";").map((s) => s.trim());
  const i = paire.indexOf("=");
  const nom = i >= 0 ? paire.slice(0, i).trim() : "";
  return [`${nom}=${CAVIARDE}`, ...attributs.filter((a) => a !== "")].join("; ");
}
