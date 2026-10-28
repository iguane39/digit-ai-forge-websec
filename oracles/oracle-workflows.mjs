#!/usr/bin/env node
// oracle-workflows — Domaine « Durcissement des workflows GitHub Actions » (statique, déterministe,
// zéro dépendance, zéro réseau : lit des fichiers YAML, n'exécute rien, ne contacte jamais GitHub).
// Cinq règles WF-1..WF-5 sur les fichiers `.github/workflows/*.yml|*.yaml` d'un dépôt (TF-2001) :
//   WF-1  permissions du GITHUB_TOKEN absentes (ni au workflow ni au job) ou trop larges
//         (write-all ; écriture posée au niveau du workflow et héritée par un job : mineur) ;
//   WF-2  action ou workflow réutilisable d'un autre dépôt non épinglé par SHA complet (majeur ;
//         mineur pour les organisations de GitHub `actions` et `github`), sauf référence inscrite
//         au fichier de verrouillage `.github/workflows/actions.lock` du dépôt ;
//   WF-3  déclencheur pull_request_target (majeur), et checkout du code de la pull request sous ce
//         déclencheur (bloquant, forme « pwn request » documentée) ;
//   WF-4  expression de contexte non fiable substituée dans un `run:` (github.event.<…>.title,
//         .body, … et github.head_ref), directement ou par une variable `env` qui la porte ;
//   WF-5  secret long passé à une action de connexion dont GitHub documente l'OIDC, dans un job
//         sans `id-token: write`.
// Chaque règle cite la page de docs.github.com qui la fonde : champ `source` de chaque constat et
// tableau `sources[]` de la sortie, pages lues le 28/10/2026.
// Le lecteur YAML est natif (zéro dépendance npm, doctrine de la forge). Il couvre le sous-ensemble
// qu'emploient les workflows et REFUSE le reste (ancres, alias, étiquettes, clés complexes) : le
// fichier est alors dit non jugé et le verdict est FAIL, jamais un PASS silencieux.
// Contrat : JSON {oracle, version, artefact, verdict, findings, synthese, sources, non_juge} · exit 0/1/2.
// Usage : node oracle-workflows.mjs <dépôt | dossier de workflows | fichier.yml> [--json-only]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "0.1.0";
const ORACLE = "oracle-workflows";
const LU_LE = "2026-10-28";
const DOC = "https://docs.github.com/en/actions";
const GUIDES_OIDC = `${DOC}/how-tos/secure-your-work/security-harden-deployments`;

//: Les pages qui fondent chaque règle, lues le 28/10/2026 par l'API de contenu de docs.github.com
//: (`/api/article/body?pathname=…`). Les citations sont courtes et en langue d'origine.
export const SOURCES = [
  { regle: "WF-1", url: `${DOC}/reference/security/secure-use`, lu_le: LU_LE,
    fonde: "« set the default permission for the GITHUB_TOKEN to read access only for repository contents. The permissions can then be increased, as required, for individual jobs »" },
  { regle: "WF-1", url: `${DOC}/reference/workflows-and-actions/workflow-syntax#permissions`, lu_le: LU_LE,
    fonde: "clé permissions au workflow ou au job ; read-all, write-all, {} ; sans clé, le jeton part du réglage par défaut du dépôt, de l'organisation ou de l'entreprise" },
  { regle: "WF-2", url: `${DOC}/reference/security/secure-use#using-third-party-actions`, lu_le: LU_LE,
    fonde: "« Pin actions to a full-length commit SHA » ; « Pin actions to a tag only if you trust the creator »" },
  { regle: "WF-2", url: `${DOC}/how-tos/write-workflows/choose-what-workflows-do/find-and-customize-actions#using-shas`, lu_le: LU_LE,
    fonde: "« We recommend that you use a SHA value when using third-party actions » ; « You must use a commit's full SHA value, and not an abbreviated value »" },
  { regle: "WF-2", url: `${DOC}/concepts/security/workflow-dependency-lockfiles`, lu_le: LU_LE,
    fonde: "verrou `.github/workflows/actions.lock`, préversion publique : « For repositories that adopt a lockfile, SHA pinning within workflow files is no longer necessary »" },
  { regle: "WF-3", url: `${DOC}/reference/security/securely-using-pull_request_target`, lu_le: LU_LE,
    fonde: "politique par défaut qui bloque pull_request_target dans les dépôts publics, en mode évaluation, appliquée le 2 décembre 2026 ; formes « pwn request » : checkout de la tête ou du commit de fusion de la pull request" },
  { regle: "WF-3", url: `${DOC}/concepts/about-actions-policies`, lu_le: LU_LE,
    fonde: "« GitHub has added a default policy that will block the pull_request_target event in public repositories. This policy will be enforced on December 2, 2026 »" },
  { regle: "WF-4", url: `${DOC}/concepts/security/script-injections`, lu_le: LU_LE,
    fonde: "contextes non fiables, qui « typically end with body, default_branch, email, head_ref, label, message, name, page_name, ref, and title »" },
  { regle: "WF-4", url: `${DOC}/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks`, lu_le: LU_LE,
    fonde: "remède documenté : une variable d'environnement intermédiaire, lue par le shell et non substituée dans le script" },
  { regle: "WF-5", url: `${DOC}/concepts/security/openid-connect`, lu_le: LU_LE,
    fonde: "« You won't need to duplicate your cloud credentials as long-lived GitHub secrets »" },
  { regle: "WF-5", url: GUIDES_OIDC, lu_le: LU_LE,
    fonde: "huit guides OIDC par fournisseur ; chacun exige « a permissions setting with id-token: write »" },
];
const SOURCE = (regle) => SOURCES.find((s) => s.regle === regle).url;

//: WF-5 — les actions de connexion pour lesquelles un guide OIDC de docs.github.com existe, lu le
//: 28/10/2026 (une ligne par guide de `security-harden-deployments`). Le guide Docker vise Docker
//: Hub : l'action n'est jugée que sans entrée `registry`, comme dans son exemple.
export const ACTIONS_OIDC = [
  { action: "aws-actions/configure-aws-credentials", fournisseur: "Amazon Web Services", guide: "oidc-in-aws" },
  { action: "azure/login", fournisseur: "Azure", guide: "oidc-in-azure" },
  { action: "docker/login-action", fournisseur: "Docker Hub", guide: "oidc-in-docker", applicable: (w) => w.registry === undefined || w.registry === null },
  { action: "google-github-actions/auth", fournisseur: "Google Cloud Platform", guide: "oidc-in-google-cloud-platform" },
  { action: "hashicorp/vault-action", fournisseur: "HashiCorp Vault", guide: "oidc-in-hashicorp-vault" },
  { action: "jfrog/setup-jfrog-cli", fournisseur: "JFrog", guide: "oidc-in-jfrog" },
  { action: "octopusdeploy/login", fournisseur: "Octopus Deploy", guide: "oidc-in-octopus-deploy" },
  { action: "pypa/gh-action-pypi-publish", fournisseur: "PyPI", guide: "oidc-in-pypi" },
];

//: WF-4 — les fins de nom que la page « Script injections » donne pour les contextes non fiables.
export const SUFFIXES_NON_FIABLES = ["body", "default_branch", "email", "head_ref", "label", "message", "name", "page_name", "ref", "title"];

//: WF-2 — les organisations de GitHub lui-même : une étiquette y est relevée en mineur, la page
//: n'admettant l'étiquette que si l'on fait confiance au créateur.
const ORGANISATIONS_GITHUB = new Set(["actions", "github"]);

const NON_JUGE = [
  "la visibilité du dépôt et les politiques Actions du dépôt ou de l'organisation : la politique par défaut sur pull_request_target ne vise que les dépôts publics, l'oracle le dit sans le voir",
  "les permissions par défaut du GITHUB_TOKEN réglées hors fichier (dépôt, organisation, entreprise) : une clé permissions absente est relevée, la valeur qui s'appliquera n'est pas lue",
  "la confiance dans le créateur d'une action, que la page laisse au jugement humain : l'oracle ne la présume que pour les organisations actions et github (sévérité mineure)",
  "les images docker:// (épinglage par empreinte), les actions composites et les fichiers action.yml du dépôt, les dépendances transitives des actions",
  "les injections hors run: (entrée script d'actions/github-script, entrées d'actions), les sorties d'étapes steps.*.outputs, les entrées inputs.*, et les propriétés github.ref, github.ref_name et github.base_ref ; une expression qui ne rend qu'un booléen (contains(…)) sur un contexte non fiable est comptée",
  "la liste des fins de nom non fiables est celle que la page donne comme « typique » : un nom sûr qui finit pareil (github.event.repository.name) est compté, un nom non fiable qui finit autrement ne l'est pas",
  "les secrets longs passés hors des huit actions de connexion listées (variables d'environnement d'un CLI, secrets: inherit), et une étape qui a id-token: write mais passe aussi un secret",
  "sous pull_request_target, l'exécution du code de la pull request hors actions/checkout (git fetch, gh pr checkout, artefact téléchargé) et les déclencheurs workflow_run ou issue_comment qui font de même",
  "les runners auto-hébergés, CODEOWNERS, Dependabot, la protection des branches et des environnements",
  "la validité du fichier au sens de GitHub : le lecteur YAML de l'oracle couvre le sous-ensemble employé par les workflows et refuse ancres, alias, étiquettes et clés complexes",
  "le fichier de verrouillage est en préversion publique (forme `version: 'v0.0.2'` lue le 28/10/2026) : son format peut changer",
];

// ═══ Lecteur YAML natif ═══════════════════════════════════════════════════════════════════════
// Sous-ensemble : mappages et séquences en bloc, scalaires simples, entre guillemets simples ou
// doubles (y compris sur plusieurs lignes), blocs littéraux « | » et pliés « > » avec indicateurs,
// collections en flux [ ] et { }, commentaires, marqueur de document. Tout scalaire est rendu en
// chaîne (aucune conversion de type), une valeur vide en null. Les numéros de ligne des clés et des
// éléments sont gardés à part (WeakMap) pour localiser les constats.

export class ErreurYaml extends Error {
  constructor(message, ligne) { super(message); this.ligne = ligne; }
}

export function lireYaml(texte) {
  const L = String(texte).replace(/^\uFEFF/, "").split(/\r?\n/);
  const N = L.length;
  const lignes = new WeakMap();
  let i = 0;

  const indent = (s) => { let k = 0; while (k < s.length && s[k] === " ") k++; return k; };
  const vide = (s) => /^\s*(#.*)?$/.test(s);
  const erreur = (message, idx = i) => { throw new ErreurYaml(message, Math.min(idx, N - 1) + 1); };
  const estTiret = (c) => c === "-" || c.startsWith("- ");
  const sauter = () => { while (i < N && vide(L[i])) i++; };
  const marquer = (objet, ligne) => { const m = { __ligne: ligne }; lignes.set(objet, m); return m; };
  const refuserSyntaxe = (c, idx) => {
    if (c[0] === "&") erreur("ancre YAML (&) non prise en charge par le lecteur de l'oracle", idx);
    if (c[0] === "*") erreur("alias YAML (*) non pris en charge par le lecteur de l'oracle", idx);
    if (c[0] === "!") erreur("étiquette YAML (!) non prise en charge par le lecteur de l'oracle", idx);
    if (c[0] === "?" && (c.length === 1 || c[1] === " ")) erreur("clé complexe YAML (?) non prise en charge par le lecteur de l'oracle", idx);
    if (c[0] === "%" || c[0] === "@" || c[0] === "`") erreur(`caractère réservé « ${c[0]} » en tête de valeur`, idx);
  };

  // Sépare « clé: reste » ; null si la ligne n'est pas une entrée de mappage.
  function separerCle(c) {
    if (c === "" || c[0] === "#" || estTiret(c)) return null;
    if (c[0] === '"' || c[0] === "'") {
      const q = c[0];
      let p = 1, cle = "";
      while (p < c.length) {
        const ch = c[p];
        if (q === "'" && ch === "'") { if (c[p + 1] === "'") { cle += "'"; p += 2; continue; } break; }
        if (q === '"' && ch === "\\") { cle += c[p + 1] ?? ""; p += 2; continue; }
        if (q === '"' && ch === '"') break;
        cle += ch; p++;
      }
      if (p >= c.length) return null;
      const apres = c.slice(p + 1);
      const m = /^[ \t]*:(?=[ \t]|$)/.exec(apres);
      return m ? { cle, reste: apres.slice(m[0].length) } : null;
    }
    if (/^[\[{&*!|>%@`]/.test(c)) return null;
    for (let p = 0; p < c.length; p++) {
      const ch = c[p];
      if (ch === "#" && p > 0 && /\s/.test(c[p - 1])) return null;
      if (ch === ":" && (p + 1 === c.length || c[p + 1] === " " || c[p + 1] === "\t")) {
        const cle = c.slice(0, p).trim();
        return cle === "" ? null : { cle, reste: c.slice(p + 1) };
      }
    }
    return null;
  }

  function noeud(ind) {
    const c = L[i].slice(ind);
    if (c[0] === "\t") erreur("tabulation dans l'indentation (interdite en YAML)");
    if (estTiret(c)) return sequence(ind);
    if (c[0] === "?" && (c.length === 1 || c[1] === " ")) refuserSyntaxe(c, i);
    if (separerCle(c)) return mappage(ind);
    const idx = i;
    i++;
    return valeur(c, ind - 1, idx, false);
  }

  function mappage(ind) {
    const objet = {};
    const m = marquer(objet, i + 1);
    for (;;) {
      sauter();
      if (i >= N) break;
      const s = L[i];
      const k = indent(s);
      if (k < ind) break;
      if (/^(---|\.\.\.)(\s|$)/.test(s)) break;
      if (k > ind) erreur(`indentation inattendue (${k} espaces là où ${ind} sont attendus)`);
      const c = s.slice(ind);
      if (c[0] === "\t") erreur("tabulation dans l'indentation (interdite en YAML)");
      if (estTiret(c)) break; // séquence au niveau du parent : elle appartient à l'appelant
      refuserSyntaxe(c, i);
      const sc = separerCle(c);
      if (!sc) erreur(`ligne qui n'est ni une clé ni un élément de liste : « ${c.slice(0, 60)} »`);
      if (sc.cle === "<<") erreur("clé de fusion YAML (<<) non prise en charge par le lecteur de l'oracle");
      if (Object.prototype.hasOwnProperty.call(objet, sc.cle)) erreur(`clé « ${sc.cle} » définie deux fois`);
      const idx = i;
      i++;
      objet[sc.cle] = valeur(sc.reste, ind, idx, true);
      m[sc.cle] = idx + 1;
    }
    return objet;
  }

  function sequence(ind) {
    const tableau = [];
    const m = marquer(tableau, i + 1);
    for (;;) {
      sauter();
      if (i >= N) break;
      const s = L[i];
      const k = indent(s);
      if (k < ind) break;
      if (/^(---|\.\.\.)(\s|$)/.test(s)) break;
      if (k > ind) erreur(`indentation inattendue dans une liste (${k} espaces là où ${ind} sont attendus)`);
      const c = s.slice(ind);
      if (!estTiret(c)) break;
      const idx = i;
      const apresTiret = c.slice(1);
      const espaces = apresTiret.length - apresTiret.replace(/^ +/, "").length;
      const contenu = apresTiret.slice(espaces);
      let v;
      if (vide(contenu)) {
        i++;
        v = valeur("", ind, idx, false);
      } else if (estTiret(contenu) || (!/^[&*!?]/.test(contenu) && separerCle(contenu))) {
        // élément structuré qui commence sur la ligne du tiret : la ligne est ré-indentée à la
        // colonne de son contenu, et lue comme un nœud à cette colonne
        L[i] = " ".repeat(ind + 1 + espaces) + contenu;
        v = noeud(ind + 1 + espaces);
      } else {
        i++;
        v = valeur(contenu, ind, idx, false);
      }
      tableau.push(v);
      m[tableau.length - 1] = idx + 1;
    }
    return tableau;
  }

  // Valeur d'une clé ou d'un élément : `reste` est le texte sur la ligne `idx` (déjà passée).
  function valeur(reste, indParent, idx, seqMemeNiveau) {
    const r = reste.replace(/^[ \t]+/, "");
    if (r === "" || r[0] === "#") {
      sauter();
      if (i >= N) return null;
      const k = indent(L[i]);
      const c = L[i].slice(k);
      if (k > indParent && !/^(---|\.\.\.)(\s|$)/.test(L[i])) return noeud(k);
      if (seqMemeNiveau && k === indParent && estTiret(c)) return sequence(indParent);
      return null;
    }
    refuserSyntaxe(r, idx);
    if (r[0] === "|" || r[0] === ">") return blocScalaire(r, indParent, idx);
    if (r[0] === "[" || r[0] === "{") return flux(r, idx);
    if (r[0] === '"' || r[0] === "'") return guillemets(r, idx);
    return simple(r, indParent, idx);
  }

  function couperCommentaire(t) {
    for (let p = 0; p < t.length; p++) if (t[p] === "#" && (p === 0 || /\s/.test(t[p - 1]))) return t.slice(0, p);
    return t;
  }

  function simple(r, indParent, idx) {
    const morceaux = [couperCommentaire(r).trim()];
    // continuation d'un scalaire simple sur les lignes plus indentées que son parent
    for (;;) {
      let j = i;
      while (j < N && /^\s*$/.test(L[j])) j++;
      if (j >= N) break;
      const k = indent(L[j]);
      const c = L[j].slice(k);
      if (k <= indParent || c[0] === "#") break;
      if (separerCle(c)) erreur("clé de mappage dans la suite d'un scalaire simple (valeur mal indentée)", j);
      morceaux.push(j > i ? "\n".repeat(j - i) : " ");
      morceaux.push(couperCommentaire(c).trim());
      i = j + 1;
    }
    return morceaux.join("").replace(/ \n/g, "\n").replace(/\n /g, "\n");
  }

  function guillemets(r, idx) {
    const q = r[0];
    let tampon = r.slice(1), p = 0, res = "", jointure = null;
    for (;;) {
      if (p >= tampon.length) {
        // fin de ligne sans guillemet fermant : la chaîne continue à la ligne suivante
        if (i >= N) erreur("chaîne entre guillemets jamais fermée", idx);
        const suivante = L[i]; i++;
        if (jointure === "sans-espace") { res = res.replace(/[ \t]+$/, ""); }
        else {
          res = res.replace(/[ \t]+$/, "");
          if (/^\s*$/.test(suivante)) { res += "\n"; tampon = ""; p = 0; jointure = "saut"; continue; }
          if (jointure !== "saut") res += " ";
        }
        tampon = suivante.replace(/^\s+/, ""); p = 0; jointure = null;
        continue;
      }
      const ch = tampon[p];
      if (q === "'") {
        if (ch === "'") { if (tampon[p + 1] === "'") { res += "'"; p += 2; continue; } p++; break; }
        res += ch; p++; continue;
      }
      if (ch === "\\") {
        const e = tampon[p + 1];
        if (e === undefined) { p++; jointure = "sans-espace"; continue; }
        const simples = { n: "\n", t: "\t", r: "\r", 0: "\0", '"': '"', "\\": "\\", "/": "/", " ": " ", b: "\b", e: "\x1b", a: "\x07", f: "\f", v: "\v", N: "\u0085", _: "\u00a0", L: "\u2028", P: "\u2029", "\t": "\t" };
        if (e in simples) { res += simples[e]; p += 2; continue; }
        const longueur = { x: 2, u: 4, U: 8 }[e];
        if (longueur) {
          const hex = tampon.slice(p + 2, p + 2 + longueur);
          if (hex.length !== longueur || !/^[0-9a-fA-F]+$/.test(hex)) erreur(`échappement \\${e} invalide`, idx);
          res += String.fromCodePoint(parseInt(hex, 16)); p += 2 + longueur; continue;
        }
        erreur(`échappement inconnu \\${e}`, idx);
      }
      if (ch === '"') { p++; break; }
      res += ch; p++;
    }
    const apres = tampon.slice(p);
    if (!vide(apres)) erreur(`texte après une chaîne entre guillemets : « ${apres.trim().slice(0, 40)} »`, idx);
    return res;
  }

  function blocScalaire(r, indParent, idx) {
    const m = /^([|>])([1-9]?)([+-]?)([1-9]?)[ \t]*(#.*)?$/.exec(r);
    if (!m || (m[2] && m[4])) erreur(`en-tête de bloc « ${r.slice(0, 20)} » invalide`, idx);
    const style = m[1], chomp = m[3], indicateur = m[2] || m[4];
    let contenu;
    if (indicateur) contenu = Math.max(indParent, 0) + Number(indicateur);
    else {
      let j = i;
      while (j < N && /^\s*$/.test(L[j])) j++;
      contenu = j < N ? indent(L[j]) : indParent + 1;
      if (contenu <= indParent) contenu = indParent + 1;
    }
    const corps = [];
    while (i < N) {
      const s = L[i];
      if (/^\s*$/.test(s)) { corps.push(s.length > contenu ? s.slice(contenu) : ""); i++; continue; }
      if (indent(s) < contenu) break;
      corps.push(s.slice(contenu)); i++;
    }
    let fin = corps.length;
    while (fin > 0 && /^\s*$/.test(corps[fin - 1])) fin--;
    const utiles = corps.slice(0, fin);
    const traine = corps.length - fin;
    const texte = style === "|" ? utiles.join("\n") : plier(utiles);
    if (chomp === "-") return texte;
    if (chomp === "+") return texte + "\n".repeat(1 + traine);
    return utiles.length ? texte + "\n" : "";
  }

  function plier(lignesBloc) {
    let out = "", precedenteVide = true, precedenteIndentee = false;
    for (const l of lignesBloc) {
      if (/^\s*$/.test(l)) { out += "\n"; precedenteVide = true; continue; }
      const indentee = /^\s/.test(l);
      if (precedenteVide) out += l;
      else out += (indentee || precedenteIndentee ? "\n" : " ") + l;
      precedenteVide = false; precedenteIndentee = indentee;
    }
    return out;
  }

  function flux(r, idx) {
    // rassemble le texte jusqu'à l'équilibre des crochets, commentaires retirés ligne par ligne
    const fermeture = (t) => {
      let d = 0, q = null, debutScalaire = true;
      for (let k = 0; k < t.length; k++) {
        const ch = t[k];
        if (q) {
          if (q === "'" && ch === "'") { if (t[k + 1] === "'") { k++; continue; } q = null; }
          else if (q === '"' && ch === "\\") k++;
          else if (q === '"' && ch === '"') q = null;
          continue;
        }
        if ((ch === "'" || ch === '"') && debutScalaire) { q = ch; continue; }
        if (ch === "[" || ch === "{") { d++; debutScalaire = true; continue; }
        if (ch === "]" || ch === "}") { d--; if (d === 0) return k; debutScalaire = false; continue; }
        if (ch === "," || ch === ":") { debutScalaire = true; continue; }
        if (!/\s/.test(ch)) debutScalaire = false;
      }
      return -1;
    };
    const sansCommentaire = (t) => {
      let q = null;
      for (let k = 0; k < t.length; k++) {
        const ch = t[k];
        if (q) { if (q === '"' && ch === "\\") { k++; continue; } if (ch === q) q = null; continue; }
        if (ch === "'" || ch === '"') { q = ch; continue; }
        if (ch === "#" && (k === 0 || /\s/.test(t[k - 1]))) return t.slice(0, k);
      }
      return t;
    };
    let texte = sansCommentaire(r);
    while (fermeture(texte) < 0) {
      if (i >= N) erreur("collection en flux jamais fermée", idx);
      texte += " " + sansCommentaire(L[i]).trim();
      i++;
    }
    const fin = fermeture(texte);
    if (texte.slice(fin + 1).trim() !== "") erreur(`texte après une collection en flux : « ${texte.slice(fin + 1).trim().slice(0, 40)} »`, idx);
    return lireFlux(texte.slice(0, fin + 1), idx);
  }

  function lireFlux(t, idx) {
    let p = 0;
    const blanc = () => { while (p < t.length && /\s/.test(t[p])) p++; };
    const scalaire = () => {
      blanc();
      const ch = t[p];
      if (ch === '"' || ch === "'") {
        p++;
        let res = "";
        for (;;) {
          if (p >= t.length) erreur("chaîne en flux jamais fermée", idx);
          const c = t[p];
          if (ch === "'" && c === "'") { if (t[p + 1] === "'") { res += "'"; p += 2; continue; } p++; break; }
          if (ch === '"' && c === "\\") { const e = t[p + 1]; res += { n: "\n", t: "\t", '"': '"', "\\": "\\", "/": "/" }[e] ?? e; p += 2; continue; }
          if (ch === '"' && c === '"') { p++; break; }
          res += c; p++;
        }
        return res;
      }
      if (/[&*!]/.test(ch || "")) refuserSyntaxe(ch, idx);
      const debut = p;
      while (p < t.length) {
        const c = t[p];
        if (c === "," || c === "]" || c === "}" || c === "[" || c === "{") break;
        if (c === ":" && (p + 1 >= t.length || /[\s,\[\]{}]/.test(t[p + 1]))) break;
        p++;
      }
      const v = t.slice(debut, p).trim();
      return v === "" ? null : v;
    };
    const valeurFlux = () => {
      blanc();
      if (t[p] === "[") {
        p++;
        const tableau = [];
        for (;;) {
          blanc();
          if (t[p] === "]") { p++; return tableau; }
          let v = valeurFlux();
          blanc();
          if (t[p] === ":") { p++; v = { [String(v)]: valeurFlux() }; blanc(); }
          tableau.push(v);
          if (t[p] === ",") { p++; continue; }
          if (t[p] === "]") { p++; return tableau; }
          erreur("liste en flux mal formée", idx);
        }
      }
      if (t[p] === "{") {
        p++;
        const objet = {};
        for (;;) {
          blanc();
          if (t[p] === "}") { p++; return objet; }
          const cle = scalaire();
          blanc();
          let v = null;
          if (t[p] === ":") { p++; blanc(); v = (t[p] === "," || t[p] === "}") ? null : valeurFlux(); }
          if (cle === null) erreur("clé vide dans un mappage en flux", idx);
          if (Object.prototype.hasOwnProperty.call(objet, cle)) erreur(`clé « ${cle} » définie deux fois`, idx);
          objet[cle] = v;
          blanc();
          if (t[p] === ",") { p++; continue; }
          if (t[p] === "}") { p++; return objet; }
          erreur("mappage en flux mal formé", idx);
        }
      }
      return scalaire();
    };
    const v = valeurFlux();
    blanc();
    if (p < t.length) erreur("texte après une collection en flux", idx);
    return v;
  }

  // racine du document
  sauter();
  if (i < N && /^---(\s|$)/.test(L[i])) {
    const reste = L[i].slice(3);
    if (!vide(reste)) erreur("valeur sur la ligne du marqueur de document (---) non prise en charge");
    i++;
    sauter();
  }
  if (i >= N) return { valeur: null, lignes };
  const racine = noeud(indent(L[i]));
  sauter();
  if (i < N && !/^\.\.\.(\s|$)/.test(L[i])) {
    if (/^---(\s|$)/.test(L[i])) erreur("plusieurs documents YAML dans un seul fichier");
    erreur("contenu inattendu après la fin de la racine (indentation incohérente)");
  }
  return { valeur: racine, lignes };
}

// ═══ Règles WF-1..WF-5 ════════════════════════════════════════════════════════════════════════

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const texteDe = (v) => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
const RE_SHA = /^[0-9a-fA-F]{40}$/;
const RE_EXPRESSION = /\$\{\{([\s\S]*?)\}\}/g;

function lirePermissions(p) {
  if (p === undefined) return { declare: false, ecritures: [], idToken: false };
  if (p === null) return { declare: true, ecritures: [], idToken: false };
  if (typeof p === "string") {
    const v = p.trim();
    if (v === "write-all") return { declare: true, writeAll: true, ecritures: ["write-all"], idToken: true };
    if (v === "read-all") return { declare: true, ecritures: [], idToken: false };
    return { declare: true, invalide: v, ecritures: [], idToken: false };
  }
  if (estObjet(p)) {
    // id-token n'est pas une écriture : « Setting id-token: write in the workflow's permissions does
    // not give the workflow permission to modify or write to any resources » (guides OIDC, 28/10/2026).
    const ecritures = Object.entries(p).filter(([k, v]) => k !== "id-token" && texteDe(v).trim() === "write").map(([k]) => k);
    return { declare: true, ecritures, idToken: texteDe(p["id-token"]).trim() === "write" };
  }
  return { declare: true, invalide: texteDe(p), ecritures: [], idToken: false };
}

function declencheurs(on) {
  if (typeof on === "string") return [on.trim()];
  if (Array.isArray(on)) return on.map((x) => texteDe(x).trim());
  if (estObjet(on)) return Object.keys(on);
  return [];
}

// Références non fiables (WF-4) dans le contenu d'une expression ${{ … }}.
export function referencesNonFiables(expression, variablesTeintees = new Map()) {
  const refs = [];
  const re = /\bgithub\s*\.\s*event((?:\s*\.\s*[A-Za-z_][\w-]*|\s*\[\s*(?:'[^']*'|"[^"]*"|\d+|\*)\s*\])+)/g;
  let m;
  while ((m = re.exec(expression))) {
    const segments = [...m[1].matchAll(/\.\s*([A-Za-z_][\w-]*)|\[\s*'([^']*)'\s*\]|\[\s*"([^"]*)"\s*\]/g)].map((x) => x[1] ?? x[2] ?? x[3]);
    const dernier = segments[segments.length - 1];
    if (dernier && SUFFIXES_NON_FIABLES.some((s) => dernier.endsWith(s))) refs.push(`github.event${m[1].replace(/\s+/g, "")}`);
  }
  if (/\bgithub\s*\.\s*head_ref\b/.test(expression)) refs.push("github.head_ref");
  for (const v of expression.matchAll(/\benv\s*\.\s*([A-Za-z_][\w-]*)|\benv\s*\[\s*'([^']+)'\s*\]/g)) {
    const nom = v[1] ?? v[2];
    if (variablesTeintees.has(nom)) refs.push(`env.${nom} (porte ${variablesTeintees.get(nom).join(", ")})`);
  }
  return refs;
}

function referencesDansTexte(texte, teintees) {
  const refs = [];
  for (const m of String(texte).matchAll(RE_EXPRESSION)) refs.push(...referencesNonFiables(m[1], teintees));
  return refs;
}

function teindre(env, base) {
  const t = new Map(base);
  if (estObjet(env)) {
    for (const [nom, v] of Object.entries(env)) {
      const refs = referencesDansTexte(texteDe(v), base);
      if (refs.length) t.set(nom, refs); else t.delete(nom);
    }
  }
  return t;
}

function secretsCites(valeurs) {
  const noms = [];
  for (const v of valeurs) {
    for (const m of texteDe(v).matchAll(RE_EXPRESSION)) {
      for (const s of m[1].matchAll(/\bsecrets\s*\.\s*([A-Za-z_][\w-]*)|\bsecrets\s*\[\s*'([^']+)'\s*\]/g)) {
        const nom = s[1] ?? s[2];
        if (nom.toUpperCase() !== "GITHUB_TOKEN") noms.push(nom);
      }
    }
  }
  return [...new Set(noms)];
}

// Juge un workflow déjà lu ; renvoie la liste des constats et des compteurs.
export function jugerWorkflow(texte, { fichier, cheminVerrou, verrou } = {}) {
  const F = [];
  const compte = { jobs: 0, etapes: 0 };
  const add = (sev, regle, msg, where) => F.push({ sev, regle, msg, where, ...(regle.startsWith("WF-") ? { source: SOURCE(regle) } : {}) });
  let doc;
  try { doc = lireYaml(texte); }
  catch (e) {
    add("bloquant", "—", `workflow illisible par le lecteur YAML de l'oracle (${e.message}) : fichier non jugé`, `${fichier}:${e.ligne ?? "?"}`);
    return { findings: F, compte, juge: false };
  }
  const wf = doc.valeur;
  const ligne = (objet, cle) => { const m = doc.lignes.get(objet); return m ? (cle !== undefined && m[cle] !== undefined ? m[cle] : m.__ligne) : "?"; };
  if (!estObjet(wf) || wf.on === undefined || !estObjet(wf.jobs)) {
    add("bloquant", "—", "clé on ou jobs absente ou mal formée : ce fichier n'est pas un workflow jugeable", `${fichier}:1`);
    return { findings: F, compte, juge: false };
  }
  const evenements = declencheurs(wf.on);
  const pw = lirePermissions(wf.permissions);
  const teinteWf = teindre(wf.env, new Map());
  const heritiersEcriture = [];

  // ── WF-1 · permissions au niveau du workflow ──────────────────────────────────────────────
  if (pw.writeAll) add("majeur", "WF-1", "permissions: write-all au niveau du workflow : le GITHUB_TOKEN de chaque job reçoit l'écriture sur toutes les permissions", `${fichier}:${ligne(wf, "permissions")} (permissions)`);
  if (pw.invalide) add("majeur", "WF-1", `valeur de permissions non documentée (« ${pw.invalide} ») : read-all, write-all, {} ou une table de permissions sont attendus`, `${fichier}:${ligne(wf, "permissions")} (permissions)`);

  // ── WF-3 · déclencheur pull_request_target ────────────────────────────────────────────────
  const prt = evenements.includes("pull_request_target");
  if (prt) {
    add("majeur", "WF-3", "déclencheur pull_request_target : le job reçoit le GITHUB_TOKEN de la base et les secrets ; la politique par défaut de GitHub le bloquera dans les dépôts publics à partir du 2 décembre 2026 (mode évaluation aujourd'hui) — préférer pull_request, ou l'autoriser par une politique explicite", `${fichier}:${ligne(wf, "on")} (on)`);
  }

  for (const [idJob, job] of Object.entries(wf.jobs)) {
    compte.jobs++;
    const ouJob = `${fichier}:${ligne(wf.jobs, idJob)} (jobs.${idJob})`;
    if (!estObjet(job)) { add("bloquant", "—", `job « ${idJob} » mal formé : un mappage est attendu`, ouJob); continue; }
    const pj = lirePermissions(job.permissions);
    const effectives = pj.declare ? pj : pw;

    // ── WF-1 · permissions au niveau du job ─────────────────────────────────────────────────
    if (!pj.declare && !pw.declare) {
      add("majeur", "WF-1", `job « ${idJob} » sans clé permissions, ni au workflow ni au job : son GITHUB_TOKEN reçoit les permissions par défaut du dépôt ou de l'organisation, invisibles depuis ce fichier — déclarer la lecture seule et n'élever que ce que le job exige`, ouJob);
    }
    if (pj.writeAll) add("majeur", "WF-1", `job « ${idJob} » en permissions: write-all : écriture sur toutes les permissions du GITHUB_TOKEN`, `${fichier}:${ligne(job, "permissions")} (jobs.${idJob}.permissions)`);
    if (pj.invalide) add("majeur", "WF-1", `job « ${idJob} » : valeur de permissions non documentée (« ${pj.invalide} »)`, `${fichier}:${ligne(job, "permissions")} (jobs.${idJob}.permissions)`);
    if (!pj.declare && pw.declare && !pw.writeAll && pw.ecritures.length) heritiersEcriture.push(idJob);

    // ── WF-2 · workflow réutilisable appelé par le job ──────────────────────────────────────
    if (job.uses !== undefined) jugerUses(texteDe(job.uses), `${fichier}:${ligne(job, "uses")} (jobs.${idJob}.uses)`);

    const etapes = Array.isArray(job.steps) ? job.steps : [];
    const teinteJob = teindre(job.env, teinteWf);
    etapes.forEach((etape, n) => {
      compte.etapes++;
      if (!estObjet(etape)) return;
      const nomEtape = etape.name !== undefined ? ` « ${texteDe(etape.name)} »` : "";
      const ou = (cle) => `${fichier}:${ligne(etape, cle)} (jobs.${idJob}.steps[${n}]${cle ? "." + cle : ""}${nomEtape})`;
      const uses = etape.uses !== undefined ? texteDe(etape.uses).trim() : null;
      const avec = estObjet(etape.with) ? etape.with : {};

      // ── WF-2 · action de l'étape ──────────────────────────────────────────────────────────
      if (uses) jugerUses(uses, ou("uses"));

      // ── WF-3 · checkout du code de la pull request sous pull_request_target ───────────────
      if (prt && uses && /^actions\/checkout@/i.test(uses)) {
        const ref = texteDe(avec.ref), depot = texteDe(avec.repository);
        const tete = /github\s*\.\s*event\s*\.\s*pull_request\s*\.\s*head\s*\.|refs\/pull\/|github\s*\.\s*head_ref/.test(ref);
        const fourche = /github\s*\.\s*event\s*\.\s*pull_request\s*\.\s*head\s*\.\s*repo/.test(depot);
        const optOut = texteDe(avec["allow-unsafe-pr-checkout"]).trim() === "true";
        if (tete || fourche || optOut) {
          const motif = [tete && `ref: ${ref}`, fourche && `repository: ${depot}`, optOut && "allow-unsafe-pr-checkout: true"].filter(Boolean).join(", ");
          add("bloquant", "WF-3", `checkout du code de la pull request sous pull_request_target (${motif}) : le code d'une fourche s'exécute avec les secrets et le jeton de la base (forme « pwn request » documentée)`, ou("with"));
        }
      }

      // ── WF-4 · injection par expression de contexte non fiable dans run ────────────────────
      if (etape.run !== undefined) {
        const teinte = teindre(etape.env, teinteJob);
        const refs = referencesDansTexte(texteDe(etape.run), teinte);
        if (refs.length) {
          add("bloquant", "WF-4", `expression de contexte non fiable substituée dans le script avant son exécution : ${[...new Set(refs)].join(" ; ")} — la passer par une variable d'environnement lue par le shell ("$VAR"), jamais par \${{ }} dans run`, ou("run"));
        }
      }

      // ── WF-5 · secret long là où l'OIDC est documenté ────────────────────────────────────
      if (uses) {
        const cible = uses.split("@")[0].toLowerCase();
        const oidc = ACTIONS_OIDC.find((a) => a.action === cible && (!a.applicable || a.applicable(avec)));
        if (oidc && !effectives.idToken) {
          const secrets = secretsCites([...Object.values(avec), ...(estObjet(etape.env) ? Object.values(etape.env) : [])]);
          if (secrets.length) {
            F.push({ sev: "majeur", regle: "WF-5", msg: `${oidc.action} reçoit un secret long (${secrets.map((s) => `secrets.${s}`).join(", ")}) dans un job sans id-token: write, alors que GitHub documente la connexion OIDC pour ${oidc.fournisseur} — jeton court par job au lieu d'un secret à faire tourner`, where: ou("uses"), source: `${GUIDES_OIDC}/${oidc.guide}` });
          }
        }
      }
    });
  }

  if (heritiersEcriture.length) {
    add("mineur", "WF-1", `écriture (${pw.ecritures.join(", ")}) posée au niveau du workflow et héritée par ${heritiersEcriture.length} job(s) sans permissions propres (${heritiersEcriture.join(", ")}) : la page recommande la lecture seule par défaut, élevée job par job`, `${fichier}:${ligne(wf, "permissions")} (permissions)`);
  }
  return { findings: F, compte, juge: true };

  function jugerUses(u, ou) {
    if (u.startsWith("./") || u.startsWith("$/") || u.startsWith("docker://")) return; // local, ou non jugé (NON_JUGE)
    const at = u.lastIndexOf("@");
    if (at < 0) { add("majeur", "WF-2", `référence « ${u} » sans version (@ref absent) : elle suit la branche par défaut de l'action`, ou); return; }
    const ref = u.slice(at + 1);
    if (RE_SHA.test(ref)) return;
    if (verrou && verrou.has(u)) {
      F.push({ sev: "info", regle: "WF-2", msg: `référence « ${u} » non épinglée par SHA dans le fichier, mais inscrite au verrou ${cheminVerrou} pour ce workflow`, where: ou, source: `${DOC}/concepts/security/workflow-dependency-lockfiles` });
      return;
    }
    const proprietaire = u.slice(0, at).split("/")[0].toLowerCase();
    if (ORGANISATIONS_GITHUB.has(proprietaire)) {
      add("mineur", "WF-2", `action de GitHub « ${u} » épinglée par étiquette ou branche, pas par SHA complet : une étiquette peut être déplacée ; le SHA complet ou le verrou actions.lock l'immobilisent`, ou);
    } else {
      add("majeur", "WF-2", `action tierce « ${u} » non épinglée par SHA complet : son mainteneur, ou quiconque prend son dépôt, peut déplacer « ${ref} » vers un autre code, qui recevra les secrets et le jeton du job`, ou);
    }
  }
}

// ═══ Lecture du dépôt, du verrou, et sortie ═══════════════════════════════════════════════════

// Ensemble des références inscrites au verrou pour un workflow donné (null si pas inscrit). Les clés
// du verrou sont des chemins depuis la racine du dépôt (« .github/workflows/ci.yml »).
function referencesVerrouillees(verrou, cheminRelatif) {
  if (!verrou || !estObjet(verrou.workflows)) return null;
  const cible = cheminRelatif.split("\\").join("/");
  for (const [cle, refs] of Object.entries(verrou.workflows)) {
    if (cle.split("\\").join("/") === cible) return new Set((Array.isArray(refs) ? refs : []).map((x) => texteDe(x).trim()));
  }
  return null;
}

export function jugerCible(cible) {
  const findings = [];
  const synthese = { fichiers_lus: 0, fichiers_juges: 0, jobs: 0, etapes: 0, verrou: null, par_regle: {} };
  let fichiers = [], racineDepot = null, dossierWorkflows = null;
  const stat = fs.statSync(cible);
  if (stat.isFile()) {
    fichiers = [cible];
    dossierWorkflows = path.dirname(cible);
    const parent = path.dirname(dossierWorkflows);
    if (path.basename(dossierWorkflows) === "workflows" && path.basename(parent) === ".github") racineDepot = path.dirname(parent);
  } else {
    const sousDossier = path.join(cible, ".github", "workflows");
    if (fs.existsSync(sousDossier) && fs.statSync(sousDossier).isDirectory()) { racineDepot = cible; dossierWorkflows = sousDossier; }
    else dossierWorkflows = cible;
    fichiers = fs.readdirSync(dossierWorkflows, { withFileTypes: true })
      .filter((e) => e.isFile() && /\.ya?ml$/i.test(e.name))
      .map((e) => path.join(dossierWorkflows, e.name))
      .sort();
  }
  let verrou = null;
  const cheminVerrou = path.join(dossierWorkflows, "actions.lock");
  const affiche = (p) => (racineDepot ? path.relative(racineDepot, p) : path.relative(path.dirname(dossierWorkflows), p)).split("\\").join("/");
  if (fs.existsSync(cheminVerrou)) {
    try { verrou = lireYaml(fs.readFileSync(cheminVerrou, "utf8")).valeur; synthese.verrou = affiche(cheminVerrou); }
    catch (e) { findings.push({ sev: "info", regle: "WF-2", msg: `verrou actions.lock illisible (${e.message}) : non pris en compte, les références sont jugées sans lui`, where: `${affiche(cheminVerrou)}:${e.ligne ?? "?"}`, source: SOURCE("WF-2") }); }
  }
  for (const f of fichiers) {
    synthese.fichiers_lus++;
    const relatif = affiche(f);
    const refsVerrou = referencesVerrouillees(verrou, racineDepot ? path.relative(racineDepot, f) : `.github/workflows/${path.basename(f)}`);
    const r = jugerWorkflow(fs.readFileSync(f, "utf8"), { fichier: relatif, cheminVerrou: synthese.verrou, verrou: refsVerrou });
    if (r.juge) synthese.fichiers_juges++;
    synthese.jobs += r.compte.jobs;
    synthese.etapes += r.compte.etapes;
    findings.push(...r.findings);
  }
  for (const f of findings) if (f.sev !== "info") synthese.par_regle[f.regle] = (synthese.par_regle[f.regle] || 0) + 1;
  return { findings, synthese };
}

// ---- CLI -------------------------------------------------------------------------------------
const lanceEnDirect = process.argv[1]
  && fileURLToPath(import.meta.url).toLowerCase().split("\\").join("/")
     === path.resolve(process.argv[1]).toLowerCase().split("\\").join("/");
if (lanceEnDirect) {
  const args = process.argv.slice(2);
  const cible = args.find((a) => !a.startsWith("--"));
  const jsonOnly = args.includes("--json-only");
  const sortir = (verdict, code, findings, synthese) => {
    process.stdout.write(JSON.stringify({
      oracle: ORACLE, version: VERSION, artefact: cible || null, verdict,
      findings: findings.length ? findings : [{ sev: "info", regle: "—", msg: "aucun défaut détecté sur les 5 règles WF-1..WF-5", where: cible }],
      synthese, sources: SOURCES, non_juge: NON_JUGE,
    }, null, jsonOnly ? 0 : 2));
    process.exit(code);
  };
  if (!cible || !fs.existsSync(cible)) sortir("SKIP", 2, [{ sev: "info", regle: "—", msg: "cible introuvable", where: String(cible) }], null);
  const { findings, synthese } = jugerCible(cible);
  if (synthese.fichiers_lus === 0) {
    sortir("SKIP", 2, [{ sev: "info", regle: "—", msg: "aucun workflow (.yml ou .yaml) trouvé : ni .github/workflows dans la cible, ni fichier de workflow à sa racine", where: cible }], synthese);
  }
  const durs = findings.filter((f) => f.sev === "bloquant" || f.sev === "majeur");
  sortir(durs.length ? "FAIL" : "PASS", durs.length ? 1 : 0, findings, synthese);
}
