# digit-ai-forge-websec

Forge dédiée à la **sécurité du produit web livré**. Née du mandat TF-0123 (décision humaine
du 12/08/2026, registre `digit-ai-forge-pilot/todo/TODO.jsonl`), verdict de l'étude
d'opportunité du 12/08 (`digit-ai-forge-pilot/output/20260812-etude-opportunite-forges.md §1`).
Modèle : **forge-seo** — invocation sur mandat humain uniquement, jamais de déclenchement
automatique ; pré-MEP en gate optionnel consommé par les oracles M-1…M-5 du pilot, post-MEP
en mission récurrente à livrable différentiel.

## Catalogue de services

> Section proposée par la campagne « catalogues » du pilot (2026-08-12) — générée depuis
> la source unique `catalogues/catalogue.jsonl` du pilot (v1.5.0, challengée état de
> l'art le 12/08/2026). **prouvé** = preuve exécutée ; *déclaré* = méthode documentée seulement.

| Service | Intention (« je veux… ») | Point d'entrée | Statut |
|---|---|---|---|
| **Juger l'exposition runtime** | savoir si mon produit servi expose une configuration dangereuse | `node scripts\capturer.mjs <url> <capture.json> puis node oracles\oracle-exposition.mjs <capture.json>` | prouvé (experimental) |
| **Scanner les dépendances vulnérables (SCA)** | savoir si mes dépendances portent des CVE connues, avec seuils | `node oracles\oracle-sca.mjs <racine-produit> [--seuils f.json]` | prouvé (experimental) |
| **Tenir un contrat de sécurité ASVS L1** | m'engager sur un niveau de sécurité vérifiable et daté | `referentiels\asvs-l1.md (frontmatter challenge_date)` | déclaré (experimental) |

Le catalogue consolidé des dix forges vit chez le pilot :
[digit-ai-forge-pilot/catalogues/CATALOGUES.md](https://github.com/iguane39/digit-ai-forge-pilot/blob/main/catalogues/CATALOGUES.md).

## Délimitation — websec vs agents-security

**Deux objets, zéro recouvrement**, prouvé au verdict de non-recouvrement de l'étude
d'opportunité (§1b, catalogue v1.3.0) :

| Forge | Juge | Ne juge PAS |
|---|---|---|
| **`digit-ai-forge-websec`** (ici) | le **PRODUIT web livré** : sa configuration de sécurité runtime (en-têtes HTTP, cookies), ses dépendances vulnérables, sa conformité à un contrat ASVS curé | l'outillage agentique qui a construit le produit |
| [`digit-ai-forge-agents-security`](https://github.com/iguane39/digit-ai-forge-agents-security) | l'**OUTILLAGE agentique** : définitions d'agents, appels d'outils, capacités et permissions | le produit livré lui-même — aucune notion de HTTP, de dépendance npm/pip, ni d'ASVS |

Un agent qui a construit un site peut être scanné sain par `agents-security` et livrer un
site sans aucun en-tête de sécurité — les deux forges répondent à des questions différentes,
et aucune ne se substitue à l'autre. Réciproquement, `websec` ne sait rien dire de la
sécurité d'un `agent.def` ou d'un journal d'appels d'outils.

## Doctrine

- **Le juge ne vit pas chez le jugé.** `forge-development` construit le produit ; elle ne
  peut pas être son propre contrôle de sécurité runtime — d'où une forge séparée.
- **Invocation sur mandat humain**, via le pilot (`digit-ai-forge-pilot`). Cette forge
  n'audite jamais spontanément un dépôt ou une URL tiers.
- **Elle outille, ne décide jamais.** Un verdict `FAIL` est un constat argumenté et localisé
  — jamais un blocage automatique d'une MEP, jamais une correction appliquée à la place d'un
  humain.
- **Zéro API tierce payante, zéro dépendance npm.** Deux oracles + un script de capture,
  Node natif (`.mjs`), aucune installation requise pour la partie propre à cette forge.
  `oracle-sca` **délègue** à l'outillage déjà présent sur le poste (npm, pip-audit) — il ne
  l'installe jamais et ne dégrade jamais silencieusement son verdict quand cet outillage
  manque (SKIP motivé, jamais un PASS par défaut).
- **Zéro donnée réelle.** Dépôt public : toutes les fixtures sont synthétiques (URLs, cookies,
  dépendances fictives ou à CVE publique déjà connue) — aucune donnée client, aucun secret.

## Catalogue v0 — statut prouvé

> « prouvé » = preuve exécutée (fixture rejouée par `self-test.mjs`) ; « déclaré » = méthode
> documentée seulement. Un service sans preuve n'apparaîtrait pas ici.

| Service | Intention (« je veux… ») | Point d'entrée | Statut |
|---|---|---|---|
| **Juger l'exposition HTTP d'une réponse** | connaître la configuration de sécurité (en-têtes, cookies) d'un produit avant sa MEP | `node oracles/oracle-exposition.mjs <capture.json>` | **prouvé** — 15 fixtures (`fixtures/exposition/`), 11 règles EX-1..EX-11 |
| **Capturer une réponse HTTP réelle** | produire l'entrée de l'oracle d'exposition depuis une URL réelle | `node scripts/capturer.mjs <url> [--sortie <fichier>]` | **prouvé** (fetch natif, zéro dépendance) — ne juge rien, capture seulement |
| **Juger les dépendances vulnérables** | savoir si les dépendances d'un produit portent des CVE connues | `node oracles/oracle-sca.mjs <dossier-cible>` | **prouvé** — npm (`npm audit`) et pip (`pip-audit`) enveloppés, fixtures vertes/rouges par écosystème, SKIP motivé si l'outillage ou le réseau manque |
| **Rejouer toutes les preuves** | vérifier en un geste que rien n'a régressé | `node oracles/self-test.mjs` | **prouvé** — 23/23 PASS déterministes à la dernière exécution connue (12/08/2026), + volet SCA dépendant de l'outillage réel du poste |

### `oracle-exposition.mjs` — 11 règles EX-1..EX-11

| Règle | Détecte | Sévérité |
|---|---|---|
| EX-1 | Content-Security-Policy absente | bloquant |
| EX-2 | CSP présente mais triviale (`default-src *` / `script-src *`) | majeur |
| EX-3 | Strict-Transport-Security absente sur une réponse HTTPS (non applicable en HTTP) | bloquant |
| EX-4 | `X-Content-Type-Options` absente ou différente de `nosniff` | majeur |
| EX-5 | Ni `X-Frame-Options` valide ni `frame-ancestors` en CSP (clickjacking) | majeur |
| EX-6 | `Referrer-Policy` absente ou réglée sur `unsafe-url` | majeur |
| EX-7 | `Permissions-Policy` absente | **mineur** (ne fait pas échouer le verdict global) |
| EX-8 | Cookie posé sans l'attribut `Secure` | bloquant |
| EX-9 | Cookie posé sans l'attribut `HttpOnly` | majeur |
| EX-10 | Cookie posé sans l'attribut `SameSite` déclaré explicitement | majeur |
| EX-11 | Fuite de version serveur (`Server`, `X-Powered-By`) | majeur |

```
node scripts/capturer.mjs https://exemple.tld --sortie capture.json
node oracles/oracle-exposition.mjs capture.json
```

### `oracle-sca.mjs` — deux écosystèmes enveloppés

| Écosystème | Manifeste requis | Outil délégué | Seuil par défaut |
|---|---|---|---|
| npm | `package.json` + `package-lock.json` | `npm audit --package-lock-only --json` (déjà présent, aucune installation) | `critical=0`, `high=0` |
| pip | `requirements.txt` | `pip-audit -r requirements.txt --format json` | `vulnerabilites=0` (paquets touchés) |

```
node oracles/oracle-sca.mjs <dossier-cible> [--seuils <fichier.json>]
```

Sans manifeste exploitable NI outil disponible pour un manifeste présent : verdict `SKIP`
motivé, jamais un `PASS` silencieux — c'est une règle dure du mandat (TF-0123). Le champ
`seuils_appliques` de la sortie dit toujours si le seuil vient d'un fichier `--seuils` ou du
défaut embarqué.

### Contrat de sortie (les deux oracles)

```json
{ "oracle": "...", "version": "0.1.0", "artefact": "...", "verdict": "PASS|FAIL|SKIP",
  "findings": [{ "sev": "bloquant|majeur|mineur|info", "regle": "EX-1", "msg": "...", "where": "..." }],
  "non_juge": ["..."] }
```

Exit `0` = PASS, `1` = FAIL, `2` = SKIP. `oracle-sca` ajoute `synthese` (compteurs par
écosystème) et `seuils_appliques` (source + valeurs).

## Référentiel `referentiels/asvs-l1.md`

Sous-ensemble curé du niveau **L1** de l'OWASP ASVS 5.0.0 (mai 2025, CC BY-SA 4.0) —
identifiants **cités**, texte intégral **non recopié** (voir le fichier pour l'attribution
complète et le lien vers le standard). Chaque exigence porte : l'ID ASVS, un résumé en une
ligne française, le moyen de vérification (`oracle-exposition` | `oracle-sca` | `revue
humaine`) et son statut (`outillé` | `manuel`). `challenge_date: 2026-08-12` — à re-challenger
en fraîcheur avant tout usage éloigné de cette date.

## Rejouer les preuves

```
node oracles/self-test.mjs
```

`oracle-exposition` (15 fixtures) est **entièrement déterministe** — zéro réseau, zéro
dépendance de poste. Le volet `oracle-sca` dépend de l'outillage **réellement présent** sur
le poste qui exécute le self-test (npm, pip-audit) et de l'accès réseau à leurs bases
d'avisos ; en leur absence, le self-test consigne un **SKIP motivé** par cas — jamais compté
comme une preuve du sens rouge, jamais présenté comme un succès. Rejouer avant toute
confiance dans une modification — un `✓` sans self-test rejoué n'est pas un `✓`.

## Limites explicites (ce que la v0 n'est pas)

- **Pas de DAST.** Aucun fuzzing d'endpoint, aucune injection active, aucun scan actif de
  vulnérabilités applicatives. **OWASP ZAP est consigné en v1** — non construit ici.
- **Pas de pentest manuel.** Cette forge outille des vérifications machine reproductibles ;
  elle ne remplace ni un audit de sécurité humain, ni un test d'intrusion.
- **`oracle-sca` dépend du poste.** Aucun outil SCA n'est installé par cette forge ; si
  aucun de npm/pip-audit n'est présent (ou si le réseau vers leur base d'avisos est
  injoignable), le verdict est `SKIP` motivé — jamais un `PASS` faute de preuve.
  `osv-scanner` (multi-écosystème) n'est **pas** enveloppé en v0, faute de poste équipé pour
  le prouver par fixture.
- **`oracle-exposition` ne juge pas la couche TLS.** Version de protocole, suites de
  chiffrement, validité et chaîne du certificat sont hors périmètre — v0 juge la réponse
  applicative capturée par un `fetch`, pas une négociation TLS.
- **Référentiel ASVS partiel.** `referentiels/asvs-l1.md` cure un sous-ensemble du niveau L1
  centré sur les chapitres couverts par les deux oracles (V3, V15) et quelques chapitres
  adjacents (V1, V6, V12, V13, V14) — 9 chapitres L1 restent non curés, listés explicitement
  dans le référentiel (jamais tus).
- **Pas de décision.** Un verdict `FAIL` ne bloque rien tout seul — un humain ou un run amont
  décide de la suite via le pilot.

## Arborescence

```
oracles/
  oracle-exposition.mjs   juge une capture HTTP {url,status,headers} — 11 règles EX-1..EX-11
  oracle-sca.mjs          enveloppe npm audit / pip-audit en verdict machine normalisé
  self-test.mjs           rejeu intégral à double sens
scripts/
  capturer.mjs            capture réelle fetch(url) → JSON d'entrée d'oracle-exposition
referentiels/
  asvs-l1.md              contrat de sécurité v0, sous-ensemble curé ASVS 5.0.0 niveau L1
fixtures/
  exposition/             15 fixtures JSON (vertes + rouges) pour oracle-exposition
  sca/                    manifestes npm/pip synthétiques (vulnérables + propres) + cas SKIP
```
