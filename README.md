# digit-ai-forge-websec

Forge dédiée à la **sécurité du produit web livré**. Née du mandat TF-0123 (décision humaine
du 12/08/2026, registre `digit-ai-forge-pilot/todo/TODO.jsonl`), verdict de l'étude
d'opportunité du 12/08 (`digit-ai-forge-pilot/output/20260812-etude-opportunite-forges.md §1`).
Modèle : **forge-seo** — invocation sur mandat humain uniquement, jamais de déclenchement
automatique ; pré-MEP en gate optionnel consommé par les oracles M-1…M-5 du pilot, post-MEP
en mission récurrente à livrable différentiel.

## Catalogue de services

> Section proposée par la campagne « catalogues » du pilot (2026-08-13) — générée depuis
> la source unique `catalogues/catalogue.jsonl` du pilot (v1.6.0, challengée état de
> l'art le 12/08/2026). **prouvé** = preuve exécutée ; *déclaré* = méthode documentée seulement.

| Service | Intention (« je veux… ») | Point d'entrée | Statut |
|---|---|---|---|
| **Juger l'exposition runtime** | savoir si mon produit servi expose une configuration dangereuse | `node scripts\capturer.mjs <url> <capture.json> puis node oracles\oracle-exposition.mjs <capture.json>` | prouvé (experimental) |
| **Scanner les dépendances vulnérables (SCA)** | savoir si mes dépendances portent des CVE connues, avec seuils | `node oracles\oracle-sca.mjs <racine-produit> [--seuils f.json]` | prouvé (experimental) |
| **Tenir un contrat de sécurité ASVS L1** | m'engager sur un niveau de sécurité vérifiable et daté | `referentiels\asvs-l1.md (frontmatter challenge_date)` | déclaré (experimental) |
| **Juger un scan dynamique (DAST)** | savoir ce qu'un scan ZAP relève sur une cible **autorisée par écrit**, en verdict à seuils | `node oracles\oracle-dast.mjs --cible <url> --autorisation <f.json> [--rapport <zap.json>]` | prouvé pour le garde-fou et la lecture de rapport ; **exécution ZAP non prouvée** (ZAP absent du poste) |
| **Dérouler une méthode de test de sécurité** | savoir *comment* on teste une exigence ASVS, cas par cas | `referentiels\wstg-cas.md` (28 cas WSTG 4.2 curés, rattachés à `asvs-l1.md`) | déclaré (experimental) |

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
- **Zéro API tierce payante, zéro dépendance npm.** Trois oracles + un script de capture,
  Node natif (`.mjs`), aucune installation requise pour la partie propre à cette forge.
  `oracle-sca` et `oracle-dast` **délèguent** à l'outillage déjà présent sur le poste (npm,
  pip-audit, OWASP ZAP) — ils ne l'installent jamais et ne dégradent jamais silencieusement
  leur verdict quand cet outillage manque (SKIP motivé, jamais un PASS par défaut).
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
| **Juger un scan dynamique (DAST)** | savoir ce qu'OWASP ZAP relève sur une cible autorisée, en verdict à seuils | `node oracles/oracle-dast.mjs --cible <url> --autorisation <f.json> [--rapport <zap.json>]` | **partiellement prouvé** — garde-fou dual-use et lecture de rapport ZAP prouvés (13 fixtures, `fixtures/dast/`) ; **branche d'exécution ZAP non prouvée** faute de ZAP sur le poste (SKIP motivé) |
| **Rejouer toutes les preuves** | vérifier en un geste que rien n'a régressé | `node oracles/self-test.mjs` | **prouvé** — 36/36 PASS déterministes à la dernière exécution connue (14/08/2026), + volet SCA dépendant de l'outillage réel du poste |

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

### `oracle-dast.mjs` — enveloppe OWASP ZAP, garde-fou dual-use fail-closed

Lève la dette **D-W1** (mandat TF-0187). Un scan dynamique sollicite réellement une cible :
c'est une capacité à double usage. L'oracle **refuse de faire quoi que ce soit** tant que la
cible n'est pas nommément déclarée autorisée par écrit — et le refus est un `FAIL` bruyant
(exit 1), jamais un `SKIP` discret, pour qu'une faute de frappe dans `--cible` ne parte jamais
en scan.

| Garde-fou | Règle | Refus |
|---|---|---|
| Cible explicite | `--cible <url>` absolue en http(s) — aucune cible par défaut, jamais | `DAST-USAGE` (SKIP) / `DAST-AUTZ-CIBLE` |
| Autorisation écrite | `--autorisation <f.json>` ou `WEBSEC_DAST_AUTORISATION` | `DAST-AUTZ-ABSENTE` |
| Complétude | `autorisation_ecrite: true`, `mandat`, `proprietaire`, `environnement`, `cibles`, `fenetre{debut,fin}` | `DAST-AUTZ-CHAMPS` |
| Périmètre nommé | origine de `--cible` **identique** à une entrée de `cibles` — aucun joker, aucun sous-domaine implicite | `DAST-AUTZ-CIBLE` |
| Fenêtre datée | la date du jour tombe dans `fenetre` — une autorisation périmée n'autorise plus | `DAST-AUTZ-FENETRE` |
| Instance dédiée | `environnement: "production"` exige `autorisation_production_distincte: true` | `DAST-AUTZ-PROD` |
| Actif déclaré | `--mode actif` exige `actif_autorise: true` (le passif est le défaut) | `DAST-AUTZ-MODE` |

Deux voies une fois le garde-fou franchi : `--rapport <zap.json>` juge un rapport ZAP **déjà
produit** (aucune émission vers la cible), sinon l'oracle cherche ZAP sur le poste
(`WEBSEC_DAST_ZAP`, puis `zap-baseline.py` / `zap.sh` / `zap.bat` — résolus dans le `PATH`,
jamais exécutés « pour voir ») et lance une passe **baseline passive**. Seuils par défaut
`high=0, medium=0` (`low`/`informational` comptés en synthèse, non bloquants), surchargeables
par `--seuils <f.json>`.

```
node oracles/oracle-dast.mjs --cible https://recette.exemple.tld \
     --autorisation autorisation.json [--rapport zap.json] [--seuils s.json] [--mode passif|actif]
```

Ce que cet oracle **ne juge pas** est déclaré dans son champ `non_juge` — au premier rang :
il vérifie une **déclaration écrite et traçable**, jamais la sincérité du consentement ; et
une absence d'alerte ZAP n'est jamais une absence de vulnérabilité.

### Contrat de sortie (les trois oracles)

```json
{ "oracle": "...", "version": "0.1.0", "artefact": "...", "verdict": "PASS|FAIL|SKIP",
  "findings": [{ "sev": "bloquant|majeur|mineur|info", "regle": "EX-1", "msg": "...", "where": "..." }],
  "non_juge": ["..."] }
```

Exit `0` = PASS, `1` = FAIL, `2` = SKIP. `oracle-sca` et `oracle-dast` ajoutent `synthese`
(compteurs) et `seuils_appliques` (source + valeurs). Pour `oracle-dast` : `FAIL` couvre aussi
le **refus du garde-fou** (rien n'a été émis) et `SKIP` les deux cas où rien n'a pu être jugé
— aucune cible fournie, ou ZAP absent du poste.

## Référentiel `referentiels/asvs-l1.md`

Sous-ensemble curé du niveau **L1** de l'OWASP ASVS 5.0.0 (mai 2025, CC BY-SA 4.0) —
identifiants **cités**, texte intégral **non recopié** (voir le fichier pour l'attribution
complète et le lien vers le standard). Chaque exigence porte : l'ID ASVS, un résumé en une
ligne française, le moyen de vérification (`oracle-exposition` | `oracle-sca` | `revue
humaine`) et son statut (`outillé` | `manuel`). `challenge_date: 2026-08-12` — à re-challenger
en fraîcheur avant tout usage éloigné de cette date.

## Référentiel `referentiels/wstg-cas.md`

Sous-ensemble curé de l'**OWASP Web Security Testing Guide 4.2** (déc. 2020, dernière version
stable au 14/08/2026 ; CC BY-SA 4.0) — identifiants **cités**, fiches **non recopiées**.
Là où `asvs-l1.md` dit *ce qu'on exige*, ce document dit *comment on le teste* : **28 cas**
(25 rattachés à une exigence L1 nommée d'`asvs-l1.md`, 3 aux règles outillées classées L2/L3),
chacun avec son geste de vérification et son outillage (`oracle-exposition` | `oracle-dast` |
`manuel`). Quatre chapitres entiers (ATHZ, BUSL, ERRH, APIT) et 54 cas nommés restent **non
curés**, listés explicitement dans le fichier — leur chapitre ASVS n'est pas curé non plus.
`challenge_date: 2026-08-14` (re-challenger à la publication d'une WSTG v5.0).

## Rejouer les preuves

```
node oracles/self-test.mjs
```

`oracle-exposition` (15 fixtures) et le volet garde-fou/rapport d'`oracle-dast` (13 cas) sont
**entièrement déterministes** — zéro réseau, zéro dépendance de poste, et **aucun scan n'est
lancé par le self-test**, fût-il autorisé (les cas d'exécution forcent `WEBSEC_DAST_ZAP` sur un
chemin injouable). Le volet `oracle-sca` dépend de l'outillage **réellement présent** sur
le poste qui exécute le self-test (npm, pip-audit) et de l'accès réseau à leurs bases
d'avisos ; en leur absence, le self-test consigne un **SKIP motivé** par cas — jamais compté
comme une preuve du sens rouge, jamais présenté comme un succès. Rejouer avant toute
confiance dans une modification — un `✓` sans self-test rejoué n'est pas un `✓`.

## Limites explicites (ce que la v0 n'est pas)

- **DAST : enveloppe livrée, exécution non prouvée (dette D-W1 requalifiée le 14/08/2026,
  TF-0187).** `oracle-dast.mjs` enveloppe OWASP ZAP et traduit son rapport en verdict à
  seuils ; son garde-fou dual-use et sa lecture de rapport sont prouvés par 13 fixtures. Mais
  **ZAP n'est installé sur aucun poste de l'écosystème à ce jour** : la branche d'exécution
  réelle (spider, passe passive, rapport produit par ZAP lui-même) n'est **pas** prouvée par
  fixture, et le chemin nominal ici est un `SKIP` motivé. La dette n'est donc pas close : elle
  passe de « pas de DAST du tout » à « DAST outillé, exécution à prouver sur poste équipé ».
- **Aucun scan sans autorisation écrite.** `oracle-dast` refuse (`FAIL`, exit 1) toute cible
  qui n'est pas nommément déclarée dans un fichier d'autorisation daté et en cours de validité
  — la production exige en plus une autorisation distincte, et le mode actif une mention
  explicite. Ce refus est structurel, pas une option : il ne se désactive pas.
- **Pas de pentest manuel.** Cette forge outille des vérifications machine reproductibles ;
  elle ne remplace ni un audit de sécurité humain, ni un test d'intrusion. `wstg-cas.md`
  décrit une **méthode**, il ne l'exécute pas : 20 de ses 28 cas sont manuels.
- **`oracle-sca` dépend du poste.** Aucun outil SCA n'est installé par cette forge ; si
  aucun de npm/pip-audit n'est présent (ou si le réseau vers leur base d'avisos est
  injoignable), le verdict est `SKIP` motivé — jamais un `PASS` faute de preuve.
  `osv-scanner` (multi-écosystème) n'est **pas** enveloppé en v0, faute de poste équipé pour
  le prouver par fixture.
- **`oracle-exposition` ne juge pas la couche TLS.** Version de protocole, suites de
  chiffrement, validité et chaîne du certificat sont hors périmètre — v0 juge la réponse
  applicative capturée par un `fetch`, pas une négociation TLS.
- **Référentiel WSTG partiel.** `referentiels/wstg-cas.md` ne cure que les cas rattachables à
  une exigence d'`asvs-l1.md` : 4 chapitres entiers (autorisation, logique métier, gestion
  d'erreurs, API) et 54 cas nommés restent dehors. L'absence de constat sur eux n'est pas un
  constat d'absence de défaut.
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
  oracle-dast.mjs         enveloppe OWASP ZAP — garde-fou dual-use fail-closed + seuils
  self-test.mjs           rejeu intégral à double sens (36 contrôles)
scripts/
  capturer.mjs            capture réelle fetch(url) → JSON d'entrée d'oracle-exposition
referentiels/
  asvs-l1.md              contrat de sécurité v0, sous-ensemble curé ASVS 5.0.0 niveau L1
  wstg-cas.md             méthode de test, 28 cas curés WSTG 4.2 rattachés à asvs-l1.md
fixtures/
  exposition/             15 fixtures JSON (vertes + rouges) pour oracle-exposition
  sca/                    manifestes npm/pip synthétiques (vulnérables + propres) + cas SKIP
  dast/                   autorisations synthétiques (valide/expirée/production/incomplète),
                          rapports ZAP synthétiques (propre/vulnérable), seuils desserrés
```
