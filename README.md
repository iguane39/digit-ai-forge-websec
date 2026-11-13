# digit-ai-forge-websec

Forge dédiée à la **sécurité du produit web livré**. Née du mandat TF-0123 (décision humaine
du 12/08/2026, registre `digit-ai-factory/todo/TODO.jsonl`), verdict de l'étude
d'opportunité du 12/08 (`digit-ai-factory/output/03-etudes/20260812-etude-opportunite-forges.md §1`).
Modèle : **forge-seo** — invocation sur mandat humain uniquement, jamais de déclenchement
automatique ; pré-MEP en gate optionnel consommé par les oracles M-1…M-5 du pilot, post-MEP
en mission récurrente à livrable différentiel.

## Utilisation

Cette forge ne se lance pas seule : la Factory la mobilise quand votre demande en a besoin.
Ouvrez une session Claude Code dans le dossier de votre projet et collez cette phrase, la même
pour tous les cas d'usage :

```
Utilise https://github.com/iguane39/digit-ai-factory pour ce projet
```

La Factory installe ce qui manque, cette forge comprise, puis vous demande ce que vous voulez
obtenir. Détail : [README de la Factory](https://github.com/iguane39/digit-ai-factory#utiliser-la-factory--une-seule-phrase).

## Catalogue de services

> Section proposée par la campagne « catalogues » du pilot (2026-08-13) — générée depuis
> la source unique `catalogues/catalogue.jsonl` du pilot (v1.6.0, challengée état de
> l'art le 12/08/2026). **prouvé** = preuve exécutée ; *déclaré* = méthode documentée seulement.

| Service | Intention (« je veux… ») | Point d'entrée | Statut |
|---|---|---|---|
| **Juger l'exposition runtime** | savoir si mon produit servi expose une configuration dangereuse | `node scripts\capturer.mjs <url> <capture.json> puis node oracles\oracle-exposition.mjs <capture.json>` | prouvé (experimental) |
| **Scanner les dépendances vulnérables (SCA)** | savoir si mes dépendances portent des CVE connues, avec seuils | `node oracles\oracle-sca.mjs <racine-produit> [--seuils f.json]` | prouvé (experimental) |
| **Tenir un contrat de sécurité ASVS L1** | m'engager sur un niveau de sécurité vérifiable et daté | `referentiels\asvs-l1.md (frontmatter challenge_date)` | déclaré (experimental) |
| **Juger un scan dynamique (DAST)** | savoir ce qu'un scan ZAP relève sur une cible **autorisée par écrit**, en verdict à seuils | `node oracles\oracle-dast.mjs --cible <url> --autorisation <f.json> [--rapport <zap.json>]` | prouvé pour le garde-fou, la lecture de rapport et les modes passif et actif (vrai ZAP, cible de fixture locale, 12/11/2026) ; applications riches et authentifiées non prouvées |
| **Dérouler une méthode de test de sécurité** | savoir *comment* on teste une exigence ASVS, cas par cas | `referentiels\wstg-cas.md` (39 cas WSTG 4.2 curés, rattachés à `asvs-l1.md`) | déclaré (experimental) |
| **Commander une revue de code** | faire relire le code d'un produit par un agent, sous plafond de jetons et au format de rapport fixe | `referentielsevue-de-code.md` (consigne type, tranches de 2 000 lignes, 4 statuts de constat) | déclaré (experimental) |

Le catalogue consolidé des dix forges vit chez le pilot :
[digit-ai-factory/catalogues/CATALOGUES.md](https://github.com/iguane39/digit-ai-factory/blob/main/catalogues/CATALOGUES.md).

## Délimitation — websec vs agents-security

**Deux objets, zéro recouvrement**, prouvé au verdict de non-recouvrement de l'étude
d'opportunité (§1b, catalogue v1.3.0) :

| Forge | Juge | Ne juge PAS |
|---|---|---|
| **`digit-ai-forge-websec`** (ici) | le **PRODUIT web livré** : sa configuration de sécurité runtime (en-têtes HTTP, cookies) et celle qu'en déclare un fichier `_headers`, ses dépendances vulnérables, le durcissement des workflows GitHub Actions qui le livrent, sa conformité à un contrat ASVS curé | l'outillage agentique qui a construit le produit |
| [`digit-ai-forge-agents-security`](https://github.com/iguane39/digit-ai-forge-agents-security) | l'**OUTILLAGE agentique** : définitions d'agents, appels d'outils, capacités et permissions | le produit livré lui-même — aucune notion de HTTP, de dépendance npm/pip, ni d'ASVS |

Un agent qui a construit un site peut être scanné sain par `agents-security` et livrer un
site sans aucun en-tête de sécurité — les deux forges répondent à des questions différentes,
et aucune ne se substitue à l'autre. Réciproquement, `websec` ne sait rien dire de la
sécurité d'un `agent.def` ou d'un journal d'appels d'outils.

## Doctrine

- **Le juge ne vit pas chez le jugé.** `forge-development` construit le produit ; elle ne
  peut pas être son propre contrôle de sécurité runtime — d'où une forge séparée.
- **Invocation sur mandat humain**, via le pilot (`digit-ai-factory`). Cette forge
  n'audite jamais spontanément un dépôt ou une URL tiers.
- **Elle outille, ne décide jamais.** Un verdict `FAIL` est un constat argumenté et localisé
  — jamais un blocage automatique d'une MEP, jamais une correction appliquée à la place d'un
  humain.
- **Zéro API tierce payante, zéro dépendance npm.** Cinq oracles + un script de capture,
  Node natif (`.mjs`), aucune installation requise pour la partie propre à cette forge.
  `oracle-sca` et `oracle-dast` **délèguent** à l'outillage déjà présent sur le poste (npm,
  pip-audit ou uvx, OWASP ZAP) — ils ne l'installent jamais et ne dégradent jamais silencieusement
  leur verdict quand cet outillage manque (SKIP motivé, jamais un PASS par défaut).
- **Zéro donnée réelle.** Dépôt public : toutes les fixtures sont synthétiques (URLs, cookies,
  dépendances fictives ou à CVE publique déjà connue) — aucune donnée client, aucun secret.

## Catalogue v0 — statut prouvé

> « prouvé » = preuve exécutée (fixture rejouée par `self-test.mjs`) ; « déclaré » = méthode
> documentée seulement. Un service sans preuve n'apparaîtrait pas ici.

| Service | Intention (« je veux… ») | Point d'entrée | Statut |
|---|---|---|---|
| **Juger l'exposition HTTP d'une réponse** | connaître la configuration de sécurité (en-têtes, cookies) d'un produit avant sa MEP | `node oracles/oracle-exposition.mjs <capture.json>` | **prouvé** — 15 fixtures (`fixtures/exposition/`), 11 règles EX-1..EX-11 |
| **Capturer une réponse HTTP réelle** | produire l'entrée de l'oracle d'exposition depuis une URL réelle | `node scripts/capturer.mjs <url> [--sortie <fichier>]` | **prouvé** (fetch natif, zéro dépendance) — ne juge rien, capture seulement ; la valeur des cookies posés (TF-2095) et les autres porteurs de jeton (paramètres de forme jeton de l'URL et de Location, Authorization, Proxy-Authorization, Cookie, TF-2107 ; Content-Location, Link, Refresh, X-Auth-Token, WWW-Authenticate et le jeton caché dans une URL imbriquée ou percent-encodée, TF-2133) sont caviardés à la capture, noms et attributs gardés ; dans toute URL portée par un en-tête (Location, Report-To, Link, Reporting-Endpoints, `report-uri`…), la valeur de chaque paramètre est remplacée par position, quel que soit son nom (TF-2306) : schéma, hôte, chemin et noms des paramètres restent lisibles ; l'adresse capturée elle-même (champ `url`) et celle du message d'échec suivent la même règle de position (TF-2390) ; tout en-tête dont le nom contient token, key, secret, auth, session ou password est masqué, et le même motif juge les noms de paramètre d'URL séparés par `&` ou `;` (TF-2394, D-197 (c)) |
| **Juger un fichier `_headers`** | savoir, avant de déployer sur Cloudflare (Workers static assets ou Pages), si les en-têtes que déclare mon `_headers` tiennent les règles EX | `node oracles/oracle-exposition-statique.mjs <_headers \| dossier>` | **prouvé** — règles EX-1..EX-11 réutilisées sans copie, HD-1 et HD-2 sourcées sur developers.cloudflare.com (lu le 28/10/2026), 8 fixtures (`fixtures/exposition-statique/`) |
| **Juger les dépendances vulnérables** | savoir si les dépendances d'un produit portent des CVE connues | `node oracles/oracle-sca.mjs <dossier-cible>` | **prouvé** — npm (`npm audit`) et pip (`pip-audit`, ou `uvx pip-audit` ; `requirements.txt`, `uv.lock`, `poetry.lock`) enveloppés, fixtures vertes/rouges par écosystème, SKIP rendu comme un manque nommé si l'outillage ou le réseau manque |
| **Juger un scan dynamique (DAST)** | savoir ce qu'OWASP ZAP relève sur une cible autorisée, en verdict à seuils | `node oracles/oracle-dast.mjs --cible <url> --autorisation <f.json> [--rapport <zap.json>]` | **partiellement prouvé** — garde-fou dual-use, lecture de rapport ZAP, modes passif et actif et options de balayage prouvés par 41 cas de self-test (`fixtures/dast/`, ZAP simulé) ; exécution avec le vrai ZAP (Docker) prouvée contre une cible de fixture locale par `scripts/preuve-dast-actif.mjs` ; applications riches et authentifiées, et ZAP natif, non prouvés |
| **Juger les workflows GitHub Actions** | savoir si les workflows qui construisent et livrent mon produit donnent trop de droits, exécutent du code non épinglé ou injectable | `node oracles/oracle-workflows.mjs <dépôt \| dossier \| fichier.yml>` | **prouvé** — 5 règles WF-1..WF-5 sourcées sur docs.github.com (lu le 28/10/2026), 15 fichiers de fixtures (`fixtures/workflows/`), lecteur YAML natif identique à PyYAML sur 30 fichiers le 28/10/2026 |
| **Rejouer toutes les preuves** | vérifier en un geste que rien n'a régressé | `node oracles/self-test.mjs` | **prouvé** — 229 PASS, 0 FAIL, 0 SKIP à la dernière exécution (12/11/2026 ; 200 PASS et 1 SKIP avant TF-2444), dont le volet SCA dépendant de l'outillage réel du poste |

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

Les onze règles sont exportées par la fonction `jugerEnTetes(enTetes, { https })` (version 0.2.0) :
la lecture statique d'un fichier `_headers` les applique sans en recopier la logique.

### `oracle-exposition-statique.mjs` — un fichier `_headers` jugé par les règles EX (TF-1996)

Juge le fichier `_headers` de Cloudflare (Workers static assets ou Pages) avant tout déploiement.
Pour chaque requête sondée, il calcule les en-têtes que le fichier lui applique, puis les passe à
`jugerEnTetes` : ce sont les règles EX-1..EX-11 ci-dessus, aucune n'est réécrite. Les sondes sont
la racine `/` et un représentant de chaque motif valide (`*` et `:nom` remplacés par `x`).

| Règle | Détecte | Sévérité | Page qui la fonde |
|---|---|---|---|
| EX-1..EX-11 | Les défauts d'en-têtes ci-dessus, sur les en-têtes que reçoit chaque sonde ; le constat nomme ses sondes | celles d'`oracle-exposition` | — |
| HD-1 | En-tête posé hors de toute règle ; ligne sans `nom: valeur` ; motif qui ne commence ni par `/` ni par `https://` ; port ; plus d'un `*` | majeur | `workers/static-assets/headers/`, `pages/configuration/headers/` |
| HD-2 | Plus de 100 règles ; ligne de plus de 2 000 caractères | majeur | idem |

Calcul des en-têtes d'une sonde, d'après les pages lues le 28/10/2026 : toutes les règles dont le
motif correspond s'appliquent, une valeur posée deux fois est jointe par une virgule, et `! Nom`
retire l'en-tête. La preuve de la réutilisation est une équivalence jouée par la recette : un
`_headers` qui pose les en-têtes d'une capture lève exactement les règles de cette capture.

```
node oracles/oracle-exposition-statique.mjs <fichier _headers | dossier qui le contient>
```

Ce que la lecture ne voit pas est déclaré dans `non_juge`. Au premier rang : les en-têtes posés
par le code d'un Worker ou par Pages Functions, auxquels `_headers` ne s'applique pas, et la HSTS
réglée au niveau de la zone. Le site déployé se confirme par `capturer.mjs` puis
`oracle-exposition`.

### `oracle-sca.mjs` — deux écosystèmes enveloppés

| Écosystème | Manifeste requis | Outil délégué | Seuil par défaut |
|---|---|---|---|
| npm | `package.json` + `package-lock.json` | `npm audit --package-lock-only --json` (déjà présent, aucune installation) | `critical=0`, `high=0` |
| pip | `requirements.txt`, `uv.lock` ou `poetry.lock` | `pip-audit -r <requirements> --format json`, sinon `uvx --from pip-audit==2.10.1 pip-audit` | `vulnerabilites=0` (paquets touchés) |

```
node oracles/oracle-sca.mjs <dossier-cible> [--seuils <fichier.json>]
```

Un verrou `uv.lock` ou `poetry.lock` est lu par l'oracle (blocs `[[package]]`, `name` et
`version`) ; ses paquets de registre sont écrits épinglés dans un requirements temporaire,
hors de la cible, puis audités avec `--no-deps --disable-pip` : rien n'est résolu ni installé,
l'audit prend quelques secondes. Le projet lui-même (source `virtual` ou `editable` d'`uv`)
n'est pas une dépendance ; un paquet d'un autre type de source (git, chemin, URL, index privé)
n'est pas interrogeable et se nomme au manque. Deux versions du même nom (marqueurs de
résolution) sont auditées en deux lots, `pip-audit` refusant le doublon dans un fichier.

Quand `pip-audit` est absent du poste, l'oracle le lance par `uvx pip-audit` si `uvx` est
présent : `uvx` l'exécute dans un environnement isolé de son cache, sans installation globale
(l'oracle n'installe toujours rien). L'appel est épinglé à la version du remède
(`uvx --from pip-audit==2.10.1 pip-audit`) : sans cela, uvx prendrait la dernière version publiée et le
verdict changerait avec elle. Les deux voies ont le même délai de 240 s par appel (`pip-audit` direct
a mis 85, 90 et 174 s sur `pip-vulnerable`, `uvx` 159 s). Les champs `synthese.pip.outil` et
`synthese.pip.delai_s` disent quelle voie a servi et quel délai elle avait. Sans
`pip-audit` ni `uvx`, le remède du manque nomme la commande à lancer, version épinglée :
`pip install pip-audit==2.10.1` ou `uv tool install pip-audit==2.10.1` (ou installer `uv`, qui fournit `uvx`).

Un `SKIP` se rend comme un **manque nommé** (TF-2272) : le champ `manques` liste, par
manifeste non audité, l'écosystème, la cause (outil absent, audit indisponible, format non
reconnu, paquets hors registre) et le remède ; sur un `SKIP`, le champ `motif` le dit en une
phrase (« AUDIT NON JOUÉ, aucune dépendance jugée (ce n'est pas un PASS) — manque : … »). Une
porte de production qui lit un `SKIP` lit donc que l'audit n'a pas eu lieu, et pourquoi. Un
`PASS` peut porter des `manques` partiels (paquets hors registre) : ils restent dans les
`findings` (`SCA-SKIP`, sévérité `info`).

Sans manifeste exploitable NI outil disponible pour un manifeste présent : verdict `SKIP`
motivé, jamais un `PASS` silencieux — c'est une règle dure du mandat (TF-0123). Le champ
`seuils_appliques` de la sortie dit toujours si le seuil vient d'un fichier `--seuils` ou du
défaut embarqué. `WEBSEC_SCA_PIP_AUDIT` et `WEBSEC_SCA_UVX` désignent une commande à la place
de `pip-audit` / `uvx` (un chemin `.mjs` est joué par node ; un chemin injouable simule
l'absence) : c'est ce que la recette emploie pour rejouer les deux voies sans rien installer.

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
(`WEBSEC_DAST_ZAP`, puis les commandes du mode — résolues dans le `PATH`, jamais exécutées
« pour voir ») et lance le balayage **du mode demandé**, puis juge son rapport. Seuils par défaut
`high=0, medium=0` (`low`/`informational` comptés en synthèse, non bloquants), surchargeables
par `--seuils <f.json>`.

| Mode | Commande cherchée | Ce qui part vers la cible |
|---|---|---|
| `passif` (défaut) | `zap-baseline.py`, sinon l'image Docker épinglée (`zap-baseline.py`) | l'araignée et les règles passives, aucune règle d'attaque ; l'araignée **soumet les formulaires** qu'elle trouve (un POST, constaté le 13/11/2026), seule l'option `exclusions` du mandat l'en empêche |
| `actif` (`actif_autorise: true`) | `zap-full-scan.py`, `zap.sh` ou `zap.bat`, sinon l'image Docker épinglée (`zap-full-scan.py`) | l'araignée, puis l'attaque active de chaque URL trouvée |

Un mode ne se rabat jamais sur l'autre (TF-2444). Un ZAP qui ne sait que `baseline` ne rend pas un
« actif » : `SKIP` `DAST-ACTIF-IMPOSSIBLE`. Un ZAP qui attaque (`zap-full-scan.py`, ou le balayage
rapide de `zap.sh` / `zap.bat`, dont l'aide de ZAP 2.17.0 dit « The URL to attack ») ne sert pas un
« passif » : `SKIP` `DAST-PASSIF-IMPOSSIBLE`. Dans les deux cas rien n'est lancé.

**L'image Docker est épinglée par empreinte** (TF-2477) : `ghcr.io/zaproxy/zaproxy@sha256:781a2bda…`, ZAP 2.17.0, et non
l'étiquette mobile `stable`, dont les règles changeaient sans que la forge le sache. Une image absente du poste est un `SKIP`
qui nomme la référence à tirer (`docker pull`) ; l'oracle ne se rabat pas sur `stable` et ne tire rien. `WEBSEC_DAST_IMAGE`
désigne une autre image : sans empreinte ni version complète (`:2.17.0`), le verdict le dit (`DAST-IMAGE-MOBILE`, info) et consigne
l'identifiant local de l'image qui a tourné. Sur cette voie l'oracle passe aussi `-silent` à ZAP : `zap-baseline.py` et
`zap-full-scan.py` lancent sinon `-addonupdate` et installent `pscanrulesBeta` / `ascanrulesBeta` depuis le réseau, donc d'autres
règles que celles de l'image, et ce démarrage coûtait plusieurs minutes. Les règles de l'image sont listées dans
`referentiels/zap-regles.json` (lues sans réseau par `node scripts/lire-regles-zap.mjs --image <référence> --ecrire`, qui compare
ses lectures aux add-ons que ZAP dit charger) ; une alerte dont le nom n'y figure pas est signalée (`DAST-REGLE-HORS-IMAGE`, info,
jamais un changement de verdict). Un ZAP natif du poste n'est ni épinglé ni coupé de sa mise à jour : `synthese.balayage.maj_modules`
le dit. Changer d'image se décide : relire ses règles, puis changer la constante `IMAGE_DEFAUT` et la liste dans le même commit — le
self-test refuse l'écart.

Le fichier d'autorisation porte aussi les limites du balayage, les mêmes dans les deux modes :

| Champ | Effet sur ZAP | Mal formé |
|---|---|---|
| `en_tete_acces` `{nom, valeur}` ou `{nom, valeur_env}` | un en-tête ajouté à toute requête vers l'origine autorisée (règle `replacer`, bornée à cette origine) ; `valeur_env` nomme une variable d'environnement, pour ne pas écrire un secret dans le mandat | `DAST-AUTZ-CHAMPS` ; une variable absente refuse aussi le balayage |
| `debit_max_requetes_par_seconde` (nombre, 0 < n ≤ 1000) | un fil et `ceil(1000/n)` ms entre deux requêtes, pour l'araignée et pour l'attaque | `DAST-AUTZ-CHAMPS` |
| `exclusions` (liste de chemins, `/…`) | aucune requête vers l'origine autorisée + chemin (préfixe compris) : exclusion globale ZAP | `DAST-AUTZ-CHAMPS` |
| `duree_max_minutes` (nombre, 0 < n ≤ 1440) | ZAP est arrêté au bout de cette durée | `DAST-AUTZ-CHAMPS` |
| `plafond_requetes` (entier, 1 à 1 000 000 ; exige le débit) | la durée se déduit : plafond × délai entre requêtes + 5 min de démarrage | `DAST-AUTZ-CHAMPS` |

**Délai de ZAP (0.3.0, TF-2486).** `duree_max_minutes` s'il est déclaré ; sinon, avec un débit, la
durée de `plafond_requetes` requêtes (1000 par défaut) plus 5 min, jamais moins de 30 min ; sinon 30
min. Le délai est toujours borné par la fin de la fenêtre d'autorisation. À 10 requêtes par minute, il
vaut 105 min, là où le délai fixe de la 0.2.0 coupait ZAP vers la 299e requête. Quand il est
dépassé, l'oracle arrête l'arbre de processus entier (`taskkill /T` sous Windows, groupe de processus
ailleurs, `docker rm -f` du conteneur nommé) et rend `SKIP` `DAST-DELAI`. `synthese.balayage` porte le
délai retenu et sa source.

**Lancement sur Windows (0.3.0, TF-2485).** Node refuse de lancer un `.bat` ou un `.cmd` sans shell
(`EINVAL`, mesuré sous Node v24.16.0). `zap.bat` passe donc par `cmd.exe /d /v:off /s /c`, chaque
argument entre guillemets ; un argument qui porte `"` ou `%` n'est jamais réécrit et rend `SKIP`
`DAST-LANCEMENT`. ZAP natif tourne dans son propre dossier, avec `-dir` vers un dossier de travail
jetable. Un lancement refusé par le système est dit avec son code d'erreur.

Une option présente et mal formée refuse le balayage : il ne part jamais sans une limite que le
mandat avait posée. La voie `--rapport` n'émet rien et ne lit pas ces champs. La valeur de l'en-tête
ne sort jamais dans le verdict (`synthese.balayage` en garde le nom) ; elle figure dans la ligne de
commande du processus ZAP le temps du balayage.

```
node oracles/oracle-dast.mjs --cible https://recette.exemple.tld \
     --autorisation autorisation.json [--rapport zap.json] [--seuils s.json] [--mode passif|actif]
```

Ce que cet oracle **ne juge pas** est déclaré dans son champ `non_juge` — au premier rang :
il vérifie une **déclaration écrite et traçable**, jamais la sincérité du consentement ; et
une absence d'alerte ZAP n'est jamais une absence de vulnérabilité.

### `oracle-workflows.mjs` — 5 règles WF-1..WF-5 (TF-2001)

Juge les fichiers `.github/workflows/*.yml|*.yaml` d'un dépôt, d'un dossier de workflows ou un
fichier seul. Lecture statique : rien n'est exécuté, GitHub n'est jamais contacté. Chaque constat
porte un champ `source`, la page de docs.github.com qui fonde la règle, lue le 28/10/2026.

| Règle | Détecte | Sévérité | Page qui la fonde |
|---|---|---|---|
| WF-1 | Job sans clé `permissions`, ni au workflow ni au job ; `write-all` ; valeur non documentée | majeur | `actions/reference/security/secure-use`, `workflow-syntax#permissions` |
| WF-1 | Écriture posée au niveau du workflow et héritée par un job (`id-token` n'en est pas une) | **mineur** | idem : lecture seule par défaut, élevée job par job |
| WF-2 | Action ou workflow réutilisable tiers non épinglé par SHA complet de 40 caractères | majeur | `secure-use#using-third-party-actions`, `find-and-customize-actions#using-shas` |
| WF-2 | Même défaut sur une action des organisations `actions` ou `github` | **mineur** | « Pin actions to a tag only if you trust the creator » |
| WF-2 | Référence inscrite au verrou `.github/workflows/actions.lock` du dépôt | info | `concepts/security/workflow-dependency-lockfiles` (préversion publique) |
| WF-3 | Déclencheur `pull_request_target`, bloqué par défaut en dépôt public à partir du 2 décembre 2026 | majeur | `securely-using-pull_request_target`, `about-actions-policies` |
| WF-3 | Checkout de la tête de la pull request sous ce déclencheur (`ref`, `repository`, `allow-unsafe-pr-checkout`) | bloquant | idem, forme « pwn request » |
| WF-4 | Contexte non fiable substitué dans un `run:` (`github.event.…` finissant par `body`, `title`, `ref`… ; `github.head_ref`), directement ou par une variable `env` qui le porte | bloquant | `concepts/security/script-injections` |
| WF-5 | Secret long passé à l'une des 8 actions de connexion dont GitHub documente l'OIDC, dans un job sans `id-token: write` | majeur | `concepts/security/openid-connect` et le guide du fournisseur |

```
node oracles/oracle-workflows.mjs <dépôt | dossier de workflows | fichier.yml>
```

Le lecteur YAML est natif, sans dépendance. Il couvre le sous-ensemble qu'emploient les workflows et
**refuse** le reste (ancres, alias, étiquettes, clés complexes) : le fichier est alors dit non jugé
(règle `—`, verdict `FAIL`), jamais un `PASS` silencieux. Comparé à PyYAML le 28/10/2026 sur 30
fichiers (15 workflows de produits du poste et 15 fixtures), il a rendu 30 lectures identiques.
Ce que l'oracle ne voit pas est déclaré dans `non_juge` : au premier rang, la visibilité du dépôt et
les permissions par défaut réglées hors fichier.

### Contrat de sortie (tous les oracles)

```json
{ "oracle": "...", "version": "0.1.0", "artefact": "...", "verdict": "PASS|FAIL|SKIP",
  "findings": [{ "sev": "bloquant|majeur|mineur|info", "regle": "EX-1", "msg": "...", "where": "..." }],
  "non_juge": ["..."] }
```

Exit `0` = PASS, `1` = FAIL, `2` = SKIP. `oracle-sca` et `oracle-dast` ajoutent `synthese`
(compteurs) et `seuils_appliques` (source + valeurs). `oracle-workflows` ajoute `synthese`
(fichiers lus et jugés, jobs, étapes, constats par règle) et `sources[]` (`url`, `lu_le`), et
chacun de ses constats porte `source`. `oracle-exposition-statique` ajoute `sondes` (en-têtes
calculés par sonde), `synthese` et `sources[]`. Pour `oracle-dast` : `FAIL` couvre aussi
le **refus du garde-fou** (rien n'a été émis) et `SKIP` les cas où rien n'a pu être jugé
— aucune cible fournie, ZAP absent du poste, ou ZAP d'une forme que le mode refuse
(`DAST-ACTIF-IMPOSSIBLE`, `DAST-PASSIF-IMPOSSIBLE`). La `synthese.balayage` dit le mode joué, la
forme du ZAP, le débit, les exclusions et le nom de l'en-tête d'accès (jamais sa valeur).

## Référentiel `referentiels/asvs-l1.md`

Sous-ensemble curé du niveau **L1** de l'OWASP ASVS 5.0.0 (mai 2025, CC BY-SA 4.0) —
identifiants **cités**, texte intégral **non recopié** (voir le fichier pour l'attribution
complète et le lien vers le standard). Chaque exigence porte : l'ID ASVS, un résumé en une
ligne française, le moyen de vérification (`oracle-exposition` | `oracle-sca` | `revue
humaine`) et son statut (`outillé` | `manuel`). Depuis la 0.2.0 (03/11/2026) il couvre aussi les
exigences L1 de V2, V5 et V8 (logique métier, fichiers, contrôle d'accès). `challenge_date: 2026-08-12` — à re-challenger
en fraîcheur avant tout usage éloigné de cette date.

## Référentiel `referentiels/wstg-cas.md`

Sous-ensemble curé de l'**OWASP Web Security Testing Guide 4.2** (déc. 2020, dernière version
stable au 14/08/2026 ; CC BY-SA 4.0) — identifiants **cités**, fiches **non recopiées**.
Là où `asvs-l1.md` dit *ce qu'on exige*, ce document dit *comment on le teste* : **39 cas**
(36 rattachés à une exigence L1 nommée d'`asvs-l1.md`, 3 aux règles outillées classées L2/L3),
chacun avec son geste de vérification et son outillage (`oracle-exposition` | `oracle-dast` |
`manuel`). Deux chapitres entiers (ERRH, APIT) et 56 cas nommés restent **non
curés**, listés explicitement dans le fichier — leur chapitre ASVS n'est pas curé non plus.
`challenge_date: 2026-08-14` (re-challenger à la publication d'une WSTG v5.0). Depuis la 0.2.1
(TF-2460), le fichier dit aussi ce que le **mode actif** d'`oracle-dast` couvre (11 cas, par le nom de la
règle ZAP qui les vise) et sous quelle autorisation ; son frontmatter porte `oracle_dast`, la version de
l'oracle décrite, que le self-test compare à la version courante.

## Référentiel `referentiels/classes-attaque.md`

Liste datée des **classes d'attaque qu'une revue de code doit chercher** : 9 classes de base (injection,
contrôle d'accès, ressources et fichiers, cryptographie et secrets, logique métier, abus de fonction,
chaînes de confiance, joker, évidences) et 117 classes fines des familles qui touchent un produit web,
plus 36 classes hors produit web nommées par groupe. Source : `security-audit-skill` de Cloudflare,
licence MIT, commit `c1c8a8c` du 14/09/2026 (avis de droits dans le fichier). Chaque classe est recoupée
avec `asvs-l1.md` et `wstg-cas.md` et dit ce qu'un oracle de la forge en lit aujourd'hui. Le fichier ne
nomme aucun produit, ne contient aucune faille réelle et n'est lu par aucun oracle. La relecture d'un
produit n'a lieu que sur mandat qui le nomme. `challenge_date: 2026-11-02`, prochaine revue le
2027-02-02.

## Référentiel `referentiels/revue-de-code.md`

Ce qui fixe **comment** une revue de code se commande, se borne et se rend : la consigne type de
l'agent, un plafond de 300 000 jetons tenu par tranches de 2 000 lignes, la forme du rapport et 4
statuts de constat (lu, relu, rejoué, non confirmé) qui mesurent la part de faux constats. Issu de
l'étude 20261103k du pilot et de la décision humaine D-162 (a) du 03/11/2026. La revue reste sur
décision humaine ; l'étape de mise en production du pilot la propose (`ETAPE-MEP.md` § 1 quater) et ne
bloque jamais. Aucun oracle ne lit un rapport de revue. `challenge_date: 2026-11-03`, prochaine revue
le 2026-12-01.

## Rejouer les preuves

```
node oracles/self-test.mjs
```

`oracle-exposition` (15 fixtures), `oracle-exposition-statique` (8 fixtures, 16 contrôles),
`oracle-workflows` (15 fichiers de fixtures, 19 contrôles) et le volet garde-fou/rapport
d'`oracle-dast` (13 cas, plus 28 cas du mode actif et des options de balayage) sont **entièrement
déterministes** — zéro réseau, zéro dépendance de poste, et **aucun scan n'est
lancé par le self-test**, fût-il autorisé (les cas d'exécution forcent `WEBSEC_DAST_ZAP` sur un
chemin injouable, ou sur un ZAP simulé qui enregistre sa ligne de commande sans rien émettre). Le volet `oracle-sca` dépend de l'outillage **réellement présent** sur
le poste qui exécute le self-test (npm, pip-audit ou à défaut uvx) et de l'accès réseau à leurs bases
d'avisos ; en leur absence, le self-test consigne un **SKIP motivé** par cas, qui nomme la
commande d'installation épinglée de `pip-audit` — jamais compté
comme une preuve du sens rouge, jamais présenté comme un succès. Rejouer avant toute
confiance dans une modification — un `✓` sans self-test rejoué n'est pas un `✓`.

La preuve **avec le vrai ZAP** du mode actif est un banc à part, hors self-test :

```
node scripts/preuve-dast-actif.mjs [--oracle <oracle-dast.mjs>] [--debit 10] [--scenarios A,B,C]
```

Il exige Docker et l'image épinglée de l'oracle (`ghcr.io/zaproxy/zaproxy@sha256:781a2bda…`) déjà présentes (sinon `SKIP` motivé, exit 2),
démarre `fixtures/dast/cible-locale.mjs` sur `127.0.0.1` et ne balaie rien d'autre. La preuve se lit au
journal de la cible, pas au rapport de ZAP : A (passif) ne reçoit aucune sonde active, B (actif sans
option) en reçoit et atteint la route que C (actif avec options) n'atteint jamais, avec l'en-tête sur
toute requête privée et un pic de requêtes par seconde sous la borne. Compter plusieurs minutes par
scénario (ZAP démarre et se met à jour avant de balayer).

La preuve **avec le vrai ZAP** du mode passif (TF-2476) est un second banc, hors self-test :

```
node scripts/preuve-dast-passif.mjs [--oracle <oracle-dast.mjs>]
```

Même image épinglée, déjà présente. Il démarre `fixtures/dast/cible-passive.mjs` (cookie sans attribut, en-têtes CORS ouverts,
formulaire sans jeton) sur `127.0.0.1`, lance la passe passive et rend, cas par cas (SESS-02, CLNT-07, SESS-05), si la règle de
l'image a été levée : `referentiels/wstg-cas.md` en reprend le résultat dans sa section du mode passif. Compter une minute.

## Limites explicites (ce que la v0 n'est pas)

- **DAST : dette D-W1 CLOSE le 14/08/2026 (TF-0206), exécution réellement prouvée.**
  `oracle-dast.mjs` enveloppe ZAP et traduit son rapport en verdict à seuils ; garde-fou
  dual-use et lecture de rapport prouvés par fixtures. La **branche d'exécution a tourné** :
  ZAP 2.17.0 via l'image officielle `ghcr.io/zaproxy/zaproxy:stable`, passe baseline passive
  sur une instance de recette servie localement et **autorisée par un mandat écrit**, rapport
  JSON produit par ZAP lui-même, verdict FAIL sur trois alertes *medium* réelles (absence de
  jeton anti-CSRF, en-tête CSP absent, anti-clickjacking absent). Le garde-fou a été rejoué
  dans le même souffle : la même autorisation refuse une cible hors périmètre, « rien n'a été
  émis vers la cible ».
- **Le mode actif a tourné le 12/11/2026 (TF-2444), sur une cible de fixture locale.**
  `scripts/preuve-dast-actif.mjs` lance le vrai ZAP 2.17.0 (image Docker) contre
  `fixtures/dast/cible-locale.mjs` et lit ce que la cible a reçu : le mode actif envoie des sondes
  actives, le mode passif aucune ; l'exclusion, l'en-tête d'accès et le débit du mandat tiennent. Avant
  la correction, le même balayage actif ne livrait que la passe passive (voir `CHANGELOG.md`).
- **Ce qui reste non prouvé, et doit le rester tant que personne ne l'a exercé** : l'installation
  NATIVE de ZAP sur ce poste (le JRE réclame une élévation, la voie Docker a été retenue) — les
  formes `zap-baseline.py`, `zap-full-scan.py`, `zap.sh` et `zap.bat` ne sont prouvées que par un ZAP
  simulé qui enregistre sa ligne de commande (depuis la 0.3.0, `zap.bat` et `zap.sh` sont de vrais
  scripts qui l'enveloppent), et le balayage rapide du vrai ZAP natif n'a jamais été lancé ; et le comportement sur une application réelle, riche et authentifiée — les cibles de preuve
  sont une page statique (14/08/2026) et une cible de fixture de quatre routes (12/11/2026).
- **Aucun scan sans autorisation écrite.** `oracle-dast` refuse (`FAIL`, exit 1) toute cible
  qui n'est pas nommément déclarée dans un fichier d'autorisation daté et en cours de validité
  — la production exige en plus une autorisation distincte, et le mode actif une mention
  explicite. Ce refus est structurel, pas une option : il ne se désactive pas.
- **Pas de pentest manuel.** Cette forge outille des vérifications machine reproductibles ;
  elle ne remplace ni un audit de sécurité humain, ni un test d'intrusion. `wstg-cas.md`
  décrit une **méthode**, il ne l'exécute pas : 21 de ses 39 cas sont manuels seuls, et 4 autres
  le sont avec une part relevée par ZAP ; les alertes d'`oracle-dast` sont des signaux à qualifier.
- **`oracle-sca` dépend du poste.** Aucun outil SCA n'est installé par cette forge ; si
  aucun de npm/pip-audit/uvx n'est présent (ou si le réseau vers leur base d'avisos est
  injoignable), le verdict est `SKIP` motivé, rendu comme un manque nommé — jamais un `PASS`
  faute de preuve. Les verrous `uv.lock` et `poetry.lock` sont audités paquet par paquet de
  registre ; les paquets d'une autre source (git, chemin, URL, index privé) ne le sont pas.
  Un paquet que `pip-audit` lui-même ne trouve pas sur PyPI et saute (`skip_reason`) compte au
  total sans être jugé : l'oracle ne le nomme pas encore.
  `osv-scanner` (multi-écosystème) n'est **pas** enveloppé en v0, faute de poste équipé pour
  le prouver par fixture.
- **`oracle-workflows` lit des fichiers, pas un dépôt GitHub.** Il ne voit ni la visibilité du
  dépôt (la politique par défaut sur `pull_request_target` ne vise que les dépôts publics), ni les
  permissions par défaut du jeton réglées dans le dépôt ou l'organisation, ni les politiques
  Actions. Il ne suit pas les actions composites, les images `docker://` ni les dépendances
  transitives. Sa liste de contextes non fiables est celle que la page donne comme « typique ».
- **`oracle-exposition-statique` lit une déclaration, pas une réponse.** Les en-têtes posés par le
  code d'un Worker, par Pages Functions, par une règle de transformation ou par la zone (HSTS du
  certificat de bordure) lui échappent, comme ceux que Cloudflare ajoute de lui-même. Il ne sonde
  que la racine et un représentant par motif, et suppose une réponse servie en HTTPS.
- **`oracle-exposition` ne juge pas la couche TLS.** Version de protocole, suites de
  chiffrement, validité et chaîne du certificat sont hors périmètre — v0 juge la réponse
  applicative capturée par un `fetch`, pas une négociation TLS.
- **Référentiel WSTG partiel.** `referentiels/wstg-cas.md` ne cure que les cas rattachables à
  une exigence d'`asvs-l1.md` : 2 chapitres entiers (gestion d'erreurs, API) et 56 cas
  nommés restent dehors. L'absence de constat sur eux n'est pas un
  constat d'absence de défaut.
- **Référentiel ASVS partiel.** `referentiels/asvs-l1.md` cure un sous-ensemble du niveau L1
  centré sur les chapitres couverts par les deux oracles (V3, V15) et quelques chapitres
  adjacents (V1, V2, V5, V6, V8, V12, V13, V14) — 7 chapitres restent non curés (V4, V7, V9, V10,
  V11, V16, V17), listés explicitement dans le référentiel (jamais tus).
- **Pas de décision.** Un verdict `FAIL` ne bloque rien tout seul — un humain ou un run amont
  décide de la suite via le pilot.

## Arborescence

```
oracles/
  oracle-exposition.mjs   juge une capture HTTP {url,status,headers} — 11 règles EX-1..EX-11 (exportées)
  oracle-exposition-statique.mjs  juge un fichier _headers de Cloudflare — règles EX réutilisées, HD-1, HD-2
  oracle-sca.mjs          enveloppe npm audit / pip-audit (ou uvx pip-audit ; uv.lock, poetry.lock) en verdict machine normalisé
  oracle-dast.mjs         enveloppe OWASP ZAP — garde-fou dual-use fail-closed + seuils
  oracle-workflows.mjs    juge les workflows GitHub Actions — 5 règles WF-1..WF-5, lecteur YAML natif
  self-test.mjs           rejeu intégral à double sens (277 contrôles le 13/11/2026)
scripts/
  preuve-dast-actif.mjs   banc réel du mode actif d'oracle-dast : vrai ZAP (Docker) contre la cible locale de fixture, hors self-test
  preuve-dast-passif.mjs  banc réel du mode passif d'oracle-dast : vrai ZAP (Docker) contre la cible passive de fixture, hors self-test
  lire-regles-zap.mjs     lit les règles de l'image ZAP épinglée (sans réseau) et écrit referentiels/zap-regles.json ; --verifier compare
  capturer.mjs            capture réelle fetch(url) → JSON d'entrée d'oracle-exposition
  caviarder-cookies.mjs   retire la valeur d'un Set-Cookie, nom et attributs gardés (appelé par capturer.mjs)
  caviarder-jetons.mjs    retire les jetons de l'URL (imbriquée ou encodée comprise), de Location, Content-Location, Link, Refresh, X-Auth-Token, WWW-Authenticate, Authorization et Cookie, tout en-tête dont le nom contient token, key, secret, auth, session ou password, et la valeur de tout paramètre d'une URL portée par un en-tête (appelé par capturer.mjs)
referentiels/
  asvs-l1.md              contrat de sécurité v0, sous-ensemble curé ASVS 5.0.0 niveau L1
  wstg-cas.md             méthode de test, 39 cas curés WSTG 4.2 rattachés à asvs-l1.md
  classes-attaque.md      classes d'attaque d'une revue de code, source Cloudflare (MIT), recoupées ASVS et WSTG
  revue-de-code.md        consigne, plafond par tranches et format du rapport d'une revue de code
  zap-regles.json         règles actives et passives de l'image ZAP épinglée par oracle-dast, lues dans l'image (TF-2477)
fixtures/
  exposition/             15 fixtures JSON (vertes + rouges) pour oracle-exposition
  exposition-statique/    8 fichiers _headers synthétiques : 1 vert, 7 rouges (EX par sonde, HD-1, HD-2)
  sca/                    manifestes npm/pip/uv/poetry synthétiques (vulnérables + propres) + cas SKIP, et outils/outil-simule.mjs (pip-audit et uvx simulés)
  dast/                   autorisations synthétiques (valide/expirée/production/incomplète, actif,
                          actif avec options), rapports ZAP synthétiques (propre/vulnérable), seuils
                          desserrés, zap-simule.mjs (ZAP simulé du self-test), docker-simule.mjs (Docker
                          simulé : image présente ou non, ligne de commande enregistrée), deux rapports
                          à règle hors image ou à variante, cible-locale.mjs (la cible de fixture du banc réel
                          du mode actif) et cible-passive.mjs (celle du banc du mode passif)
  workflows/              workflows synthétiques : 2 verts, 9 rouges (une par règle au moins),
                          1 mineur, un dépôt fictif avec verrou actions.lock
```
