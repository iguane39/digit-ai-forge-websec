# Journal des modifications — digit-ai-forge-websec

La forge n'a pas de numéro de version propre : ses tags `v0.1.0` à `v1.17.0` sont ceux des runs de
version de l'écosystème, posés par le pilot. Les unités versionnées ici sont les oracles (constante
`VERSION`, champ `version` de leur sortie) et les référentiels (frontmatter `version`). Ce journal
commence le 28/10/2026 ; l'historique antérieur se lit dans `git log`.

## 2026-11-13 — `oracle-dast` 0.2.1 : l'image ZAP est épinglée par empreinte, la mise à jour des modules est coupée, les règles de l'image sont listées (TF-2477)

- **Effet** : la voie Docker lançait `ghcr.io/zaproxy/zaproxy:stable`, une étiquette qui change d'image sans prévenir, et
  `zap-baseline.py` / `zap-full-scan.py` lançaient `-addonupdate` puis installaient `pscanrulesBeta` (et `ascanrulesBeta` pour le
  balayage complet) depuis le réseau : les règles qui tournaient n'étaient ni celles de l'image ni celles du référentiel. L'oracle
  lance maintenant `ghcr.io/zaproxy/zaproxy@sha256:781a2bda…` (ZAP 2.17.0) et passe `-silent` à ZAP, que les deux scripts lisent pour
  sauter la mise à jour. Une image absente du poste est un `SKIP` qui nomme la référence à tirer, sans repli sur `stable`.
  `WEBSEC_DAST_IMAGE` désigne une autre image : sans empreinte ni version complète, le verdict le dit (`DAST-IMAGE-MOBILE`) et garde
  l'identifiant local. Pour un ZAP natif, `synthese.balayage.maj_modules` dit que la mise à jour n'est pas maîtrisée.
- **Liste des règles** : `referentiels/zap-regles.json` (56 noms du côté actif, 108 du côté passif, 7 add-ons) est lue dans l'image par
  `scripts/lire-regles-zap.mjs`, sans réseau (deux conteneurs `--network none`). L'image porte DEUX versions de chaque add-on
  (`ascanrules` 78 et 83, `pscanrules` 70 et 75, `domxss` 23 et 24…) : le script prend la plus haute et refuse d'écrire si les versions
  que ZAP dit charger (`-cmd -silent -addonlist`) diffèrent, add-on par add-on. Une alerte dont le nom n'est pas dans la liste est
  signalée (`DAST-REGLE-HORS-IMAGE`, info : jamais un changement de verdict) ; `Nom (variante)` est admis quand `Nom` est listé.
- **Cause établie, et ce qui ne l'est pas** : la règle levée le 12/11/2026, « Source Code Disclosure - File Inclusion », n'est dans
  aucun add-on de l'image ; le code de `zap-full-scan.py` (lu dans l'image) installe `ascanrulesBeta` depuis le réseau sauf `-silent`.
  Que cette règle soit dans `ascanrulesBeta` n'est pas vérifié : ce module n'est pas dans l'image et n'a pas été téléchargé.
- **Référentiel** : `wstg-cas.md` passe à 0.2.2, `oracle_dast: 0.2.1`, avec une section « Image et règles » et la source de la liste. La
  barrière de TF-2460 a refusé l'ancien frontmatter (`oracle_dast: 0.2.0`) dès que l'oracle a changé de version : un FAIL constaté
  au premier rejeu complet, puis corrigé.
- **Image tirée ?** Non : l'image épinglée est la même que `stable` sur ce poste (empreinte lue, 3,71 Go, créée le 07/08/2026) ;
  rien n'a été téléchargé. Un poste dont `stable` est plus récent doit `docker pull` la référence épinglée.
- **Mesuré le 13/11/2026, avec le vrai ZAP, avant puis après** (`scripts/preuve-dast-actif.mjs`, mêmes trois scénarios, même cible de
  fixture ; « avant » lu dans le journal de l'agent qui avait joué la preuve le 12/11 — rapporté, non rejoué ici) : le scénario passif A
  passe de 240 s à 55 s puis 36 s (deux passes), le scénario actif B de 411 s à 138 s puis 142 s, le scénario actif C de 451 s à 217 s
  puis 207 s. Les requêtes reçues par la cible en B passent de 958 à 661 puis 663, dont 659 sondes actives avant et 516 puis 517
  après : la mise à jour coupée retire les règles bêta et le temps de démarrage. Les 16 assertions de la première passe tiennent ; la
  seconde, qui ajoute « image épinglée et aucune alerte hors des règles de l'image » pour chaque scénario, en compte 19 : 19 PASS,
  0 FAIL. `hors_liste` est vide aux trois balayages de la seconde passe : la règle « Source Code Disclosure - File Inclusion » levée
  le 12/11/2026 ne l'est plus (le balayage actif B de la cible de fixture est le même qu'alors).
- **Barrière** (classe `recette-verdict-non-prononcable`) : le self-test refuse une image par défaut qui n'est pas épinglée par
  empreinte, une liste de règles qui décrit une autre image que celle de l'oracle (l'une ne change plus sans l'autre), un `-silent`
  absent de la ligne de commande de l'image, et une alerte hors liste que l'oracle ne signale pas. La preuve réelle assertit en plus
  qu'aucune alerte d'un balayage n'est hors de la liste.
- **Banc** : 16 contrôles ajoutés, un Docker simulé (`fixtures/dast/docker-simule.mjs`, désigné par `WEBSEC_DAST_DOCKER`) qui enregistre
  la ligne de commande sans lancer de conteneur, deux rapports de fixture (règle hors image, variante entre parenthèses) et la
  variable `WEBSEC_DAST_REGLES` pour la liste illisible. Avant la correction, mêmes contrôles sur l'ancien oracle (PATH sans `docker`) :
  239 PASS, 13 FAIL ; après : 252 PASS, 0 FAIL, 0 SKIP (236 PASS, 0 FAIL, 0 SKIP avant, même poste). Aucune assertion existante n'est
  modifiée.
- **Reste non prouvé** : l'image épinglée n'a servi qu'à des balayages de fixtures locales ; ZAP natif (non épinglé, mise à jour non
  coupée) et application riche ou authentifiée restent hors preuve. Les règles bêta ne tournent plus sur la voie Docker : une cible
  qui n'était couverte que par elles ne l'est plus.

## 2026-11-12 — `wstg-cas.md` 0.2.1 : le référentiel dit ce que le mode actif d'`oracle-dast` couvre, et sous quelle autorisation (TF-2460)

- **Effet** : le référentiel écrivait qu'`oracle-dast` ne lève que ce qu'une passe passive voit, vrai jusqu'à la 0.1.x, faux depuis le
  mode actif réel de la 0.2.0 (TF-2444). Une section « Ce que le mode actif d'oracle-dast couvre » dit maintenant la forme de chaque mode,
  l'autorisation exigée (fichier écrit, origine exacte, fenêtre, `actif_autorise: true`, instance dédiée, options `en_tete_acces`,
  `debit_max_requetes_par_seconde`, `exclusions`), ce que l'oracle rend (des alertes ZAP, aucun identifiant WSTG) et ce qui n'est pas
  couvert. La colonne « Outillage » nomme, pour 11 cas, la règle ZAP qui les vise et le mode ; 7 cas deviennent `oracle-dast` (ATHZ-01,
  INPV-01, -05, -07, -11, -12, CLNT-04) et 4 restent manuels avec une part relevée (CONF-04, INPV-02, INPV-19, CLNT-01). Les comptes des
  limites passent de « 31 manuels » à 21 manuels seuls, 4 partiels, 7 `oracle-dast`, 7 `oracle-exposition`.
- **Mesuré le 12/11/2026, sur ce poste** : les noms des règles d'attaque active sont lus dans les modules `ascanrules` et `domxss` de l'image
  `ghcr.io/zaproxy/zaproxy:stable` (ZAP 2.17.0), sans balayage. Un balayage actif réel de la cible de fixture locale (290 s, 950 requêtes
  reçues, débit borné à 50 par seconde) a levé 4 alertes `high` (XSS reflété, injection SQL, XSS DOM, « Source Code Disclosure - File
  Inclusion ») et 3 `medium`. Cette dernière règle n'est pas dans l'image : le balayage a chargé des règles que l'image n'a pas, cause non
  vérifiée, et la liste des règles du référentiel est donc un minimum daté. Les cas ATHZ-01, INPV-02, -07, -11, -12, -19, CLNT-04 et CONF-04
  ne reposent que sur le nom d'une règle : la forge ne les a jamais vus levés, et le référentiel le dit.
- **Barrière** (classe `documentation-d-outil-differente-de-sa-sortie`) : le frontmatter porte `oracle_dast: 0.2.0`, la version décrite ;
  le self-test la compare à la constante `VERSION` de l'oracle, et refuse une ligne de cas qui cite `oracle-dast` sans nommer `passif` ou
  `actif`. Elle ne juge pas la prose : une version d'oracle qui change fait relire le référentiel, elle ne dit pas ce qu'il faut y écrire.
- **Banc** : 5 contrôles ajoutés au self-test. Avant la correction, le contrôle vert rendait FAIL (« frontmatter sans `oracle_dast` ») sur le
  fichier d'origine ; après, 236 PASS, 0 FAIL, 0 SKIP (231 PASS, 0 FAIL, 0 SKIP avant, même poste). Aucune assertion existante n'est modifiée.
  Trois contrôles rouges, à double sens : champ absent, version périmée, cas sans mode.

## 2026-11-12 — `oracle-sca` 0.2.2 : le délai de pip-audit direct suit celui d'uvx, et l'appel uvx est épinglé (TF-2455)

- **Effet** : `pip-audit` lancé directement avait 90 s par appel, `uvx` 240 s. Sur `pip-vulnerable` (django 1.4, des
  centaines d'avis), le premier met 85 à 174 s selon le réseau : un audit qui aurait réussi était rendu « indisponible »
  (`délai de 90 s dépassé`), et le self-test d'un poste complet gardait un SKIP. Les deux voies ont maintenant 240 s par appel,
  et `uvx` est appelé en `uvx --from pip-audit==2.10.1 pip-audit …`, la version que nomme le remède d'un SKIP « outil absent ».
  Sans `--from`, uvx prenait la dernière version publiée et le verdict changeait avec elle. `synthese.pip.delai_s` dit le
  délai de la voie qui a servi.
- **Avant, mesuré le 12/11/2026 sur ce poste** : trois appels de `pip-audit` direct sur `pip-vulnerable` ont pris 85 s (par
  l'oracle, FAIL rendu à temps), 90 s et 174 s ; le self-test intégral rendait 228 PASS, 0 FAIL, 1 SKIP, ce SKIP étant
  `pip-vulnerable` en `délai de 90 s dépassé`.
- **Après, même poste** : 231 PASS, 0 FAIL, 0 SKIP (17:49 à 17:54), `pip-vulnerable` rend FAIL avec `SCA-PIP` par la voie
  directe ; la voie `uvx` épinglée rend FAIL en 127 s sur la même fixture (`outil` : `uvx pip-audit`, `delai_s` : 240).
- **Banc** : 2 contrôles ajoutés à l'outil simulé : la trace de `outil-simule.mjs` garde le paquet nommé par `--from`, et le
  self-test lit la version du remède de l'oracle pour la comparer à celle de l'appel (une seule source) ; les deux voies
  portent le même `delai_s`, au moins 180 s. Double sens joué avec un `PATH` réduit à node, donc sans outil réel : le code de
  départ avec les nouveaux contrôles rend 224 PASS, 2 FAIL (appel non épinglé, `delai_s` absent) ; le code corrigé rend 226
  PASS, 0 FAIL. Aucune assertion existante n'est modifiée. Le délai lui-même n'a pas de cas déterministe : le prouver demanderait
  un outil simulé de plus de 90 s ; il se lit par `delai_s` et par la mesure ci-dessus.

## 2026-11-12 — `oracle-dast` 0.2.0 : le mode actif lance un vrai balayage actif, et l'autorisation porte en-tête, débit et exclusions (TF-2444)

- **Effet** : `--mode actif` exigeait `actif_autorise: true` puis lançait quand même `zap-baseline.py`, la passe passive.
  Il lance maintenant `zap-full-scan.py` (araignée, puis attaque active des URL trouvées), ou le balayage rapide de
  `zap.sh` / `zap.bat`, et le mode passif reste sur `zap-baseline.py`. Un mode ne se rabat jamais sur l'autre : un ZAP
  de la mauvaise forme rend un `SKIP` (`DAST-ACTIF-IMPOSSIBLE`, `DAST-PASSIF-IMPOSSIBLE`) et rien n'est lancé. Sans
  `actif_autorise: true`, le mode actif reste refusé (`DAST-AUTZ-MODE`), avant toute émission.
- **Options du mandat** : le fichier d'autorisation porte `en_tete_acces` (`{nom, valeur}` ou `{nom, valeur_env}`, pour ne
  pas écrire un secret dans le mandat), `debit_max_requetes_par_seconde` (un fil, `ceil(1000/n)` ms entre deux requêtes) et
  `exclusions` (chemins, préfixe compris). Elles valent dans les deux modes, car une limite que le mandat pose ne se tient
  pas dans un seul. Une option mal formée, ou une variable d'en-tête absente, refuse le balayage (`DAST-AUTZ-CHAMPS`). La
  valeur de l'en-tête ne sort pas du verdict ; la règle `replacer` de ZAP est bornée à l'origine autorisée.
- **Constat traité sur la même ligne** : le balayage rapide de `zap.sh` / `zap.bat` (`-quickurl`, « The URL to attack » dans
  l'aide de ZAP 2.17.0) servait le mode passif jusqu'ici, et attaquait. Il est maintenant refusé en passif.
- **Avant, mesuré avec le vrai ZAP 2.17.0 (image Docker) contre `fixtures/dast/cible-locale.mjs`** : un balayage `--mode actif`
  avec `actif_autorise: true` a livré 8 requêtes en 0,4 s, 0 sonde active (la route d'exclusion atteinte une fois, aucun
  en-tête), en 219 s dont l'essentiel est le démarrage de ZAP.
- **Après, même banc** (`scripts/preuve-dast-actif.mjs`, une exécution des scénarios A, B et C, 16 assertions, 16 PASS,
  0 FAIL) : passif, 7 requêtes, 0 sonde active, 0 requête vers la route exclue, 1 requête privée sur 1 avec l'en-tête ;
  actif sans option (témoin), 958 requêtes dont 659 sondes actives, 40 requêtes vers la route à exclure, 0 en-tête sur 39
  requêtes privées, pic de 134 requêtes/s ; actif avec les trois options (borne de 10/s), 891 requêtes dont 634 sondes
  actives, 0 vers la route exclue, l'en-tête sur 40 requêtes privées sur 40, pic de 9 requêtes/s. Une première série
  (C seul, puis A et B) avait donné les mêmes verdicts. Essai séparé : une règle `replacer` dont `url` ne correspond pas à
  la cible laisse la requête privée sans l'en-tête (0 sur 1), donc la clé borne bien la règle.
- **Banc** : 28 cas ajoutés au self-test, avec un ZAP simulé (`fixtures/dast/zap-simule.mjs`) qui enregistre sa ligne de
  commande sans rien émettre ; chaque cas force `WEBSEC_DAST_ZAP` sur lui, et le self-test ne lance toujours aucun scan.
  Contre le code d'origine, les cas du mode actif échouent (obtenu SKIP : l'ancien code ne sait pas jouer le ZAP simulé),
  ce qui ne reproduit pas le défaut : la reproduction est la mesure avec le vrai ZAP ci-dessus. Les 13 cas existants passent
  sans modification d'assertion. Self-test intégral : 200 PASS, 0 FAIL, 1 SKIP avant (le SKIP : `pip-audit` direct au-delà de
  90 s, étranger à l'item) ; 229 PASS, 0 FAIL, 0 SKIP après, soit 28 cas ajoutés et ce contrôle réseau qui passe cette fois.
- **Reste non prouvé** : ZAP natif (aucune installation sur le poste ; `zap.sh` en balayage rapide jamais lancé), application
  riche et authentifiée (la cible de preuve compte quatre routes). La valeur de l'en-tête figure dans la ligne de commande du
  processus ZAP le temps du balayage, ce que le verdict déclare dans `non_juge`.

## 2026-11-12 — `oracle-sca` 0.2.1 et self-test : le SKIP « pip-audit absent » nomme la commande épinglée, et uvx sert (TF-2398)

- **Effet** : sur un poste sans `pip-audit` mais avec `uvx`, le self-test jouait les sens rouge et vert pip en SKIP
  (« pip-audit absent du poste ») alors que l'oracle sait lancer `uvx pip-audit` depuis 0.2.0 ; il les joue maintenant par
  `uvx`, et ces deux contrôles passent. Sur un poste sans les deux, chaque SKIP nomme la commande, lue du remède de l'oracle
  (une seule source) : `pip install pip-audit==2.10.1` ou `uv tool install pip-audit==2.10.1`, ou installer `uv`.
  Le remède du manque d'`oracle-sca` (« installer pip-audit ou uv ») donne la même commande ; la version 2.10.1 est celle
  mesurée sur le poste le 12/11/2026. L'appel `uvx pip-audit` lui-même n'est pas épinglé (inchangé).
- **Banc** : `runJson` prend un délai en paramètre ; les deux contrôles pip réels attendent 300 s, car `uvx` met 159 s à
  résoudre `django==1.4` dans son environnement isolé (mesuré) et l'oracle lui laisse 240 s : à 120 s, un audit réussi
  était lu `ILLISIBLE`. Aucune assertion n'est modifiée.
- **Preuve** : 3 contrôles ajoutés (`pip-clean`, `uv-propre`, `poetry-propre` sans les deux outils → remède épinglé). Sur
  l'état de départ avec ce banc : 197 PASS, 3 FAIL (remède « installer pip-audit ou uv »). Poste sans `pip-audit`, `uvx`
  présent : 196 PASS, 0 FAIL, 2 SKIP avant ; 201 PASS, 0 FAIL, 0 SKIP après. Poste sans les deux : 196 PASS, 0 FAIL, 3 SKIP
  nommant la commande. Poste complet : 200 PASS, 0 FAIL, 1 SKIP (`pip-audit` direct dépasse 90 s sur `pip-vulnerable`,
  antérieur et non traité ici).

## 2026-11-10 — `scripts/caviarder-jetons.mjs` : le nom d'un en-tête ou d'un paramètre est jugé par motif (TF-2394, D-197 (c))

- **Effet** : un en-tête dont le nom contient `token`, `key`, `secret`, `auth`, `session` ou `password` (sans casse, séparateurs
  `-`, `_`, `.` ignorés) est masqué à la capture. Avant, seul `X-Auth-Token` l'était par son nom : `X-API-Key`, `X-CSRF-Token`,
  `X-Access-Token` et `x-amz-security-token` entraient en clair dans la capture versionnée avec le produit. Le même motif juge
  les noms de paramètre d'URL et de paramètre de chemin, et la liste de paramètres se sépare maintenant sur `&` et sur `;` :
  `caviarderUrl("…?a=1;token=zzz")` laissait `zzz` en clair (la valeur de `a` portait tout le reste).
  Un en-tête à plusieurs valeurs est masqué élément par élément.
- **Inchangé** : `Authorization` et `Proxy-Authorization` (schéma conservé), `Cookie`, `Set-Cookie`, `WWW-Authenticate`
  (schéma, realm et error conservés) gardent leur traitement propre, qui passe avant le motif. Les en-têtes neutres sortent
  octet pour octet.
- **Portée dite** : sur l'adresse capturée et les URL d'en-tête, la position (TF-2306, TF-2390) masquait déjà `a=1;token=…`,
  car la valeur de `a` est remplacée en entier. La forme fautive vivait dans `caviarderUrl` (par nom), qui sert aux valeurs
  imbriquées et aux paramètres de chemin, et reste exportée. Les en-têtes à nom suspect, eux, fuyaient bien de bout en bout.
- **Faux positifs mesurés** (registre IANA des champs HTTP, `field-names.csv`, 260 noms, relevé le 10/11/2026 ; une valeur neutre
  passée à chaque nom) : 18 noms masqués. Quatre l'étaient déjà (Authorization, Proxy-Authorization, Cookie, Set-Cookie).
  Les 14 autres : Authentication-Control, Authentication-Info, Proxy-Authentication-Info, Concealed-Auth-Export,
  Optional-WWW-Authenticate, Proxy-Authenticate, CMCD-Session, CTA-Common-Access-Token, Include-Referred-Token-Binding-ID,
  Lock-Token, Public-Key-Pins, Public-Key-Pins-Report-Only, Sec-Token-Binding, Sec-WebSocket-Key. Masqués à tort, sans secret :
  les deux Public-Key-Pins (empreintes publiques), Sec-WebSocket-Key (nonce de poignée de main), Include-Referred-Token-Binding-ID
  (drapeau) et les défis Proxy-Authenticate, Optional-WWW-Authenticate et Authentication-Control (schéma et realm, que
  WWW-Authenticate garde lisibles). `Keep-Alive` n'est pas masqué : « keep » ne contient pas « key ». Hors registre :
  `:authority` (pseudo-en-tête HTTP/2, jamais rendu par `fetch`) serait masqué. Côté paramètres d'URL, sur 32 noms usuels testés,
  11 deviennent masqués : `token_type`, `keyword`, `keywords`, `author`, `authority`, `monkey`, `turkey`, `sessions`, `keyboard`,
  `hotkey`, `passwordless`.
- **Décision** : aucun n'est exempté. Aucun oracle de la forge ne lit ces noms, une liste d'exemption est l'endroit où un secret
  se glisse, et la perte (lisibilité d'un nom ordinaire dans une capture) coûte moins qu'un secret versionné. Le choix est épinglé
  par le banc (10 noms du registre et 4 noms d'URL attendus masqués) ; le revoir se fait en connaissance de ce banc.
- **Attente revue, aucune relâchée** : le bord d'URL de TF-2107 qui lisait `token_type=x` lit `token_type=[caviardé]`. Le commentaire
  qui disait `token_type` lisible est corrigé.
- **Limites dites** : le motif ne couvre pas `signature`, `sig`, `csrf`, `jwt` ni `code` comme nom d'en-tête (`X-Amz-Signature`,
  `Signature`, un en-tête `X-Csrf` sans « token » sortent en clair) ; ces mots restent jugés par la liste de noms pour les seuls
  paramètres d'URL. Un secret porté par un en-tête au nom neutre (`X-Foo`) n'est pas vu. Les captures déjà écrites ne sont pas réécrites.
- **oracle-exposition** : aucune règle ni `VERSION` ne change (0.2.0).
- **Où** : `scripts/caviarder-jetons.mjs` (motif, séparateur `;`, branche des en-têtes), `oracles/self-test.mjs` (deux nouveaux
  blocs, une attente revue), `README.md`.
- **Preuve** : valeurs factices assemblées à l'exécution. Banc du caviardage sur le code d'avant : 4 PASS, 17 FAIL (neuf en-têtes,
  le tableau, sept formes d'URL). De bout en bout, sur le `capturer.mjs` d'avant : 7 valeurs sur 8 survivent. Recette complète
  après : 198 PASS, 0 FAIL, 0 SKIP. Un premier passage de la recette sur l'arbre propre avait rendu 167 PASS, 3 FAIL, les trois
  sur `oracle-sca` (pip-audit lent sur le réseau du poste, fixtures pip et poetry rendues `ILLISIBLE`) ; ces fixtures rejouées une à
  une rendent PASS, FAIL, FAIL attendus, et le passage suivant est vert.

## 2026-11-10 — `scripts/capturer.mjs` : l'adresse capturée elle-même est caviardée par position (TF-2390)

- **Effet** : reste de TF-2306. Le champ `url` de la capture (l'adresse passée en argument) et l'adresse du message
  d'échec (`capture échouée pour …`) gardaient le caviardage par forme de nom : un lien d'accès passé en argument avec un
  paramètre de nom ordinaire (`?meta=<JWT>`, `?s=<signature>`, `#id=<valeur>`) entrait en clair dans la capture
  versionnée avec le produit. Désormais la valeur de chaque paramètre de requête et de fragment de l'adresse est
  remplacée par `[caviardé]` quel que soit son nom, par la règle de TF-2306 (`caviarderUrlEnTete`), sans second code.
  Restent lisibles : schéma, hôte, chemin et noms des paramètres
  (`http://hôte/acces/ouvrir?kid=[caviardé]&meta=[caviardé]&page=[caviardé]#id=[caviardé]`).
- **Défaut voisin trouvé en le reproduisant** : le MOTIF du message d'échec recopiait l'adresse en clair. `fetch` refuse
  un identifiant `utilisateur:mot-de-passe@` (« Request cannot be constructed from a URL that includes credentials : … »)
  et une adresse mal formée (« Failed to parse URL from … ») en citant l'adresse telle que passée ; le message d'échec
  la reprenait derrière l'adresse caviardée. Le motif est maintenant filtré : l'adresse brute y est remplacée par sa forme
  caviardée, puis toute autre adresse absolue du motif passe par `caviarderUrlsDeValeur`.
- **Changement de comportement voulu** : `page=2` d'une adresse devient `page=[caviardé]`, comme dans une URL d'en-tête.
  Trois attentes du banc, qui lisaient `page=2` (TF-2107, TF-2133 et le message d'échec de TF-2107), sont revues en
  ce sens, aucune relâchée ; l'attente de TF-2133 sur un `redirect_uri` encodé passe de « seul son code est remplacé » à
  « la valeur disparaît en entier ». La phrase de TF-2306 ci-dessous qui dit l'adresse capturée inchangée
  est remplacée par cette entrée. `caviarderUrl` (par forme de nom) reste exporté et sert encore aux valeurs imbriquées.
- **Limites dites** : celles de TF-2306, inchangées : un élément de requête sans `=` est tenu pour un nom (drapeau), donc un
  jeton nu (`?<jeton>`) n'est pas vu ; un jeton en segment de chemin reste non traité. Les captures déjà écrites ne sont
  pas réécrites. Un message du moteur qui citerait l'adresse sous une forme normalisée différente de celle passée est
  filtré par la seule règle des adresses absolues `schéma://…` : une adresse relative ou tronquée dans un tel message
  n'est pas vue.
- **oracle-exposition** : aucune règle ni `VERSION` ne change (0.2.0) ; il ne lit de l'adresse que le schéma, conservé.
- **Où** : `scripts/capturer.mjs` (deux appels, import), `oracles/self-test.mjs` (nouveau banc TF-2390, trois attentes
  revues), `README.md`.
- **Preuve** : le faux JWT de 684 caractères et les valeurs sont assemblés à l'exécution, jamais en clair dans le source.
  Banc des seuls blocs de capture (TF-2095 à TF-2390, harnais jetable hors dépôt) sur l'ancien `capturer.mjs` avec le nouveau
  banc : 61 PASS, 10 FAIL (7 contrôles de l'adresse, 3 attentes revues) ; puis, motif de l'échec ajouté et correction de
  l'adresse seule : 72 PASS, 2 FAIL (les deux messages du moteur, valeurs survivantes 8 et 6) ; avec le correctif
  complet : 74 PASS, 0 FAIL.

## 2026-11-09 — `scripts/capturer.mjs` : la valeur de chaque paramètre d'une URL d'en-tête est caviardée par position (TF-2306)

- **Effet** : troisième correction de la même classe (`capture-de-preuve-porte-un-jeton`, après TF-2107 et TF-2133). Une
  redirection Cloudflare Access a laissé en clair le paramètre `meta` de `Location` (un JWT de 684 caractères) et la
  signature `s` de `Report-To` : les deux corrections précédentes jugeaient la FORME du nom (`token`, `code`, `key`…), et
  `meta` comme `s` n'en ont pas. La capture versionnée avec le produit a été prise par son balayage de secrets.
  Désormais, dans toute URL portée par un en-tête, la valeur de chaque paramètre de requête ou de fragment est remplacée
  par `[caviardé]` quel que soit son nom. Restent lisibles : schéma, hôte, chemin et noms des paramètres
  (`…/app?kid=[caviardé]&meta=[caviardé]&redirect_url=[caviardé]`).
- **Périmètre** : `Location`, `Content-Location`, `Link`, `Refresh` et les URL de `WWW-Authenticate` passent par la
  nouvelle règle de position. Tout autre en-tête (`Report-To`, `Reporting-Endpoints`, `Content-Security-Policy` et son
  `report-uri`…) est parcouru pour ses URL absolues `schéma://…`, y compris dans un JSON à barres `\/` et `&`
  échappées ; le reste de la valeur (directives, `;`, JSON, `NEL`, `Access-Control-Allow-Origin`) sort octet pour octet.
- **Changement de comportement voulu** : un paramètre sans jeton d'une URL d'en-tête (`state`, `lang`, `page`) perd
  aussi sa valeur, et un `redirect_uri` encodé disparaît en entier avec son code. Six attentes de TF-2107 et TF-2133
  ont été durcies en conséquence (aucune n'a été relâchée) ; l'URL capturée elle-même (champ `url`) garde le caviardage
  par forme de nom de TF-2107 et TF-2133, inchangé et toujours testé.
- **Limites dites** : un élément de requête sans `=` est tenu pour un nom (drapeau) et reste, donc un jeton nu sans nom
  (`?<jeton>`) n'est pas vu ; une URL relative dans un en-tête autre que ceux de la liste (`report-uri /csp?t=…`) n'est
  pas vue, faute de `schéma://` ; un jeton dans un segment de chemin reste non traité (limite de TF-2133). Les captures
  déjà écrites ne sont pas réécrites.
- **Où** : `scripts/caviarder-jetons.mjs` (`caviarderUrlEnTete`, `caviarderUrlsDeValeur`, `caviarderUrl` accepte le
  traitement des paramètres en second argument), `scripts/capturer.mjs` (commentaire), `oracles/self-test.mjs`.
- **oracle-exposition** : aucune règle ni `VERSION` ne change (0.2.0) ; la capture caviardée est lue comme avant, CSP
  comprise (ni EX-1 ni EX-2 sur la fixture).
- **Preuve** : le faux JWT de 684 caractères, les signatures et les valeurs sont assemblés à l'exécution dans le
  self-test, jamais en clair dans le source. Sens rouge mesuré avant le code : 41 PASS, 16 FAIL (5 porteurs survivants,
  5 contrôles vert du nouveau banc, 6 attentes durcies de TF-2107 et TF-2133), puis arrêt sur `caviarderUrlEnTete is not
  a function` avant les 2 bancs de bords. Après : `node oracles/self-test.mjs` 154 PASS, 0 FAIL, 2 SKIP motivé
  (`pip-audit` absent du poste) ; avant le changement 137 PASS, 0 FAIL, 2 SKIP. 17 contrôles ajoutés.

## 2026-11-06 — `oracle-sca` 0.2.0 : uv.lock, poetry.lock, uvx, et un SKIP qui nomme son manque (TF-2272)

- **Effet** : sur un produit Python géré par `uv` ou `poetry` (`pyproject.toml` + verrou, sans `requirements.txt`),
  l'oracle rendait « aucun manifeste reconnu » puis, avec un `requirements.txt` exporté, un SKIP faute de
  `pip-audit`. Il lit maintenant `uv.lock` et `poetry.lock`, audite leurs paquets de registre, lance `pip-audit` par
  `uvx pip-audit` quand `pip-audit` est absent et `uvx` présent, et rend tout SKIP comme un manque nommé.
- **Verrous** : blocs `[[package]]`, clés `name` et `version` de tête de bloc. Les paquets sont écrits épinglés dans un
  requirements temporaire hors de la cible puis audités avec `--no-deps --disable-pip` (2,5 s mesurées contre 110 s
  pour `pip-audit -r` qui résout dans un environnement isolé). Le projet lui-même (`source` `virtual` ou `editable`)
  n'est pas une dépendance ; un paquet git, chemin, URL ou index privé n'est pas interrogeable et se nomme au manque.
  Deux versions du même nom (marqueurs de résolution) passent en deux lots : `pip-audit` refuse le doublon, mesuré.
- **Manque nommé** : sortie enrichie du champ `manques` (écosystème, manifeste, cause, remède) et, sur un SKIP, du
  champ `motif` (« AUDIT NON JOUÉ, aucune dépendance jugée (ce n'est pas un PASS) — manque : … »). Un délai dépassé se
  dit (« délai de 90 s dépassé ») au lieu de « sortie vide ». Verdicts, codes de sortie et seuils inchangés.
- **Surcharge pour la recette** : `WEBSEC_SCA_PIP_AUDIT` et `WEBSEC_SCA_UVX` désignent la commande à lancer à la place de
  `pip-audit` / `uvx` ; `fixtures/sca/outils/outil-simule.mjs` joue les deux sans réseau ni installation.
- **Où** : `oracles/oracle-sca.mjs` (`VERSION` 0.1.0 → 0.2.0), `oracles/self-test.mjs`, `fixtures/sca/`.
- **Preuve** : `node oracles/self-test.mjs` rejoué sur l'ancien `oracle-sca.mjs` avec les nouveaux cas : 119 PASS,
  16 FAIL (les 16 nouveaux cas, tous en SKIP « aucun manifeste reconnu » ou sans champ `manques`). Avec le nouveau :
  138 PASS, 0 FAIL, 1 SKIP motivé (`pip-audit -r requirements.txt` sur la fixture `pip-vulnerable` dépasse le délai de
  90 s sur ce poste, antérieur à ce changement). 19 contrôles ajoutés, dont 3 avec l'outil réel (`pip-audit`, puis
  `uvx` réel avec `pip-audit` déclaré absent).
- **Limite dite** : un paquet que `pip-audit` saute lui-même (`skip_reason`) compte au total sans être nommé ; la copie
  d'`oracle-sca` de `digit-ai-forge-agents` (`.claude/skills/quality-oracles/scripts/oracle-sca.mjs`) est un autre code
  et n'est pas touchée.

## 2026-11-04 — `scripts/capturer.mjs` : cinq en-têtes de plus et l'URL encodée ne portent plus de jeton dans la capture (TF-2133)

- **Effet** : même classe que TF-2107. Une capture versionnée ne garde plus en clair : les URL de `Content-Location`,
  `Link` (chaque `<URL>` et `anchor="URL"`) et `Refresh` (`délai; url=URL`) ; la valeur entière de `X-Auth-Token` ;
  dans `WWW-Authenticate`, le jeton nu d'un défi (`Negotiate …`), la valeur d'un paramètre de nom de jeton ou de
  défi (`nonce`, `opaque`, `response`…) et l'URL à jeton d'une valeur (`resource_metadata=`). Schémas, `realm`,
  `error`, `scope`, `qop` restent. Une valeur de paramètre qui est elle-même une URL ou une liste de paramètres
  (`redirect_uri=https%3A%2F%2F…%3Fcode%3D…`, jusqu'à 3 niveaux de percent-encoding) est décodée avant d'être jugée,
  caviardée, puis ré-encodée au même niveau ; une valeur sans jeton sort octet pour octet.
- **Limite dite** : un jeton dans un segment de chemin (`/reset/<jeton>`) n'a ni nom ni forme à reconnaître sans
  heuristique d'entropie, qui abîmerait des URL sans jeton ; il n'est pas traité. Les captures déjà écrites ne sont
  pas réécrites.
- **Où** : `scripts/caviarder-jetons.mjs` (`caviarderLien`, `caviarderRefresh`, `caviarderDefi`,
  `caviarderValeurImbriquee`), appelé par `scripts/capturer.mjs` via `caviarderEnTetes` et `caviarderUrl`.
- **oracle-exposition** : aucune règle ni `VERSION` ne change ; la capture caviardée est jugée comme avant (EX-1).
- **Preuve** : `oracles/self-test.mjs` rejoue le vrai `capturer.mjs` contre une origine locale qui répond 302 avec
  chaque porteur en clair. Sens rouge mesuré avant le code : 102 PASS, 16 FAIL (les 7 porteurs, 7 contrôles vert,
  2 bancs de bords) ; après : 118 PASS, 0 FAIL. 19 contrôles ajoutés.

## 2026-11-04 — `scripts/capturer.mjs` : l'URL, Location, Authorization et Cookie ne portent plus de jeton dans la capture (TF-2107)

- **Effet** : même classe que TF-2095. Une capture versionnée ne garde plus en clair : les paramètres de forme
  jeton de l'URL capturée et de l'en-tête `Location` (`token`, `access_token`, `id_token`, `code`, `key`, `apikey`,
  `signature`, `sig`, `session`, `sid`, `jwt`, `secret`, `password`, tout nom qui se termine par `token`, `secret`,
  `key`, `signature`, `password` ou `session`), dans la requête, le fragment et les paramètres de chemin
  (`;jsessionid=`) ; l'identifiant `utilisateur:mot-de-passe@` d'une URL ; la valeur d'`Authorization` et de
  `Proxy-Authorization` (le schéma `Bearer`, `Basic`, `Digest` reste) ; les valeurs d'un en-tête `Cookie`. Les
  paramètres sans jeton (`state`, `lang`, `token_type`, `page`) et tous les autres en-têtes sortent octet pour octet.
- **Où** : `scripts/caviarder-jetons.mjs` (nouveau, réutilise le caviardage de TF-2095), appelé par
  `scripts/capturer.mjs` ; le message d'échec de capture ne recopie plus non plus le jeton de l'URL demandée.
  Les captures déjà écrites ne sont pas réécrites.
- **oracle-exposition** : aucune règle ni `VERSION` ne change, il ne lit de l'URL que le schéma. Vérifié : la
  capture caviardée est jugée comme avant (EX-1) et aucun secret n'entre dans son verdict.
- **Preuve** : `oracles/self-test.mjs` rejoue le vrai `capturer.mjs` contre une origine locale qui répond 302 avec
  chaque porteur en clair. Sens rouge mesuré avant le câblage : 89 PASS, 10 FAIL (les 5 porteurs, 4 contrôles
  vert, le message d'échec) ; après : 99 PASS, 0 FAIL. 16 contrôles ajoutés.

## 2026-11-03 — `referentiels/revue-de-code.md` 1.0.0 (TF-2057, D-162 (a))

- **Nouveau référentiel** : la consigne type d'une revue de code par un seul agent, le plafond de
  300 000 jetons tenu par le pilot en tranches de 2 000 lignes (la suivante part si le cumul relevé
  laisse 130 000 jetons de marge), le format du rapport et ses 4 statuts de constat : lu, relu, rejoué,
  non confirmé. Source : l'étude 20261103k du pilot, option O2, et les 2 revues mesurées de TF-2057.
- **Intégration** : l'étape de mise en production du pilot propose la revue à son entrée
  (`ETAPE-MEP.md` § 1 quater) ; son oracle avertit en TM14 quand le dossier ne dit rien de la revue.
  La forge ne bloque toujours aucune mise en production.
- **Ni oracle, ni skill.** Aucun produit nommé, aucune faille. La recette `oracles/self-test.mjs` ne
  change pas. Prochaine revue le 2026-12-01, avec la mesure des statuts.

## 2026-11-03 — `scripts/capturer.mjs` : la valeur des cookies n'entre plus dans la capture (TF-2095)

- **Effet** : une capture d'origine qui pose un cookie (jeton de session ou de formulaire) ne garde plus
  sa valeur, remplacée par `[caviardé]` ; le nom et tous les attributs (Path, Domain, Expires, Max-Age,
  Secure, HttpOnly, SameSite) restent, donc EX-8, EX-9 et EX-10 jugent la capture comme avant. Une capture
  rangée sous `forge/etapes/websec` et versionnée ne fait plus entrer de jeton réel dans le dépôt.
- **Où** : `scripts/caviarder-cookies.mjs` (nouveau), appelé par `scripts/capturer.mjs` avant l'écriture.
  Les captures déjà écrites ne sont pas réécrites : celles qui portent une valeur restent à caviarder ou à purger.
- **oracle-exposition** : ses constats nomment le cookie et jamais sa valeur ; vérifié sur une capture à
  valeur en clair, la valeur n'est recopiée dans aucun constat. Aucune règle ni `VERSION` ne change.
- **Preuve** : `oracles/self-test.mjs` rejoue le vrai `capturer.mjs` contre une origine locale à 3 cookies
  (sens rouge : 0 valeur survivante dans le fichier, la sortie standard et les messages ; sens vert : noms
  et attributs présents, EX-8 levée sur le seul cookie sans Secure). 8 contrôles ajoutés.

## 2026-11-03 — `asvs-l1.md` 0.2.0, `wstg-cas.md` 0.2.0, `classes-attaque.md` 0.2.0 (TF-2071)

- **`asvs-l1.md`** : 12 exigences L1 de l'ASVS 5.0.0 rejoignent la table, 4 pour chacune des classes
  que les revues de code relèvent le plus : V8 (contrôle d'accès : V8.1.1, V8.2.1, V8.2.2, V8.3.1),
  V5 (fichiers et SSRF par nom de fichier : V5.2.1, V5.2.2, V5.3.1, V5.3.2), V2 (logique métier :
  V2.1.1, V2.2.1, V2.2.2, V2.3.1). Identifiants, niveaux et sens relus au tag `v5.0.0_release`. Une
  note nomme les exigences voisines L2 et L3 non listées (SSRF général V1.3.6, limites et verrous
  métier V2.3.2 à V2.4.1, archives V5.2.3, champ et locataires V8.2.3 et V8.4.1).
- **`wstg-cas.md`** : 11 cas WSTG 4.2 s'ajoutent, de 28 à 39 : ATHZ-01 à ATHZ-04, BUSL-01, -02, -03,
  -06, -08, -09 et INPV-19, chacun rattaché à une exigence L1. BUSL-04, -05 et -07 restent non
  curés, motif dit : leur exigence est L2 ou L3.
- **`classes-attaque.md`** : CA-02, CA-03 et CA-05 se rattachent aux exigences et cas retenus, et
  cessent d'être des classes sans rattachement ; DN-1, MS-2, MS-4 et CA-06 sont mis à jour dans le
  même sens. Daté du 03/11/2026.
- **Ni oracle, ni skill.** La recette `oracles/self-test.mjs` ne lit pas les référentiels et ne
  change pas : 77 PASS, 0 FAIL avant et après.

## 2026-11-02 — `referentiels/classes-attaque.md` 0.1.0 (TF-2057, D-136 (a))

- **Nouveau référentiel** des classes d'attaque qu'une revue de code doit chercher : 9 classes de base
  et 117 classes fines des familles qui touchent un produit web, 36 autres nommées par groupe. Source :
  `cloudflare/security-audit-skill`, licence MIT, commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
  (14/09/2026), avis de droits conservé dans le fichier. Daté du 02/11/2026, prochaine revue le
  2027-02-02.
- **Recoupement** de chaque classe avec `asvs-l1.md` et `wstg-cas.md`, et avec ce que les oracles de la
  forge en lisent. Trois classes de base (contrôle d'accès, fichiers et SSRF, logique métier) n'ont
  aucun rattachement curé ; l'écart est dit dans le fichier, non comblé.
- **Ni oracle, ni skill, ni relecture de produit.** Aucun produit nommé, aucune faille réelle. La
  recette `oracles/self-test.mjs` ne change pas.

## 2026-10-28 — `oracle-exposition-statique` 0.1.0, `oracle-exposition` 0.2.0 (TF-1996, part websec)

- **Nouvel oracle `oracles/oracle-exposition-statique.mjs`** : il juge le fichier `_headers` de
  Cloudflare (Workers static assets ou Pages) avant tout déploiement. Il calcule les en-têtes que
  chaque requête sondée recevrait, puis les juge par les règles EX-1 à EX-11, sans les recopier.
- **Deux règles propres au fichier**, sourcées sur developers.cloudflare.com (lu le 28/10/2026) :
  HD-1 pour la syntaxe, HD-2 pour les limites de 100 règles et de 2 000 caractères par ligne.
- **`oracle-exposition` 0.2.0** : les onze règles passent dans la fonction exportée
  `jugerEnTetes`. Sa sortie ne change pas : 16 sorties comparées avant et après, identiques hors
  du champ `version`.
- **Recette** : 16 contrôles ajoutés (8 fixtures sous `fixtures/exposition-statique/`), dont
  3 équivalences entre une capture et un `_headers` qui pose les mêmes en-têtes. Rouge avant
  l'oracle (61 PASS, 16 FAIL, exit 1), vert après (77 PASS, 0 FAIL, exit 0).

## 2026-10-28 — `oracle-workflows` 0.1.0 (TF-2001)

- **Nouvel oracle `oracles/oracle-workflows.mjs`** : il juge les workflows GitHub Actions d'un dépôt
  sur 5 règles, WF-1 à WF-5 : permissions du `GITHUB_TOKEN`, épinglage par SHA complet,
  `pull_request_target`, injection par contexte non fiable dans `run:`, secret long là où l'OIDC est
  documenté. Chaque constat cite sa page de docs.github.com, lue le 28/10/2026.
- **Lecteur YAML natif**, sans dépendance : il refuse ancres, alias, étiquettes et clés complexes,
  et le fichier est alors dit non jugé. Comparé à PyYAML sur 30 fichiers, 30 lectures identiques.
- **Verrou `actions.lock` pris en compte** (préversion publique de GitHub) : une référence inscrite
  au verrou pour son workflow n'est plus relevée comme non épinglée.
- **Recette** : 19 contrôles ajoutés à `oracles/self-test.mjs` (15 fichiers sous
  `fixtures/workflows/`). Rouge avant l'oracle (42 PASS, 18 FAIL, exit 1), vert après (61 PASS,
  0 FAIL, exit 0). La découverte des oracles en trouve 4 au lieu de 3.
