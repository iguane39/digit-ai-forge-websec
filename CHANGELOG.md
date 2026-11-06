# Journal des modifications — digit-ai-forge-websec

La forge n'a pas de numéro de version propre : ses tags `v0.1.0` à `v1.17.0` sont ceux des runs de
version de l'écosystème, posés par le pilot. Les unités versionnées ici sont les oracles (constante
`VERSION`, champ `version` de leur sortie) et les référentiels (frontmatter `version`). Ce journal
commence le 28/10/2026 ; l'historique antérieur se lit dans `git log`.

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
