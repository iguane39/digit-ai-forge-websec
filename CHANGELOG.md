# Journal des modifications — digit-ai-forge-websec

La forge n'a pas de numéro de version propre : ses tags `v0.1.0` à `v1.17.0` sont ceux des runs de
version de l'écosystème, posés par le pilot. Les unités versionnées ici sont les oracles (constante
`VERSION`, champ `version` de leur sortie) et les référentiels (frontmatter `version`). Ce journal
commence le 28/10/2026 ; l'historique antérieur se lit dans `git log`.

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
