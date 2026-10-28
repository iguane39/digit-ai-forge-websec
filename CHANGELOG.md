# Journal des modifications — digit-ai-forge-websec

La forge n'a pas de numéro de version propre : ses tags `v0.1.0` à `v1.17.0` sont ceux des runs de
version de l'écosystème, posés par le pilot. Les unités versionnées ici sont les oracles (constante
`VERSION`, champ `version` de leur sortie) et les référentiels (frontmatter `version`). Ce journal
commence le 28/10/2026 ; l'historique antérieur se lit dans `git log`.

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
