# digit-ai-forge-websec

Forge de **sécurité du produit web livré** — juge le produit, pas l'outillage agentique qui
l'a construit (`digit-ai-forge-agents-security`, délimitation croisée dans les deux README).
Détail complet : `README.md`. Mandat d'origine : TF-0123
(`digit-ai-forge-pilot/todo/TODO.jsonl`).

## Garde-fous

- **Invocation sur mandat humain uniquement**, via le pilot. Jamais d'audit spontané d'un
  dépôt ou d'une URL tiers depuis cette forge.
- **Outille, ne décide jamais.** Un verdict `FAIL` est un constat localisé, jamais un
  blocage ou une correction automatique.
- **Zéro API tierce payante, zéro dépendance npm propre.** `oracle-sca` et `oracle-dast`
  délèguent à l'outillage déjà présent sur le poste (npm, pip-audit, OWASP ZAP) — ils ne
  l'installent jamais et rendent un **SKIP motivé** (jamais un PASS silencieux) quand cet
  outillage ou le réseau manque.
- **Aucun scan dynamique sans autorisation écrite.** `oracle-dast` est fail-closed : cible
  nommée dans un fichier d'autorisation daté, en cours de validité, instance dédiée par
  défaut, mode actif déclaré — sinon `FAIL` (exit 1) et rien n'est émis. Ce garde-fou
  dual-use ne se désactive pas, et le self-test ne lance jamais de scan réel.
- **Dépôt public : zéro donnée réelle.** Fixtures synthétiques uniquement — URLs, cookies et
  dépendances fictives ou à CVE déjà publique.
- **Référentiel cité, jamais recopié.** `referentiels/asvs-l1.md` (ASVS 5.0.0) et
  `referentiels/wstg-cas.md` (WSTG 4.2) citent des identifiants sous CC BY-SA 4.0 et les
  résument en une ligne française — ne jamais coller le texte intégral d'un standard dans ce
  dépôt. Tout cas WSTG curé est rattaché à une exigence d'`asvs-l1.md` ; sans rattachement,
  il n'entre pas.
- **Avant toute modification d'une règle** : rejouer `node oracles/self-test.mjs` (double
  sens — verte passe, rouge échoue pour la bonne raison). Le volet `oracle-sca` peut
  légitimement rendre des SKIP motivés selon l'outillage du poste — ce n'est pas un échec du
  self-test, mais ce n'est pas non plus une preuve : ne pas la présenter comme telle.
- **v0 : pas de pentest ; DAST outillé mais non prouvé en exécution.** `oracle-dast` enveloppe
  ZAP (garde-fou et lecture de rapport prouvés), mais ZAP n'est installé sur aucun poste : la
  branche d'exécution réelle reste à prouver — dette D-W1 requalifiée, pas close. Limites
  détaillées dans `README.md §Limites`, jamais promises au-delà.

## Point d'entrée

```
node oracles/self-test.mjs                         # preuve intégrale
node scripts/capturer.mjs <url> --sortie c.json     # capture réelle
node oracles/oracle-exposition.mjs c.json           # scan de l'exposition HTTP
node oracles/oracle-sca.mjs <dossier-cible>          # scan des dépendances vulnérables
node oracles/oracle-dast.mjs --cible <url> --autorisation <f.json>   # DAST, sur périmètre autorisé
```
