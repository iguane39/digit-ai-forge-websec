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
- **Zéro API tierce payante, zéro dépendance npm propre.** `oracle-sca` délègue à
  l'outillage déjà présent sur le poste (npm, pip-audit) — il ne l'installe jamais et rend
  un **SKIP motivé** (jamais un PASS silencieux) quand cet outillage ou le réseau manque.
- **Dépôt public : zéro donnée réelle.** Fixtures synthétiques uniquement — URLs, cookies et
  dépendances fictives ou à CVE déjà publique.
- **ASVS cité, jamais recopié.** `referentiels/asvs-l1.md` cite des identifiants ASVS 5.0.0
  (CC BY-SA 4.0) et les résume en une ligne française — ne jamais coller le texte intégral
  du standard dans ce dépôt.
- **Avant toute modification d'une règle** : rejouer `node oracles/self-test.mjs` (double
  sens — verte passe, rouge échoue pour la bonne raison). Le volet `oracle-sca` peut
  légitimement rendre des SKIP motivés selon l'outillage du poste — ce n'est pas un échec du
  self-test, mais ce n'est pas non plus une preuve : ne pas la présenter comme telle.
- **v0 : pas de DAST, pas de pentest.** Limites détaillées dans `README.md §Limites`, jamais
  promises au-delà.

## Point d'entrée

```
node oracles/self-test.mjs                         # preuve intégrale
node scripts/capturer.mjs <url> --sortie c.json     # capture réelle
node oracles/oracle-exposition.mjs c.json           # scan de l'exposition HTTP
node oracles/oracle-sca.mjs <dossier-cible>          # scan des dépendances vulnérables
```
