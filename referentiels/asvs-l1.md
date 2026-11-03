---
version: 0.2.0
challenge_date: 2026-08-12
sources:
  - "OWASP Application Security Verification Standard (ASVS) 5.0.0 — publié mai 2025, licence CC BY-SA 4.0 — https://github.com/OWASP/ASVS/tree/master/5.0"
  - "OWASP Top 10:2025 — nov. 2025 — https://owasp.org/Top10/2025/ — A02:2025 Security Misconfiguration, A03:2025 Software Supply Chain Failures"
  - "Cyber Resilience Act (UE) 2024/2847 — signalement d'incident actif dès le 11/09/2026, conformité produit pleine au 11/12/2027"
---

# Référentiel — contrat de sécurité v0 (sous-ensemble curé, niveau ASVS L1)

**Attribution et licence.** Le contenu de l'OWASP ASVS 5.0.0 est publié sous licence
**CC BY-SA 4.0** par l'OWASP Foundation (https://github.com/OWASP/ASVS). Ce document **cite
des identifiants d'exigences (Vx.x.x) et en résume le sens en une ligne française** — il ne
recopie **pas** le texte intégral du standard. Pour le libellé officiel complet, se référer
au texte source : https://github.com/OWASP/ASVS/tree/master/5.0/en.

**Périmètre de la curation.** Sous-ensemble **niveau 1 (L1)** — le socle applicable à toute
application, avant les renforcements L2 (données sensibles) et L3 (critique). Curation
volontairement centrée sur les chapitres où `digit-ai-forge-websec` apporte une vérification
outillée v0 (V3 Web Frontend Security, V15 Secure Coding and Architecture — dépendances) et
quelques chapitres adjacents à fort enjeu produit web (V1, V6, V12, V13, V14). Depuis la 0.2.0
(03/11/2026, TF-2071), les trois classes que les revues de code relèvent le plus — contrôle d'accès,
fichiers et SSRF, logique métier — sont curées : V2 Validation and Business Logic, V5 File
Handling et V8 Authorization, leurs seules exigences L1. **Restes explicites** (loi transverse
n°3 du pilot — l'oubli ne se tait pas) : V4 API and Web Service, V7 Session Management,
V9 Self-contained Tokens, V10 OAuth and OIDC, V11 Cryptography, V16 Security Logging and
Error Handling, V17 WebRTC — non curés, à élargir sur mandat.

**Numérotation.** Les identifiants sont ceux de l'ASVS **5.0.0** (chapitre 8 = Authorization,
chapitre 14 = Data Protection) ; la 4.0.3 numérote autrement (son V8 est la protection des données).
Les lignes V2, V5 et V8 ci-dessous ont été relues le 03/11/2026 contre les fichiers
`5.0/en/0x11-…`, `0x14-…` et `0x17-…` du dépôt OWASP/ASVS au tag `v5.0.0_release` (commit
`5cf9b03`) : identifiant, niveau et sens. Les autres lignes gardent leur date de relecture
(`challenge_date`).

**Méthode de test associée.** Ce document dit *ce qu'on exige* ; `referentiels/wstg-cas.md`
(WSTG 4.2 curé, 14/08/2026) dit *comment on le teste*, cas par cas, chaque cas rattaché à une
exigence ci-dessous.

**Colonne « Vérification »** : `oracle-exposition` | `oracle-sca` | `revue humaine` — jamais
inventée, chaque valeur correspond à un contrôle réellement exécutable aujourd'hui ou à un
constat honnête d'absence d'automatisation.

## V1 — Encoding and Sanitization (prévention des injections)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V1.2.1 | Encodage de sortie contextualisé (HTML/attribut/CSS/en-tête) pour ne pas altérer la structure du document | revue humaine | manuel |
| V1.2.2 | Encodage contextualisé des URLs construites dynamiquement ; protocoles dangereux (`javascript:`, `data:`) interdits | revue humaine | manuel |
| V1.2.3 | Échappement des contenus JS/JSON construits dynamiquement (anti-injection JS/JSON) | revue humaine | manuel |
| V1.2.4 | Requêtes paramétrées / ORM obligatoires contre l'injection SQL/NoSQL/HQL/Cypher | revue humaine | manuel |
| V1.2.5 | Appels système protégés contre l'injection de commandes OS | revue humaine | manuel |
| V1.3.1 | Tout HTML non fiable (éditeur WYSIWYG) assaini par une bibliothèque de sanitization reconnue | revue humaine | manuel |
| V1.3.2 | `eval()` et exécution de code dynamique évités ; entrée assainie si inévitable | revue humaine | manuel |
| V1.5.1 | Parseurs XML configurés en restrictif, entités externes désactivées (anti-XXE) | revue humaine | manuel |

## V2 — Validation and Business Logic (logique métier, intégrité des données)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V2.1.1 | Les règles de validation des entrées (formats courants ou format interne) sont documentées | revue humaine | manuel |
| V2.2.1 | Toute entrée qui pèse sur une décision métier ou de sécurité est validée contre une liste de valeurs, de motifs et de bornes admis (en L1, ces entrées-là suffisent) | revue humaine | manuel |
| V2.2.2 | La validation est imposée sur une couche serveur de confiance ; celle du client sert l'usage, jamais de contrôle de sécurité | revue humaine | manuel |
| V2.3.1 | Un flux métier d'un même utilisateur n'avance que dans l'ordre prévu des étapes, sans en sauter aucune | revue humaine | manuel |

## V3 — Web Frontend Security (en-têtes, cookies, CSRF)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V3.2.1 | Le contenu n'est pas interprété hors de son contexte prévu (API/fichier uploadé servi sans exécution) | revue humaine | manuel |
| V3.2.2 | Contenu texte affiché via des fonctions de rendu sûres (`textContent`), jamais injecté comme HTML | revue humaine | manuel |
| **V3.3.1** | Cookies posés avec l'attribut **Secure** (et préfixe `__Host-`/`__Secure-`) | **oracle-exposition (EX-8)** | **outillé** |
| **V3.4.1** | En-tête **Strict-Transport-Security** présent, durée ≥ 1 an, sur toute réponse HTTPS | **oracle-exposition (EX-3)** | **outillé** |
| V3.4.2 | `Access-Control-Allow-Origin` figé ou validé contre une liste blanche, jamais un joker exposant des données sensibles | revue humaine | manuel |
| V3.5.1 | Requêtes cross-origin vers des fonctions sensibles validées (jeton anti-CSRF ou en-tête non-CORS-safelisted) | revue humaine | manuel |
| V3.5.2 | Si la protection repose sur le préflight CORS, aucun appel sensible n'est possible sans le déclencher | revue humaine | manuel |
| V3.5.3 | Fonctions sensibles appelées par des méthodes HTTP non « sûres » (POST/PUT/PATCH/DELETE, pas GET/HEAD) | revue humaine | manuel |

> Note de cohérence : `oracle-exposition` vérifie **9 règles supplémentaires** (CSP, anti-
> clickjacking, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, attributs
> `HttpOnly`/`SameSite` des cookies, fuite de version serveur) qui correspondent à des
> exigences ASVS classées **L2/L3** (V3.4.3, V3.4.4, V3.4.5, V3.4.6, V3.3.2, V3.3.4, V13.4.6) —
> hors du sous-ensemble **L1** curé ici, mais délibérément vérifiées dès la v0 car peu
> coûteuses à outiller et à fort effet. Elles ne sont donc **pas** listées comme L1 dans ce
> tableau pour ne pas fausser la lecture du niveau réellement tenu.

## V5 — File Handling (téléversement, chemins de fichier, SSRF par nom de fichier)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V5.2.1 | Seuls des fichiers d'une taille que l'application sait traiter sans perte de performance ni déni de service sont acceptés | revue humaine | manuel |
| V5.2.2 | Extension conforme à celles attendues et contenu conforme au type annoncé (octets magiques, réécriture d'image), y compris dans une archive ; en L1, les fichiers qui pèsent sur une décision suffisent | revue humaine | manuel |
| V5.3.1 | Un fichier téléversé ou produit depuis une entrée non fiable, rangé dans un dossier public, n'est jamais exécuté comme code serveur quand on l'appelle en HTTP | revue humaine | manuel |
| V5.3.2 | Les chemins de fichier se bâtissent sur des données internes ou de confiance, non sur les noms soumis ; sinon validation et assainissement stricts (traversée de chemin, inclusion locale ou distante, SSRF) | revue humaine | manuel |

## V6 — Authentication (sous-ensemble mots de passe)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V6.1.1 | Anti-brute-force / anti-credential-stuffing documentés (rate limiting, anti-automatisation) | revue humaine | manuel |
| V6.2.1 | Mot de passe utilisateur ≥ 8 caractères (15 recommandé) | revue humaine | manuel |
| V6.2.2 | L'utilisateur peut changer son mot de passe | revue humaine | manuel |
| V6.2.3 | Le changement de mot de passe exige l'ancien ET le nouveau | revue humaine | manuel |
| V6.2.4 | Mot de passe soumis vérifié contre au moins les 3000 mots de passe les plus fréquents | revue humaine | manuel |
| V6.2.5 | Aucune règle de composition imposée (pas de minimum majuscules/chiffres/symboles) | revue humaine | manuel |
| V6.2.6 | Champ mot de passe masqué (`type=password`), affichage temporaire toléré | revue humaine | manuel |
| V6.2.7 | Collage et gestionnaires de mots de passe autorisés | revue humaine | manuel |
| V6.2.8 | Mot de passe vérifié tel que reçu, sans troncature ni changement de casse | revue humaine | manuel |
| V6.3.1 | Contrôles anti credential-stuffing/brute-force appliqués conformément à la documentation | revue humaine | manuel |
| V6.3.2 | Comptes par défaut (`root`/`admin`/`sa`) absents ou désactivés | revue humaine | manuel |
| V6.4.1 | Mots de passe/codes d'activation générés par le système : aléatoires, expirants, jamais définitifs | revue humaine | manuel |
| V6.4.2 | Indices de mot de passe et questions secrètes absents | revue humaine | manuel |

## V8 — Authorization (contrôle d'accès)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V8.1.1 | La documentation d'autorisation fixe les règles d'accès par fonction et par donnée, selon les permissions du consommateur et les attributs de la ressource | revue humaine | manuel |
| V8.2.1 | L'accès à une fonction est réservé aux consommateurs qui en ont la permission explicite | revue humaine | manuel |
| V8.2.2 | L'accès à une donnée est réservé aux consommateurs autorisés sur cet objet précis (parade à l'IDOR et au BOLA, accès non autorisé à un objet par sa référence) | revue humaine | manuel |
| V8.3.1 | Les règles d'autorisation s'appliquent dans une couche serveur de confiance, sans s'appuyer sur un contrôle qu'un consommateur non fiable peut manipuler, tel le JavaScript client | revue humaine | manuel |

> Note de cohérence (0.2.0) : les exigences voisines classées **L2/L3** dans V1, V2, V5 et V8 ne
> sont pas listées dans les tableaux ci-dessus, pour ne pas fausser la lecture du niveau L1 tenu,
> mais elles restent exigibles aux niveaux supérieurs. Pour les trois classes de la 0.2.0 : SSRF
> par validation de protocole, de domaine, de chemin et de port (V1.3.6, L2) ; limites métier,
> transactions, verrous et anti-automatisation (V2.3.2, V2.3.3, V2.3.4, V2.4.1, L2) ; archives
> et téléchargement de fichiers (V5.2.3, V5.4.1, V5.4.2, V5.4.3, L2 ; V5.3.3, L3) ; accès au
> champ d'un objet et isolation entre locataires (V8.2.3, V8.4.1, L2). Niveaux relus au tag
> `v5.0.0_release` le 03/11/2026.

## V12 — Secure Communication (TLS)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V12.1.1 | Seules les versions récentes de TLS activées (1.2/1.3), la plus récente préférée | revue humaine | manuel |
| V12.2.1 | TLS utilisé pour toute connectivité externe, aucun repli en clair | oracle-exposition (partiel — juge l'URL/HSTS observés, pas la négociation TLS elle-même) | outillé (partiel) |
| V12.2.2 | Certificats TLS externes émis par une autorité publiquement reconnue | revue humaine | manuel |

## V13 — Configuration (fuite d'information)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V13.4.1 | Dossiers de contrôle de version (`.git`, `.svn`) non exposés ni accessibles | revue humaine (candidat `capturer.mjs` v1 — sonde de chemins connus) | manuel |

## V14 — Data Protection

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V14.2.1 | Donnée sensible jamais transmise via l'URL ou la query string | revue humaine | manuel |
| V14.3.1 | Données authentifiées effacées du stockage client à la fin de session | revue humaine | manuel |

## V15 — Secure Coding and Architecture (dépendances)

| ID ASVS | Résumé (une ligne) | Vérification | Statut |
|---|---|---|---|
| V15.1.1 | Délais de remédiation documentés pour les composants tiers vulnérables | revue humaine (politique — fixe les seuils consommés par `oracle-sca --seuils`) | manuel |
| **V15.2.1** | Aucun composant en production ne dépasse les délais de remédiation documentés (pas de vulnérabilité connue non traitée) | **oracle-sca (SCA-NPM, SCA-PIP)** | **outillé** |

## Mapping OWASP Top 10:2025 (contexte, pas une source ASVS)

| Catégorie Top 10:2025 | Couverture par cette forge |
|---|---|
| **A02:2025 — Security Misconfiguration** | `oracle-exposition` (en-têtes de sécurité HTTP, cookies) |
| **A03:2025 — Software Supply Chain Failures** | `oracle-sca` (dépendances vulnérables via l'outillage du poste) |

Les huit autres catégories 2025 (contrôle d'accès, injection, cryptographie, conception,
authentification, intégrité logicielle/data, journalisation, gestion des erreurs) ne sont
**pas** couvertes par un oracle de cette forge en v0 — cf. tableaux V1/V2/V5/V6/V8 ci-dessus, marqués
« revue humaine ».

## Ce que ce contrat n'est pas

- **Pas une certification ASVS.** Une conformité aux lignes « outillé » de ce document ne
  vaut ni audit ASVS complet, ni certification — c'est un contrat de sécurité **v0**, sous-
  ensemble curé et partiellement automatisé.
- **Pas un DAST.** Aucune de ces règles n'exploite activement l'application (fuzzing,
  injection réelle). Depuis le 14/08/2026, `oracles/oracle-dast.mjs` enveloppe OWASP ZAP sous
  garde-fou d'autorisation écrite, mais son exécution réelle n'est pas prouvée faute de ZAP
  sur le poste (dette D-W1 requalifiée, cf. `README.md §Limites`). La **méthode** de test
  correspondante est curée dans `referentiels/wstg-cas.md`.
- **Pas un audit de code.** Les exigences V1/V2/V5/V6/V8 marquées « revue humaine » nécessitent une
  lecture de code ou un test manuel — cet oracle ne les exécute pas.
