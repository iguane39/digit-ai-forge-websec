---
version: 0.1.0
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
quelques chapitres adjacents à fort enjeu produit web (V1, V6, V12, V13, V14). **Restes
explicites** (loi transverse n°3 du pilot — l'oubli ne se tait pas) : V2 Validation and
Business Logic, V4 API and Web Service, V5 File Handling, V7 Session Management,
V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC, V11 Cryptography,
V16 Security Logging and Error Handling, V17 WebRTC — non curés en v0, à élargir sur mandat.

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
**pas** couvertes par un oracle de cette forge en v0 — cf. tableaux V1/V6 ci-dessus, marqués
« revue humaine ».

## Ce que ce contrat n'est pas

- **Pas une certification ASVS.** Une conformité aux lignes « outillé » de ce document ne
  vaut ni audit ASVS complet, ni certification — c'est un contrat de sécurité **v0**, sous-
  ensemble curé et partiellement automatisé.
- **Pas un DAST.** Aucune de ces règles n'exploite activement l'application (fuzzing,
  injection réelle) — ZAP est consigné en v1 (cf. `README.md §Limites`).
- **Pas un audit de code.** Les exigences V1/V6 marquées « revue humaine » nécessitent une
  lecture de code ou un test manuel — cet oracle ne les exécute pas.
