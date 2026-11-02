---
version: 0.1.0
date: 2026-11-02
challenge_date: 2026-11-02
prochaine_revue: 2027-02-02
sources:
  - "Cloudflare, security-audit-skill — https://github.com/cloudflare/security-audit-skill — commit c1c8a8c1471069fb0e188eeaff69b8e8db6564a8 (2026-09-14, « Clarify guidance and full audit modes ») — licence MIT, Copyright (c) 2025-2026 Cloudflare, Inc. — lu le 2026-11-02 sur un clone fait sans exécution : skills/security-audit/ATTACK-CLASSES.md et ses 10 fichiers compagnons"
  - "referentiels/asvs-l1.md de cette forge (ASVS 5.0.0, CC BY-SA 4.0, challenge_date 2026-08-12) — colonne ASVS"
  - "referentiels/wstg-cas.md de cette forge (WSTG 4.2, CC BY-SA 4.0, challenge_date 2026-08-14) — colonne WSTG"
---

# Référentiel — classes d'attaque qu'une revue de code doit chercher

Ce document dit **quoi chercher** quand un humain ou un agent relit le code d'un produit web : 9
classes de base et 117 classes fines, nommées comme le fait la source, avec ce que chacune cherche en
une ligne française, plus 36 classes hors produit web nommées par groupe. Il ne dit pas **où** : aucun
produit n'y est nommé, aucune faille réelle n'y est consignée. `asvs-l1.md` dit ce qu'on exige, `wstg-cas.md` dit comment on le teste, celui-ci dit ce que
la relecture du code doit viser. Il ne crée ni oracle ni skill.

**Attribution et licence.** Les noms de classes et le découpage viennent du dépôt
`cloudflare/security-audit-skill` (commit ci-dessus), publié sous licence MIT. Les lignes « ce qu'on
cherche » sont des résumés écrits ici, non des copies. L'avis de droits et la permission de la
licence suivent, comme elle l'exige :

```
MIT License

Copyright (c) 2025-2026 Cloudflare, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Les identifiants de `asvs-l1.md` et de `wstg-cas.md` cités en recoupement restent sous leur licence
CC BY-SA 4.0 (OWASP Foundation), citée dans ces 2 fichiers.

**Comment lire les colonnes.**
- **ASVS** et **WSTG** : identifiants **curés** dans les deux référentiels de la forge. Une mention
  « non curé » dit que le chapitre existe mais n'est pas dans `asvs-l1.md` ni `wstg-cas.md` : aucune
  exigence ni aucun cas de la forge ne s'y rattache, et ce n'est pas une absence de risque.
- **Forge** : ce qu'un oracle de la forge lit **aujourd'hui** sur cette classe. « aucune » veut dire
  que seule la relecture humaine ou agentique la couvre. Aucun oracle de la forge ne lit le code
  applicatif d'un produit : `oracle-workflows` lit les fichiers de workflows, `oracle-sca` le
  manifeste de dépendances, `oracle-exposition` une réponse HTTP capturée,
  `oracle-exposition-statique` un fichier `_headers`, `oracle-dast` un rapport de scan.
- Dans les tableaux de la section 2, la colonne « ASVS / WSTG » sépare les deux référentiels par une
  barre oblique.

**Règles de jugement reprises de la source** (`ATTACK-CLASSES.md` et le bloc « Core discipline » de
chaque compagnon, résumés).
- Un drapeau n'est pas un constat. Un en-tête, un attribut de cookie ou une limite de débit manquants
  ne comptent que s'ils laissent passer une requête invalide, un effet entre deux principaux, une
  rétrogradation d'assurance ou la fuite d'un secret.
- Deux statuts seulement : `confirmed`, quand la preuve dans le source est complète et qu'une
  validation locale bornée l'a établie ; `needs_validation`, quand un fait de déploiement (proxy,
  fournisseur d'identité, stockage, configuration servie) manque. Ce statut nomme le fait manquant et
  la vérification sûre qui le lèverait.
- La validation reste à la lecture du source et à des fixtures locales bornées : pas de chaîne de
  charges utiles, pas de test de disponibilité sur un service en ligne, pas d'action en environnement
  partagé. Cette limite rejoint le garde-fou d'`oracle-dast` (autorisation écrite, fail-closed).

## 1. Classes de base — `ATTACK-CLASSES.md`

| ID | Classe (nom de la source) | Ce qu'on cherche | ASVS | WSTG | Forge |
|---|---|---|---|---|---|
| CA-01 | Injection | Le chemin d'une entrée non fiable jusqu'à un puits dangereux (requête, HTML, commande, gabarit, chemin, redirection, désérialisation), y compris l'injection indirecte : donnée stockée sans risque puis relue dans un autre contexte, noms de champs, clés, en-têtes, et systèmes secondaires (journaux, caches, index) | V1.2.1 à V1.2.5, V1.3.1, V1.3.2, V1.5.1 | INPV-01, -02, -05, -07, -11, -12 ; CLNT-01 | aucune ; `oracle-dast` signale en passif un reflet (INPV-01), sans prouver l'exploitation |
| CA-02 | Access control | Qu'un appelant ne puisse rien faire hors de son autorité : bon contrôle, sur la bonne ressource, par le bon mécanisme. Chemin parallèle au même effet avec un contrôle plus faible, champ du corps qui écrase la restriction, route authentifiée mais non autorisée, lot, export ou import sans contrôle par élément | V8 non curé | ATHZ non curé | aucune |
| CA-03 | Resource and file handling | Traversée de chemin (liens symboliques, encodages, octet nul), SSRF (redirections, DNS rebinding, différences d'analyse d'URL), désérialisation, extraction d'archive, fichiers temporaires, courses entre contrôle et usage ; corruption mémoire si le langage l'admet | V5 non curé ; identifiant SSRF non relevé ici | ATHZ (traversée) non curé | aucune |
| CA-04 | Cryptography and secrets | Aléa faible pour un jeton ou une clé, secrets en dur ou dans les journaux, erreurs, URL et réponses client, dérivation de clé, HMAC non vérifié, nonce réutilisé, comparaison à canal temporel, primitive mal employée, repli sans chiffrement quand l'opération échoue | V11 non curé ; V6.4.1, V12.1.1, V12.2.1, V12.2.2, V14.2.1 | CRYP-01, CRYP-03 ; IDNT-02 | HSTS seule, par EX-3 |
| CA-05 | Business logic | Les erreurs de logique que les scanners ne trouvent pas : sauter, reculer ou rejouer une étape, échec partiel sans retour arrière, courses à effet métier (double dépense), valeurs négatives, nulles, débordantes ou mal converties, vérification juste pour une autre règle, confiance implicite dans une donnée stockée, expiration et fuseaux, comportement par défaut quand une configuration manque | V2 non curé | BUSL non curé | aucune |
| CA-06 | Feature abuse and data leakage | Une fonction légitime détournée : export ou sauvegarde qui sort des données au-delà du droit, import ou restauration qui contourne la validation, recherche, filtre ou tri qui révèle l'existence, messages, délais ou codes qui distinguent « absent » de « interdit », brouillon ou aperçu qui fuit (flux, plan de site, cache), URL de rappel que le serveur va chercher | V14.2.1, V14.3.1 ; le reste non curé | SESS-04 ; ERRH et IDNT-04 non curés | aucune |
| CA-07 | Chained vulnerabilities and trust boundaries | Un comportement permis seul devient une faille quand un autre composant suppose une garantie plus forte : échecs en plusieurs étapes, écart de garantie entre deux composants, usage de second ordre, élargissement de portée d'un jeton ou d'une délégation, fenêtres de temps (révocation, cache), restauration qui rejoue un état invalide | transverse, aucun chapitre | transverse | aucune |
| CA-08 | Wildcard | Aucune catégorie imposée : le code le plus étrange, les fonctions inachevées ou expérimentales, l'API appelée comme le frontal ne le ferait jamais, les points d'accès non documentés, le mélange de fonctions non prévues ensemble, l'historique git (correctif annulé, secret retiré mais présent), les actions irréversibles, les hypothèses sur l'environnement, ce que les tests ne couvrent pas | transverse | transverse | aucune |
| CA-09 | Obvious things | Une liste littérale à parcourir en entier : secrets en dur, TODO de sécurité, mode debug activable, comptes de test, routes `/debug`, `/admin`, `/metrics`, fichiers `.env` ou clés suivis, `.gitignore`, dépendances et CVE, `eval` et appels de commande, CORS, attributs de cookies, redirections ouvertes, TLS imposé, erreurs qui rendent trace ou chemin | V1.3.2, V3.3.1, V3.4.1, V3.4.2, V6.3.2, V13.4.1, V15.2.1 | CONF-04, CONF-07, SESS-02, CLNT-04, CLNT-07 | EX-3 (TLS imposé), EX-8 à EX-10 (attributs de cookies), `oracle-sca` (CVE connues) ; le reste aucune |

## 2. Classes fines des familles qui touchent un produit web

Chaque ligne regroupe les classes qu'un compagnon de la source range sous un même titre ; la colonne
« Classes » les nomme toutes, en anglais comme la source.

### 2.1 HTTP, sessions et identité — `WEB-PROTOCOL-AND-AUTH.md` (20 classes)

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| HT-1 | Request framing and desynchronization ; Web cache poisoning through unkeyed input ; Cache deception and private-response caching ; Host and forwarded-header trust ; Response-header injection | Deux composants (proxy, cache, application) lisent différemment la même requête, la même réponse ou la même clé de cache | aucun rattachement curé | aucune |
| HT-2 | Ordinary CSRF ; Session fixation and invalidation ; Cookie scope and transport | Un navigateur envoie ses identifiants à une action d'écriture sans jeton efficace ; un identifiant de session non renouvelé au changement de privilège ou survivant à la déconnexion ; un cookie sensible à portée trop large | V3.3.1, V3.5.1 à V3.5.3 ; V7 non curé / SESS-02, SESS-05 ; SESS-01, -03 non curés | EX-8, EX-9, EX-10 (attributs de cookies) ; CSRF et fixation aucune |
| HT-3 | JWT verification and claim binding ; OAuth/OIDC request and callback binding ; SAML signed-object and assertion binding | La signature est vérifiée, mais le jeton n'est pas lié à son émetteur, son public, son état ou sa durée ; l'élément signé n'est pas celui qu'on utilise comme identité | V9, V10 non curés / aucun cas curé | aucune |
| HT-4 | MFA enrollment and assurance downgrade ; Step-up binding and bypass ; WebAuthn and passkey verification ; Account linking and identity collision ; Password reset and broader recovery | Un second facteur qu'on peut remplacer avec le seul premier, un défi accepté pour la mauvaise session ou la mauvaise action, une récupération de compte qui devient le chemin le plus faible | V6.2.2, V6.2.3, V6.4.1 ; le reste de V6 non curé / ATHN-09 ; ATHN-04, -05, -10 non curés | aucune |
| HT-5 | API-key scope and resource binding ; API-key exposure and unsafe transport ; mTLS peer and application-identity confusion ; Certificate lifecycle fallback | Une clé qui ouvre plus de ressources que son enregistrement, une clé dans un bundle, une URL ou un journal, un certificat expiré qui laisse passer en anonyme | V12.2.1 (transport) ; le reste non curé / CRYP-03 | aucune |

### 2.2 Navigateur — `CLIENT-SIDE.md` (14 classes)

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| NV-1 | DOM-based XSS ; DOM clobbering ; Prototype pollution and gadget chain | Une source que le serveur ne voit pas (fragment d'URL, `window.name`, message) qui atteint un puits qui exécute ; un `id` injecté qui masque une variable ; une clé qui pollue un prototype puis une porte qui l'exploite | V3.2.2, V1.2.1 / CLNT-01 ; CLNT-02, -03 non curés | aucune |
| NV-2 | `postMessage` origin and source trust ; Cross-site WebSocket request use ; Credentialed CORS trust | Un gestionnaire de message sans liste exacte d'origines ; une montée WebSocket qui accepte les cookies d'une origine étrangère ; une origine reflétée avec identifiants | V3.4.2 / CLNT-07 ; messages et WebSocket non curés | aucune |
| NV-3 | Service-worker registration and scope takeover ; Service-worker cache and identity confusion ; Browser-storage disclosure and stale authorization ; Cross-context storage and broadcast confusion | Un worker ou un cache qui sert la réponse d'un autre compte après déconnexion ; un jeton ou une donnée privée lisible par un composant moins fiable | V14.3.1 / ATHN-06 ; stockage navigateur non curé | aucune |
| NV-4 | XS-Leaks and cross-origin state oracles ; Window and opener state disclosure | Une page tierce qui distingue un état protégé par un événement de chargement, un délai ou une taille de réponse | aucun rattachement curé | aucune |
| NV-5 | Clickjacking ; Client-side navigation confusion | Une action d'écriture qu'on peut encadrer dans un cadre étranger ; une destination de navigation pilotée par la source sans contrôle du schéma (`javascript:`, `data:`) | V1.2.2 ; clickjacking hors L1 / CLNT-04, CLNT-09 | EX-5 (clickjacking) ; navigation aucune |

### 2.3 Isolation et cycle de vie des données — `DATA-ISOLATION-AND-LIFECYCLE.md` (15 classes)

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| DN-1 | Missing tenant or owner enforcement ; Composite-key and namespace collision ; Policy and query disagreement ; Blob and signed-reference overreach | Un champ « propriétaire » sur l'enregistrement n'est pas une isolation : chercher la requête, la clé ou la politique qui la fait respecter sur chaque lecture et écriture | V8 non curé / ATHZ non curé | aucune |
| DN-2 | Search, cache, and index ACL drift ; Analytics, logs, traces, and diagnostics as alternate readers ; Enumeration and aggregate oracles | Une copie dérivée (index, cache, journal, statistique) qui survit aux droits de l'original ou qu'un lecteur plus large peut lire | V16 non curé / ERRH non curé | aucune |
| DN-3 | Export and backup scope expansion ; Import and restore authority expansion ; Migration default and ownership confusion ; Backup and replication boundary drift | Un export qui contient plus que le droit du demandeur, une restauration qui contourne les règles de validation, une migration qui laisse des valeurs par défaut sans propriétaire | aucun rattachement curé | aucune |
| DN-4 | Soft-delete and tombstone bypass ; Stale authorization and derived copy use ; Retention and queued-work overrun ; Restore reintroduces invalid state | Une suppression ou une révocation que contourne une recherche, un lien, une tâche en file ou une restauration | aucun rattachement curé | aucune |

### 2.4 Chaîne d'approvisionnement et livraison — `SUPPLY-CHAIN-AND-RELEASE.md` (12 classes)

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| CH-1 | Dependency source and namespace confusion ; Mutable and unbound build inputs ; Generated-source and codegen provenance gaps ; Build-context inclusion | Un résolveur qui prend le mauvais registre, une entrée de build modifiable sans relecture, un secret embarqué dans l'image ou le paquet | V15.1.1, V15.2.1 ; Top 10:2025 A03 | `oracle-sca` (CVE connues seulement, pas la confusion d'espace de noms) ; WF-2 (action non épinglée) |
| CH-2 | Untrusted code in a privileged workflow ; Workflow command and expression confusion ; Cache, artifact, and workspace trust mixing ; Automation identity overreach | Du code de contributeur qui tourne avec des secrets ; un champ contrôlé par l'attaquant substitué dans une commande ; un cache ou un artefact alimenté par un job moins fiable ; un jeton de CI trop large | aucun rattachement curé | `oracle-workflows` : WF-3, WF-4, WF-1 et WF-5 ; le mélange de cache aucune |
| CH-3 | Build-to-promotion substitution ; Release authorization and signing-policy gaps ; Update metadata and rollback confusion ; Plugin and extension trust expansion | Test, signature et publication qui visent un nom modifiable plutôt que la même empreinte ; un programme de mise à jour qui ne lie pas version, produit ou canal | aucun rattachement curé | aucune |

### 2.5 Cloud et déploiement — `CLOUD-AND-DEPLOYMENT.md` (15 classes)

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| CL-1 | Workload identity overreach ; Cross-account or cross-tenant role confusion ; Application authorization delegated to cloud metadata | Une identité de charge qui agit au-delà de son rôle sur une cible choisie par une entrée non fiable | aucun rattachement curé | aucune |
| CL-2 | Unexpected service or management-plane reachability ; Trusted-proxy and mesh identity bypass ; Metadata and internal-service reachability | Une route publique vers un point d'administration, de debug ou de métriques ; une identité transmise par un pair qui n'est pas le proxy attendu | aucun rattachement curé | aucune |
| CL-3 | Host or control-plane capability exposure ; Admission and policy path inconsistency ; Namespace and label trust confusion | Un conteneur qui peut choisir des privilèges d'hôte ; un chemin de déploiement qui échappe à la politique | aucun rattachement curé | aucune |
| CL-4 | Security-control precedence drift ; Secret exposure across workload boundaries ; Credential renewal and outage fallback | La configuration finale de chaque environnement (non le fichier de base) qui désactive authentification, transport ou audit ; un secret lisible par une autre charge | Top 10:2025 A02 | aucune ; HSTS posée au niveau de la zone est déclarée non jugée par `oracle-exposition-statique` |
| CL-5 | Object and signed-URL policy confusion ; Event-source identity confusion ; Edge/runtime boundary mismatch | Une URL signée qui n'est liée ni à l'opération ni à l'expiration ; un événement dont la source n'est pas vérifiée ; un runtime de bord qui n'a pas les mêmes garanties que l'origine | aucun rattachement curé | aucune ; les en-têtes posés par le code d'un Worker sont déclarés non jugés par `oracle-exposition-statique` |

### 2.6 Protocoles, RPC et messages — `PROTOCOLS-RPC-AND-MESSAGING.md` (14 classes)

À lire si le produit expose des webhooks, des files, un RPC ou une API à flux.

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| MS-1 | Message boundary and canonicalization disagreement ; Union, enum, and default confusion ; Envelope and payload identity mismatch | Deux lecteurs d'un même message qui divergent sur sa longueur, ses champs ou son expéditeur | V4 non curé / APIT non curé | aucune |
| MS-2 | Interceptor and method-path inconsistency ; Peer identity to application-principal confusion ; Per-item and streaming authorization gaps ; Callback and reply-correlation confusion | Un contrôle d'accès appliqué aux appels simples mais pas aux flux, ni aux éléments suivants d'un flux | V4, V8 non curés | aucune |
| MS-3 | Topic, routing-key, and subscription scope gaps ; Dead-letter, retry, and diagnostic disclosure ; Untrusted producer treated as control plane | Un abonné qui lit la file d'un autre ; un message qui se déclare événement d'administration | V4 non curé | aucune |
| MS-4 | Duplicate delivery and idempotency gaps ; Out-of-order and stale message acceptance ; Acknowledgment/commit ordering defects ; Partial multi-consumer transitions | Un effet répété par une relivraison, un état ancien qui écrase le récent | V2 non curé / BUSL non curé | aucune |

### 2.7 Ressources et disponibilité — `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` (13 classes)

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| RS-1 | Superlinear parsing, matching, or evaluation ; Decompression and representation amplification ; Database and downstream query amplification | Une petite entrée qui coûte beaucoup : expression régulière, archive, requête sans borne | aucun rattachement curé | aucune |
| RS-2 | Unbounded buffering and cardinality ; File descriptor, handle, and temporary-resource leaks ; Detached work after cancellation | Des corps, sessions ou tâches qui s'accumulent sans limite ni nettoyage à la coupure | aucun rattachement curé | aucune |
| RS-3 | Pre-authentication work imbalance ; Quota-accounting scope and reset gaps ; Worker, pool, and priority starvation | Un travail coûteux avant l'authentification ; un quota compté sur une dimension que l'attaquant choisit | V6.1.1, V6.3.1 / ATHN-03 | aucune |
| RS-4 | Reachable fatal error or deadlock ; Retry storm and fail-open amplification ; Poison-record and head-of-line blocking ; Unsafe recovery and capacity rollback | Une entrée qui arrête un processus partagé ; une reprise qui rejoue la cause de la panne | aucun rattachement curé | aucune |

### 2.8 IA et agents embarqués dans le produit — `AI-AND-LLM.md` (14 classes)

À lire seulement si le produit livré embarque un modèle de langage. L'outillage agentique qui a
construit le produit relève de `digit-ai-forge-agents-security`, pas de cette forge (README, section
« Délimitation »).

| ID | Classes | Ce qu'on cherche | ASVS / WSTG | Forge |
|---|---|---|---|---|
| IA-1 | Indirect injection through retrieved or ingested content ; Cross-session or cross-tenant context bleed ; Persistent memory poisoning ; Prompt role and provenance confusion | Un contenu que l'attaquant peut écrire et qui entre dans le contexte d'un autre utilisateur ; une mémoire ou un cache clés trop larges | aucun rattachement curé | aucune |
| IA-2 | Tool-argument injection into a downstream sink ; Excessive agency and confused-deputy authority ; Action-confirmation and approval binding ; Tool-schema and dispatcher disagreement ; Unbounded delegated action loops | Les arguments produits par le modèle atteignent une requête, une commande ou une URL sans contrôle côté outil ; l'agent agit avec une identité plus large que celle de l'appelant | aucun rattachement curé | aucune |
| IA-3 | Sub-agent and MCP trust inheritance ; MCP server and tool identity confusion ; MCP metadata and schema as policy | Un sous-agent qui hérite de tous les droits de la session ; des descriptions d'outil traitées comme une politique | aucun rattachement curé | aucune |
| IA-4 | Insecure output rendering ; Sensitive context extraction | Une sortie du modèle rendue sans encodage dans un puits qui exécute ; un contexte qui contient un secret qu'une sortie peut dévoiler | V1.2.1, V3.2.2 (puits) | aucune |

## 3. Familles nommées, hors produit web par défaut

La source en traite deux autres. Elles ne s'appliquent pas à un produit web servi par HTTP, et ne sont
pas détaillées ici (loi transverse n° 3 du pilot : l'oubli ne se tait pas). À rouvrir si le produit
livre aussi une application native ou un composant compilé.

| ID | Famille (fichier de la source) | Classes | Groupes nommés |
|---|---|---|---|
| MB | Memory safety, binary, kernel — `MEMORY-SAFETY-AND-BINARY.md` | 20 | bornes et entiers ; durée de vie, types et concurrence ; FFI et ABI ; chargement de binaires et exécution ; noyau et interfaces privilégiées |
| MO | Desktop, mobile, local IPC — `DESKTOP-MOBILE-AND-LOCAL-IPC.md` | 16 | liens profonds et rappels ; webview et pont natif ; IPC local et composants exportés ; assistant privilégié et fichiers locaux ; état applicatif et cycle de vie de l'appareil |

Total : 9 + 117 + 36 = 162 classes nommées par la source au commit cité. Comptage fait le 02/11/2026
par `grep` des lignes en gras seul de chaque fichier compagnon, recoupé à la main sur les groupes.

## 4. Constats du recoupement avec les référentiels de la forge

- **3 classes de base ne sont pas curées.** Contrôle d'accès (CA-02), fichiers et SSRF (CA-03)
  et logique métier (CA-05) n'ont aucune exigence ASVS L1 ni aucun cas WSTG dans la forge : V8, V5,
  V2, ATHZ et BUSL figurent parmi les « restes explicites » d'`asvs-l1.md` et de `wstg-cas.md`. Les
  curer est une décision à part, hors de ce document.
- **Un écart de jugement reste ouvert.** La source classe un attribut de cookie ou un en-tête manquant
  seul en simple durcissement (HT-2, bloc de discipline). `oracle-exposition` leur donne une sévérité :
  EX-8 bloquant, EX-9 et EX-10 majeurs. Les deux restent valables, parce qu'un oracle de configuration
  juge une réponse et qu'une revue de code juge un impact ; un rapport qui mêle les deux doit dire
  lequel a parlé.
- **Aucune classe de ce document n'est lue sur le code d'un produit.** Les lectures outillées portent
  sur des réponses HTTP, des fichiers `_headers`, des manifestes et des workflows : CA-04 (HSTS), CA-09,
  HT-2, NV-5, CH-1 et CH-2, chacune pour une partie de la classe. Tout le reste attend une relecture.

## 5. Limites du document

- **Relecture de produit** : hors de ce document. Aucun produit n'est nommé, et la relecture n'a lieu
  que lorsque le porteur nomme le produit à lire, via le pilot (CLAUDE.md, garde-fous : invocation sur
  mandat humain).
- **Failles** : il n'en consigne aucune, ni charge utile, ni chemin de produit.
- **Oracle et skill** : il n'en crée aucun, aucun contrôle ne le lit et la recette
  `oracles/self-test.mjs` ne le juge pas.
- **Exhaustivité** : la source dit elle-même que sa liste est un point de départ à compléter selon
  l'application.

## 6. Révision

Prochaine revue : **2027-02-02**, ou plus tôt si le dépôt de la source publie un commit après
`c1c8a8c`. Pour réviser : relire la liste des commits du dépôt source, recompter les lignes en gras
seul de chaque fichier compagnon, reporter ici les classes ajoutées, retirées ou renommées, puis
mettre à jour `version`, `challenge_date` et `prochaine_revue`. Les colonnes ASVS, WSTG et Forge se
relisent contre les deux référentiels et la liste d'oracles de la forge à cette date
(`node oracles/decouvrir-oracles.mjs`).
