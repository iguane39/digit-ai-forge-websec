---
version: 0.1.0
challenge_date: 2026-08-14
sources:
  - "OWASP Web Security Testing Guide (WSTG) 4.2 — publié 2020-12, stable au 2026-08-14 (v5.0 non publiée à cette date), licence CC BY-SA 4.0 — https://github.com/OWASP/wstg"
  - "Sommaire des cas WSTG 4.2 (chapitres 4.1 à 4.12) — https://owasp.org/www-project-web-security-testing-guide/v42/"
  - "OWASP Application Security Verification Standard (ASVS) 5.0.0 — mai 2025, CC BY-SA 4.0 — colonne de rattachement de ce document, via referentiels/asvs-l1.md"
---

# Référentiel — cas de test WSTG curés (méthode de test, sous-ensemble)

**Attribution et licence.** L'OWASP Web Security Testing Guide est publié sous licence
**CC BY-SA 4.0** par l'OWASP Foundation (https://github.com/OWASP/wstg). Ce document **cite
des identifiants de cas (WSTG-XXXX-nn) et en reformule l'intention en une ligne française
écrite ici** — il ne recopie **pas** le texte des fiches sources. Pour le mode opératoire
officiel complet (outils, charges utiles, remédiations), se référer au texte source :
https://owasp.org/www-project-web-security-testing-guide/v42/.

**Version retenue.** WSTG **4.2**, publiée en décembre 2020 et toujours la dernière version
stable au 14/08/2026 (la v5.0 est en chantier sur la branche `master`, non publiée). Les
identifiants ci-dessous sont ceux de la 4.2 ; la branche `master` en a ajouté depuis
(ex. mass assignment côté INPV, path confusion côté CONF) — ils ne sont **pas** cités ici.
`challenge_date: 2026-08-14` — re-challenger la fraîcheur (publication d'une v5.0) avant tout
usage éloigné de cette date.

**Règle de curation** (ce qui explique ce qui est là et ce qui n'y est pas) : un cas WSTG
n'est curé que s'il **vérifie une exigence présente dans `referentiels/asvs-l1.md`**. Le
document ASVS reste la source des exigences (ce qu'on doit tenir) ; celui-ci n'apporte que la
**méthode de test** (comment on constate qu'on le tient). Trois cas font exception et sont
marqués comme tels : ils vérifient des règles déjà **outillées** par `oracle-exposition`
(CSP, anti-clickjacking, fuite de version) dont les exigences ASVS correspondantes sont
classées **L2/L3** — hors table L1, mais nommées dans la « note de cohérence » d'`asvs-l1.md`.

**28 cas curés** sur les 12 chapitres de la WSTG 4.2 : 25 rattachés à une exigence L1 nommée,
3 rattachés hors L1 (règles outillées). Chapitres et cas non curés : listés nommément
en fin de document (loi transverse n°3 du pilot — l'oubli ne se tait pas).

**Colonne « Outillage »** : `oracle-exposition` | `oracle-sca` | `oracle-dast` | `manuel` —
jamais inventée. `oracle-dast` signale les cas qu'une passe **passive** ZAP peut lever ; le
verdict reste soumis au garde-fou d'autorisation de cet oracle, et une absence d'alerte n'y
vaut jamais preuve d'absence de défaut.

## 4.2 — Configuration and Deployment Management (WSTG-CONF)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-CONF-04 | Des fichiers de sauvegarde, sources ou dossiers de gestion de version traînent-ils sous la racine servie ? | Demander les chemins connus (`/.git/HEAD`, `/.svn/entries`, `*.bak`, `*.old`, `*.zip`) et vérifier que la réponse n'est pas un contenu servi | V13.4.1 | manuel (sonde de chemins) |
| WSTG-CONF-06 | Le serveur accepte-t-il des méthodes HTTP au-delà de celles dont l'application a besoin ? | Envoyer `OPTIONS`, puis `PUT`/`DELETE`/`TRACE` sur une route sensible et lire le code de retour effectif, pas seulement l'en-tête `Allow` | V3.5.3 | manuel |
| WSTG-CONF-07 | Le service impose-t-il HTTPS par un en-tête HSTS de durée suffisante ? | Capturer une réponse HTTPS et lire `Strict-Transport-Security` (présence, `max-age` ≥ 1 an) | **V3.4.1** | **oracle-exposition (EX-3)** |
| WSTG-CONF-12 | Une politique de sécurité de contenu est-elle posée, et est-elle autre chose qu'un joker ? | Lire `Content-Security-Policy` sur la réponse et vérifier qu'aucune directive de script n'est ouverte à `*` | hors L1 — cf. note de cohérence d'`asvs-l1.md` (L2/L3) | **oracle-exposition (EX-1, EX-2)** |

## 4.1 — Information Gathering (WSTG-INFO)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-INFO-02 | Le serveur annonce-t-il son produit et sa version dans ses réponses ? | Capturer une réponse et lire `Server` / `X-Powered-By` : toute version précise est une aide gratuite à l'attaquant | hors L1 — cf. note de cohérence d'`asvs-l1.md` (V13.4.6, L2/L3) | **oracle-exposition (EX-11)** |

## 4.3 — Identity Management (WSTG-IDNT)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-IDNT-02 | L'inscription délivre-t-elle un secret d'activation aléatoire, à durée de vie bornée, plutôt qu'un mot de passe définitif ? | Créer deux comptes de test et comparer les codes délivrés (prédictibilité, réutilisation, absence d'expiration) | V6.4.1 | manuel |

## 4.4 — Authentication (WSTG-ATHN)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-ATHN-01 | Les identifiants circulent-ils uniquement sur un canal chiffré, formulaire compris ? | Vérifier que la page de connexion et l'action POST sont en HTTPS, et qu'aucun repli HTTP n'accepte les mêmes identifiants | V12.2.1 | oracle-exposition (partiel — juge l'URL et HSTS, pas la négociation TLS) |
| WSTG-ATHN-02 | Des comptes livrés par défaut restent-ils actifs ? | Tenter les couples par défaut connus du socle technique déployé (`admin`, `root`, `sa`) sur l'instance de recette autorisée | V6.3.2 | manuel |
| WSTG-ATHN-03 | Un verrouillage ou une temporisation freinent-ils l'essai en masse d'identifiants ? | Enchaîner N tentatives échouées sur un compte de test et mesurer à partir de quel rang la réponse change (délai, blocage, défi) | V6.1.1, V6.3.1 | manuel |
| WSTG-ATHN-06 | Une page authentifiée reste-t-elle lisible dans le cache du navigateur après déconnexion ? | Se connecter, se déconnecter, puis revenir en arrière et rejouer la page depuis le cache local | V14.3.1 | manuel |
| WSTG-ATHN-07 | La politique de mot de passe accepte-t-elle un secret long sans imposer de composition arbitraire, et refuse-t-elle les plus courants ? | Soumettre à l'inscription un mot de passe de 7 caractères, un de 64, un à symboles, puis un mot de passe notoirement fréquent | V6.2.1, V6.2.4, V6.2.5 | manuel |
| WSTG-ATHN-08 | Le compte repose-t-il sur des questions secrètes ou des indices devinables ? | Parcourir les parcours d'inscription et de récupération et relever toute question secrète ou tout indice proposé | V6.4.2 | manuel |
| WSTG-ATHN-09 | Le changement de mot de passe exige-t-il l'ancien, et la réinitialisation délivre-t-elle un jeton à usage unique et expirant ? | Changer le mot de passe sans fournir l'ancien ; rejouer deux fois un lien de réinitialisation et le rejouer après expiration annoncée | V6.2.2, V6.2.3 | manuel |

## 4.6 — Session Management (WSTG-SESS)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-SESS-02 | Les cookies de session portent-ils les attributs qui les protègent ? | Lire les en-têtes `Set-Cookie` : `Secure`, `HttpOnly`, `SameSite`, préfixe `__Host-`/`__Secure-` | **V3.3.1** | **oracle-exposition (EX-8 ; EX-9/EX-10 hors L1)** |
| WSTG-SESS-04 | Un identifiant de session ou une donnée sensible transite-t-il par l'URL ? | Parcourir l'application en relevant les query strings, puis vérifier les journaux d'accès et l'en-tête `Referer` sortant | V14.2.1 | manuel |
| WSTG-SESS-05 | Une action sensible peut-elle être déclenchée depuis un autre site sans jeton ni contrôle d'origine ? | Rejouer une requête d'état depuis une page tierce, jeton anti-CSRF retiré puis remplacé par une valeur d'une autre session | V3.5.1, V3.5.2 | manuel |

## 4.7 — Input Validation (WSTG-INPV)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-INPV-01 | Un paramètre renvoyé dans la page permet-il d'y injecter du script (XSS réfléchi) ? | Injecter un marqueur inoffensif dans chaque paramètre reflété et observer s'il ressort encodé ou interprété comme balise | V1.2.1 | oracle-dast (passif : reflet signalé, exploitation non prouvée) |
| WSTG-INPV-02 | Un contenu enregistré ressort-il exécutable pour les autres utilisateurs (XSS stocké) ? | Déposer un marqueur inoffensif via chaque champ persisté, puis le relire depuis un autre compte et une autre vue | V1.3.1 | manuel |
| WSTG-INPV-05 | Une entrée atteint-elle la base sans requête paramétrée (injection SQL) ? | Perturber la syntaxe d'un paramètre (quote, opérateur booléen, retard temporel) et observer erreur, différence de réponse ou de latence | V1.2.4 | manuel |
| WSTG-INPV-07 | Le parseur XML accepte-t-il des entités externes ou une structure altérée ? | Soumettre un document déclarant une entité externe locale et observer si le contenu est résolu ou l'erreur détaillée | V1.5.1 | manuel |
| WSTG-INPV-11 | Une entrée finit-elle évaluée comme du code applicatif (`eval`, désérialisation, template) ? | Injecter une expression neutre mais calculable dans les paramètres suspects et vérifier si le résultat calculé ressort | V1.3.2 | manuel |
| WSTG-INPV-12 | Une entrée atteint-elle un appel système (injection de commande) ? | Ajouter un séparateur de commande suivi d'une commande inoffensive et observer la sortie ou le délai induit | V1.2.5 | manuel |

## 4.11 — Client-side (WSTG-CLNT)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-CLNT-01 | Le code client écrit-il une donnée contrôlée par l'URL dans le DOM sans passer par une fonction sûre (XSS DOM) ? | Suivre les puits (`innerHTML`, `document.write`, `eval`) depuis les sources (`location`, `postMessage`) dans le JS servi | V3.2.2 | manuel |
| WSTG-CLNT-04 | Une redirection est-elle pilotée par un paramètre sans liste blanche de destinations ? | Remplacer la destination par une origine externe puis par un protocole dangereux (`javascript:`, `data:`) et voir si elle est suivie | V1.2.2 | manuel |
| WSTG-CLNT-07 | La politique CORS renvoie-t-elle une origine reflétée ou un joker sur des données authentifiées ? | Rejouer une requête avec une `Origin` arbitraire et lire `Access-Control-Allow-Origin` / `-Credentials` de la réponse | V3.4.2 | manuel |
| WSTG-CLNT-09 | La page peut-elle être encadrée par un site tiers (clickjacking) ? | Charger l'URL dans une iframe d'origine différente et vérifier `X-Frame-Options` / `frame-ancestors` | hors L1 — cf. note de cohérence d'`asvs-l1.md` (L2/L3) | **oracle-exposition (EX-5)** |

## 4.9 — Cryptography (WSTG-CRYP)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-CRYP-01 | Le service accepte-t-il encore des versions ou des suites TLS dépassées, ou un certificat non reconnu ? | Négocier explicitement chaque version de protocole et lire la chaîne du certificat présentée | V12.1.1, V12.2.2 | manuel (hors périmètre d'`oracle-exposition`, cf. `README.md §Limites`) |
| WSTG-CRYP-03 | Une donnée sensible circule-t-elle en clair sur un canal non chiffré ? | Recenser les appels sortants du produit (API, redirections, ressources) et relever ceux servis en `http://` | V12.2.1 | oracle-exposition (partiel — juge l'URL capturée) |

## Chapitres et cas NON curés

**Quatre chapitres entiers sont hors de ce référentiel**, parce que le chapitre ASVS qu'ils
vérifieraient n'est lui-même pas curé dans `referentiels/asvs-l1.md` — les curer ici
produirait des cas de test rattachés à rien :

| Chapitre WSTG non curé | Ce qu'il teste | Motif |
|---|---|---|
| **WSTG-ATHZ** — Authorization Testing | traversée de répertoire, contournement d'autorisation, élévation de privilège, IDOR | ASVS V8 (Authorization) non curé en L1 dans `asvs-l1.md` |
| **WSTG-BUSL** — Business Logic Testing | validation métier, forge de requêtes, contrôles d'intégrité, contournement de workflow, upload de fichiers | ASVS V2 (Validation and Business Logic) non curé |
| **WSTG-ERRH** — Error Handling | messages d'erreur trop bavards, traces de pile | ASVS V16 (Security Logging and Error Handling) non curé |
| **WSTG-APIT** — API Testing | test GraphQL (seul cas de la 4.2) | ASVS V4 (API and Web Service) non curé |

**Cas non curés dans les chapitres partiellement couverts** (nommés, pas seulement comptés) :

| Chapitre | Cas 4.2 laissés de côté |
|---|---|
| WSTG-INFO | INFO-01, INFO-03, INFO-04, INFO-05, INFO-06, INFO-07, INFO-08, INFO-09, INFO-10 |
| WSTG-CONF | CONF-01, CONF-02, CONF-03, CONF-05, CONF-08, CONF-09, CONF-10, CONF-11 |
| WSTG-IDNT | IDNT-01, IDNT-03, IDNT-04, IDNT-05 |
| WSTG-ATHN | ATHN-04, ATHN-05, ATHN-10 |
| WSTG-SESS | SESS-01, SESS-03, SESS-06, SESS-07, SESS-08, SESS-09 |
| WSTG-INPV | INPV-03, INPV-04, INPV-06, INPV-08, INPV-09, INPV-10, INPV-13, INPV-14, INPV-15, INPV-16, INPV-17, INPV-18, INPV-19 |
| WSTG-CLNT | CLNT-02, CLNT-03, CLNT-05, CLNT-06, CLNT-08, CLNT-10, CLNT-11, CLNT-12, CLNT-13 |
| WSTG-CRYP | CRYP-02, CRYP-04 |

**Exigences L1 d'`asvs-l1.md` sans cas WSTG curé ici** : V1.2.3 (échappement JS/JSON),
V3.2.1 (contenu non interprété hors contexte), V6.2.6/V6.2.7/V6.2.8 (masquage, collage,
absence de troncature du mot de passe), V15.1.1 et V15.2.1 (dépendances — vérifiées par
`oracle-sca`, hors méthode WSTG). Elles restent exigibles ; simplement, aucune méthode de
test WSTG n'est proposée pour elles en v0.

L'énumération ci-dessus est arrêtée au **sommaire WSTG 4.2 au 14/08/2026**. Avant tout usage,
recouper au sommaire du dépôt source : une v5.0 publiée renumérote et ajoute des cas.

## Limites — ce que ce référentiel n'est pas

- **Ni certification, ni pentest.** Dérouler ces 28 cas ne vaut ni certification OWASP, ni
  test d'intrusion : un pentest est conduit par un humain qui enchaîne les faiblesses,
  improvise hors scénario et juge l'exploitabilité réelle. Ce document ne fait que fixer une
  méthode reproductible sur un sous-ensemble.
- **Une méthode, pas un outil.** 20 des 28 cas sont marqués `manuel` et 3 autres ne sont
  outillés que partiellement : ils décrivent le geste à faire, personne ne les exécute
  automatiquement. Un cas coché sans geste exécuté n'est pas un cas tenu — seuls 5 cas
  (CONF-07, CONF-12, INFO-02, SESS-02, CLNT-09) sont rendus par un oracle exécuté.
- **Couverture partielle assumée.** 4 chapitres entiers, plus les 54 cas nommés des chapitres
  partiellement couverts, sont hors périmètre (listés ci-dessus) : l'absence de constat sur
  ces cas n'est pas un constat d'absence de défaut.
- **Tout cas actif est soumis au garde-fou dual-use.** Les gestes qui sollicitent réellement
  la cible (ATHN-02, ATHN-03, INPV-*, CONF-06…) ne s'exécutent que sur périmètre autorisé par
  écrit, sur instance dédiée, jamais sur un système tiers — mêmes règles que
  `oracles/oracle-dast.mjs`, qui les encode en refus fail-closed.
- **Cité, jamais recopié.** Les résumés et gestes ci-dessus sont une reformulation ; ils ne se
  substituent pas aux fiches WSTG, qui restent la référence opératoire.
