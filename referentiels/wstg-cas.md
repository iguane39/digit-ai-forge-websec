---
version: 0.2.1
challenge_date: 2026-08-14
oracle_dast: 0.2.0
sources:
  - "OWASP Web Security Testing Guide (WSTG) 4.2 — publié 2020-12, stable au 2026-08-14 (v5.0 non publiée à cette date), licence CC BY-SA 4.0 — https://github.com/OWASP/wstg"
  - "Sommaire des cas WSTG 4.2 (chapitres 4.1 à 4.12) — https://owasp.org/www-project-web-security-testing-guide/v42/"
  - "OWASP Application Security Verification Standard (ASVS) 5.0.0 — mai 2025, CC BY-SA 4.0 — colonne de rattachement de ce document, via referentiels/asvs-l1.md"
  - "Noms des règles d'attaque active de ZAP 2.17.0 (modules ascanrules et domxss de l'image ghcr.io/zaproxy/zaproxy:stable), lus localement le 2026-11-12 dans leurs fichiers de messages, sans balayage ; alertes d'un balayage actif réel contre la cible de fixture locale du dépôt, même date — section « Ce que le mode actif d'oracle-dast couvre »"
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

**Ajout du 03/11/2026 (0.2.0, TF-2071).** 11 cas rejoignent le référentiel : les 4 du chapitre 4.5
(ATHZ-01 à ATHZ-04), 6 du chapitre 4.10 (BUSL-01, -02, -03, -06, -08, -09) et INPV-19. Leurs
identifiants et leurs intitulés ont été relus le jour même contre le dépôt OWASP/wstg au tag
`v4.2` (commit `dd33419`), dossiers `05-Authorization_Testing`, `10-Business_Logic_Testing` et
`07-Input_Validation_Testing`. Le rattachement à une exigence d'`asvs-l1.md` est un jugement de
curation de cette forge : l'OWASP ne publie pas de table de correspondance entre les deux standards.

**Règle de curation** (ce qui explique ce qui est là et ce qui n'y est pas) : un cas WSTG
n'est curé que s'il **vérifie une exigence présente dans `referentiels/asvs-l1.md`**. Le
document ASVS reste la source des exigences (ce qu'on doit tenir) ; celui-ci n'apporte que la
**méthode de test** (comment on constate qu'on le tient). Trois cas font exception et sont
marqués comme tels : ils vérifient des règles déjà **outillées** par `oracle-exposition`
(CSP, anti-clickjacking, fuite de version) dont les exigences ASVS correspondantes sont
classées **L2/L3** — hors table L1, mais nommées dans la « note de cohérence » d'`asvs-l1.md`.

**39 cas curés** sur les 12 chapitres de la WSTG 4.2 : 36 rattachés à une exigence L1 nommée,
3 rattachés hors L1 (règles outillées). Chapitres et cas non curés : listés nommément
en fin de document (loi transverse n°3 du pilot — l'oubli ne se tait pas).

**Ajout du 12/11/2026 (0.2.1, TF-2460).** La colonne « Outillage » et les limites disaient qu'`oracle-dast`
ne lève que ce qu'une passe passive voit. C'était exact jusqu'à `oracle-dast` 0.1.x ; depuis la 0.2.0 (TF-2444),
son mode actif lance un balayage actif. La section « Ce que le mode actif d'oracle-dast couvre » dit ce qui
change, cas par cas, et sous quelle autorisation. `oracle_dast` du frontmatter nomme la version d'oracle décrite :
le self-test de la forge refuse ce fichier si cette version n'est plus celle de l'oracle.

**Colonne « Outillage »** : `oracle-exposition` | `oracle-sca` | `oracle-dast` | `manuel` —
jamais inventée. Un cas confié à `oracle-dast` nomme toujours le mode qui le lève, `passif` ou `actif` :
le mode passif (`zap-baseline.py`) lit ce que la cible renvoie sans l'attaquer, le mode actif
(`zap-full-scan.py`) attaque en plus les URL trouvées. Dans les deux modes le verdict reste soumis au garde-fou
d'autorisation de cet oracle, et une absence d'alerte n'y vaut jamais preuve d'absence de défaut.

## 4.2 — Configuration and Deployment Management (WSTG-CONF)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-CONF-04 | Des fichiers de sauvegarde, sources ou dossiers de gestion de version traînent-ils sous la racine servie ? | Demander les chemins connus (`/.git/HEAD`, `/.svn/entries`, `*.bak`, `*.old`, `*.zip`) et vérifier que la réponse n'est pas un contenu servi | V13.4.1 | manuel (sonde de chemins) ; oracle-dast (actif, partiel : règle « Hidden File Finder », qui sonde `.git/config`, `.svn/entries` et `.svn/wc.db`, pas les `*.bak`, `*.old` ni `*.zip`) |
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

## 4.5 — Authorization Testing (WSTG-ATHZ)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-ATHZ-01 | Un paramètre qui désigne un fichier permet-il de sortir du répertoire prévu, ou d'inclure un fichier local ou distant ? | Repérer les paramètres de nom ou de chemin de fichier, y substituer une remontée de répertoire (`../`, encodée, double encodée), un chemin absolu puis une URL distante, et lire si un contenu hors de la racine est servi | V5.3.2 | oracle-dast (actif : règles « Path Traversal » et « Remote File Inclusion » ; signal à qualifier) |
| WSTG-ATHZ-02 | Une fonction ou une ressource réservée reste-t-elle accessible sans session, après déconnexion, ou depuis un rôle qui ne devrait pas l'avoir ? | Relever avec un compte administrateur de test toutes les fonctions réservées, puis rejouer chaque requête sans session, après déconnexion et avec un compte de rôle inférieur | V8.2.1, V8.3.1 | manuel |
| WSTG-ATHZ-03 | Un utilisateur peut-il modifier son propre rôle ou ses privilèges, ou atteindre ce que détient un compte plus privilégié (élévation verticale) ou de même niveau (élévation horizontale) ? | Chercher dans les requêtes les champs de rôle, de groupe ou de niveau, les rejouer modifiés depuis un compte ordinaire, puis tenter les actions réservées à un compte plus privilégié et celles d'un compte pair | V8.2.1, V8.2.2 | manuel |
| WSTG-ATHZ-04 | Une référence d'objet fournie par l'utilisateur (identifiant, nom de fichier, clé) suffit-elle à lire ou modifier l'objet d'un autre compte (IDOR) ? | Avec deux comptes de test qui possèdent chacun des objets, substituer dans la requête de l'un l'identifiant d'un objet de l'autre (lecture, modification, suppression) et comparer avec la réponse à un identifiant inexistant | V8.2.2 | manuel |

## 4.6 — Session Management (WSTG-SESS)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-SESS-02 | Les cookies de session portent-ils les attributs qui les protègent ? | Lire les en-têtes `Set-Cookie` : `Secure`, `HttpOnly`, `SameSite`, préfixe `__Host-`/`__Secure-` | **V3.3.1** | **oracle-exposition (EX-8 ; EX-9/EX-10 hors L1)** |
| WSTG-SESS-04 | Un identifiant de session ou une donnée sensible transite-t-il par l'URL ? | Parcourir l'application en relevant les query strings, puis vérifier les journaux d'accès et l'en-tête `Referer` sortant | V14.2.1 | manuel |
| WSTG-SESS-05 | Une action sensible peut-elle être déclenchée depuis un autre site sans jeton ni contrôle d'origine ? | Rejouer une requête d'état depuis une page tierce, jeton anti-CSRF retiré puis remplacé par une valeur d'une autre session | V3.5.1, V3.5.2 | manuel |

## 4.7 — Input Validation (WSTG-INPV)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-INPV-01 | Un paramètre renvoyé dans la page permet-il d'y injecter du script (XSS réfléchi) ? | Injecter un marqueur inoffensif dans chaque paramètre reflété et observer s'il ressort encodé ou interprété comme balise | V1.2.1 | oracle-dast (passif : reflet signalé, exploitation non prouvée ; actif : règle « Cross Site Scripting (Reflected) » et sa variante en réponse JSON, signal à qualifier ; alerte constatée sur la cible de fixture le 12/11/2026) |
| WSTG-INPV-02 | Un contenu enregistré ressort-il exécutable pour les autres utilisateurs (XSS stocké) ? | Déposer un marqueur inoffensif via chaque champ persisté, puis le relire depuis un autre compte et une autre vue | V1.3.1 | manuel ; oracle-dast (actif, partiel : règle « Cross Site Scripting (Persistent) » et ses deux amorces ; ZAP relit dans la même session, la relecture depuis un autre compte reste manuelle) |
| WSTG-INPV-05 | Une entrée atteint-elle la base sans requête paramétrée (injection SQL) ? | Perturber la syntaxe d'un paramètre (quote, opérateur booléen, retard temporel) et observer erreur, différence de réponse ou de latence | V1.2.4 | oracle-dast (actif : règle « SQL Injection » et ses variantes temporelles, signal à qualifier ; alerte constatée sur la cible de fixture le 12/11/2026) |
| WSTG-INPV-07 | Le parseur XML accepte-t-il des entités externes ou une structure altérée ? | Soumettre un document déclarant une entité externe locale et observer si le contenu est résolu ou l'erreur détaillée | V1.5.1 | oracle-dast (actif : règles « XML External Entity Attack » et « Exponential Entity Expansion » ; signal à qualifier) |
| WSTG-INPV-11 | Une entrée finit-elle évaluée comme du code applicatif (`eval`, désérialisation, template) ? | Injecter une expression neutre mais calculable dans les paramètres suspects et vérifier si le résultat calculé ressort | V1.3.2 | oracle-dast (actif : règles « Server Side Code Injection » et « Server Side Template Injection » ; signal à qualifier) |
| WSTG-INPV-12 | Une entrée atteint-elle un appel système (injection de commande) ? | Ajouter un séparateur de commande suivi d'une commande inoffensive et observer la sortie ou le délai induit | V1.2.5 | oracle-dast (actif : règle « Remote OS Command Injection » et sa variante temporelle ; signal à qualifier) |
| WSTG-INPV-19 | Une fonction qui va chercher une ressource à partir d'une valeur fournie (URL, nom de fichier, adresse de rappel) peut-elle être orientée vers une adresse interne ou un fichier local (SSRF) ? | Sur l'instance de recette autorisée, substituer à la valeur une adresse de bouclage, une adresse privée, le point d'accès de métadonnées du fournisseur de cloud, puis une redirection vers l'une d'elles, et observer réponse, délai ou contenu renvoyé | V5.3.2 | manuel ; oracle-dast (actif, partiel : seule règle voisine « Cloud Metadata Potentially Exposed », le module ascanrules ne porte pas de règle SSRF) |

## 4.10 — Business Logic Testing (WSTG-BUSL)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-BUSL-01 | Le serveur refuse-t-il une donnée logiquement invalide que l'écran a laissée passer (valeur hors bornes, incohérence entre champs) ? | Envoyer directement au serveur, sans passer par l'écran, des valeurs négatives, nulles, hors bornes ou incohérentes entre elles, et lire si l'opération métier les accepte | V2.2.1, V2.2.2 | manuel |
| WSTG-BUSL-02 | Une requête fabriquée à la main permet-elle de contourner l'interface et de déclencher une valeur ou une fonction que le métier n'attend pas ? | Intercepter les requêtes d'un parcours, modifier les champs cachés et les paramètres de prix, de remise ou de statut, puis appeler les routes que l'écran n'expose pas | V2.2.2, V8.3.1 | manuel |
| WSTG-BUSL-03 | Le serveur recontrôle-t-il ce que l'interface présente comme non modifiable (champ caché, liste déroulante, valeur calculée) ? | Modifier par un proxy un champ caché ou une valeur de liste pour désigner une valeur ou un objet non proposé à ce compte, et vérifier que le serveur refuse | V2.2.1, V2.2.2 | manuel |
| WSTG-BUSL-06 | Peut-on atteindre l'étape finale d'un parcours en sautant, rejouant ou reculant des étapes, et un parcours abandonné laisse-t-il ses effets ? | Appeler directement la requête de l'étape finale sans les précédentes, rejouer une étape déjà validée, abandonner à mi-parcours et lire l'état résultant (points crédités, commande créée) | V2.3.1 | manuel |
| WSTG-BUSL-08 | Le téléversement refuse-t-il un fichier hors liste, selon l'extension, le type annoncé et le contenu ? | Téléverser un fichier d'extension non prévue, un fichier dont le type annoncé contredit le contenu, puis un lot mêlant fichiers admis et refusés, et lire si l'un passe | V5.2.2 | manuel |
| WSTG-BUSL-09 | Un fichier dangereux d'un type admis est-il accepté, rangé et servi de façon à s'exécuter ? | Téléverser un fichier inoffensif qui imite un script (marqueur neutre, jamais une charge réelle), l'appeler par son URL publique et vérifier qu'il n'est ni exécuté ni interprété | V5.3.1 | manuel |

## 4.11 — Client-side (WSTG-CLNT)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-CLNT-01 | Le code client écrit-il une donnée contrôlée par l'URL dans le DOM sans passer par une fonction sûre (XSS DOM) ? | Suivre les puits (`innerHTML`, `document.write`, `eval`) depuis les sources (`location`, `postMessage`) dans le JS servi | V3.2.2 | manuel ; oracle-dast (actif, partiel : règle « Cross Site Scripting (DOM Based) », qui rend un signal à qualifier, constaté le 12/11/2026 sur une cible de fixture dont la réflexion est côté serveur : l'alerte seule ne prouve pas un puits DOM) |
| WSTG-CLNT-04 | Une redirection est-elle pilotée par un paramètre sans liste blanche de destinations ? | Remplacer la destination par une origine externe puis par un protocole dangereux (`javascript:`, `data:`) et voir si elle est suivie | V1.2.2 | oracle-dast (actif : règle « External Redirect » ; signal à qualifier) |
| WSTG-CLNT-07 | La politique CORS renvoie-t-elle une origine reflétée ou un joker sur des données authentifiées ? | Rejouer une requête avec une `Origin` arbitraire et lire `Access-Control-Allow-Origin` / `-Credentials` de la réponse | V3.4.2 | manuel |
| WSTG-CLNT-09 | La page peut-elle être encadrée par un site tiers (clickjacking) ? | Charger l'URL dans une iframe d'origine différente et vérifier `X-Frame-Options` / `frame-ancestors` | hors L1 — cf. note de cohérence d'`asvs-l1.md` (L2/L3) | **oracle-exposition (EX-5)** |

## 4.9 — Cryptography (WSTG-CRYP)

| ID WSTG | Cas (résumé d'une ligne) | Geste de vérification | Exigence ASVS rattachée | Outillage |
|---|---|---|---|---|
| WSTG-CRYP-01 | Le service accepte-t-il encore des versions ou des suites TLS dépassées, ou un certificat non reconnu ? | Négocier explicitement chaque version de protocole et lire la chaîne du certificat présentée | V12.1.1, V12.2.2 | manuel (hors périmètre d'`oracle-exposition`, cf. `README.md §Limites`) |
| WSTG-CRYP-03 | Une donnée sensible circule-t-elle en clair sur un canal non chiffré ? | Recenser les appels sortants du produit (API, redirections, ressources) et relever ceux servis en `http://` | V12.2.1 | oracle-exposition (partiel — juge l'URL capturée) |

## Ce que le mode actif d'oracle-dast couvre

Pour le lecteur qui choisit entre une passe passive et un balayage actif : depuis la 0.2.0 de l'oracle
(12/11/2026, TF-2444), `--mode actif` lance `zap-full-scan.py` ou l'image Docker de ZAP. L'araignée parcourt la
cible, les règles passives lisent chaque réponse, puis les règles d'attaque active rejouent les URL trouvées avec
des entrées altérées. Le mode passif, qui reste le défaut, lance `zap-baseline.py` et n'attaque rien. Un mode ne
se rabat jamais sur l'autre : un ZAP de la mauvaise forme rend un `SKIP` (`DAST-ACTIF-IMPOSSIBLE`,
`DAST-PASSIF-IMPOSSIBLE`) et rien n'est lancé.

**Autorisation exigée.** Le mode actif suit les conditions du mode passif, plus une. Un fichier d'autorisation
écrit porte `autorisation_ecrite: true`, `mandat`, `proprietaire`, `environnement`, `cibles` et une `fenetre`
datée en cours de validité ; l'origine de `--cible` figure à l'identique dans `cibles`, sans joker. Une cible en
`production` exige `autorisation_production_distincte: true`. Le mode actif exige en plus `actif_autorise: true` :
sans lui, `DAST-AUTZ-MODE` refuse le balayage avant toute émission vers la cible. Trois options du mandat valent
dans les deux modes : `en_tete_acces` (un en-tête ajouté aux requêtes vers l'origine autorisée, le seul
mécanisme d'authentification de l'oracle), `debit_max_requetes_par_seconde` et `exclusions` (chemins dont aucune requête
ne part) ; une option mal formée refuse le balayage (`DAST-AUTZ-CHAMPS`). Chaque cas marqué `oracle-dast (actif …)`
ci-dessus ne se joue que sous ces conditions, sur une instance dédiée.

**Ce que l'oracle rend.** Des alertes ZAP triées par risque ; `high` et `medium` font échouer le verdict par défaut.
Aucun identifiant WSTG ne circule dans son verdict : relier une alerte à un cas est un geste du lecteur, d'après
le nom de la règle cité dans la colonne « Outillage ». Un cas marqué actif est donc « relevé si ZAP alerte »,
jamais « tenu » : l'absence d'alerte ne dit rien du cas.

**Ce que la forge a constaté, et ce qu'elle n'a pas constaté.**
- Le self-test, avec un ZAP simulé, prouve le garde-fou, la ligne de commande de chaque mode et les options du mandat.
- `scripts/preuve-dast-actif.mjs` prouve, avec le vrai ZAP, que le mode actif envoie à la cible de fixture des
  sondes que le mode passif n'envoie pas.
- Un balayage actif réel de cette même cible de fixture, joué le 12/11/2026 (290 s, 950 requêtes reçues, débit
  borné à 50 par seconde, ZAP 2.17.0 par Docker), a levé quatre alertes `high` : « Cross Site Scripting (Reflected) » (INPV-01), « SQL Injection »
  (INPV-05), « Cross Site Scripting (DOM Based) » (CLNT-01, voir sa ligne) et « Source Code Disclosure - File
  Inclusion », puis trois alertes `medium` de configuration (CSP absente, HTTP seul, en-tête anti-clickjacking
  absent). L'image ne porte aucune règle de ce dernier nom : le balayage a donc chargé des règles que l'image n'a pas
  (cause non vérifiée, la mise à jour des modules au lancement est probable), et la liste des règles ci-dessus est
  un minimum daté, pas la liste exacte d'un balayage.
- Les autres cas marqués actifs (ATHZ-01, INPV-02, -07, -11, -12, -19, CLNT-04, CONF-04) s'appuient sur le seul nom
  d'une règle installée : la forge ne les a jamais vus levés. Aucun balayage n'a visé une application riche ou
  authentifiée.

**Ce que le mode actif ne couvre pas.** Aucune règle d'attaque active lue dans l'image ne vise les cas ATHN-02,
ATHN-03, ATHZ-02 à ATHZ-04, BUSL-01, -02, -03, -06, -08, -09, CONF-06, IDNT-02 ni SESS-05. Ils demandent des
comptes, des rôles ou une connaissance du métier que ZAP n'a pas : ils restent `manuel`. Il n'existe pas de règle
SSRF dans les modules lus, donc INPV-19 reste manuel. `oracle-dast` ne passe pas `-j` à ZAP : l'araignée AJAX ne
tourne pas.

## Chapitres et cas NON curés

**Deux chapitres entiers sont hors de ce référentiel**, parce que le chapitre ASVS qu'ils
vérifieraient n'est lui-même pas curé dans `referentiels/asvs-l1.md` — les curer ici
produirait des cas de test rattachés à rien. ATHZ et BUSL en sortent depuis la 0.2.0, quand
`asvs-l1.md` a curé V8, V2 et V5 :

| Chapitre WSTG non curé | Ce qu'il teste | Motif |
|---|---|---|
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
| WSTG-INPV | INPV-03, INPV-04, INPV-06, INPV-08, INPV-09, INPV-10, INPV-13, INPV-14, INPV-15, INPV-16, INPV-17, INPV-18 |
| WSTG-BUSL | BUSL-04 (chronométrage : seule exigence voisine, V2.4.2, est L3), BUSL-05 (limite d'usage d'une fonction : portée par V2.3.2 et V2.4.1, L2), BUSL-07 (défenses contre le détournement d'usage : V2.4.1 en L2 et V16, non curé) |
| WSTG-CLNT | CLNT-02, CLNT-03, CLNT-05, CLNT-06, CLNT-08, CLNT-10, CLNT-11, CLNT-12, CLNT-13 |
| WSTG-CRYP | CRYP-02, CRYP-04 |

**Exigences L1 d'`asvs-l1.md` sans cas WSTG curé ici** : V1.2.3 (échappement JS/JSON),
V2.1.1 (documentation des règles de validation), V5.2.1 (taille des fichiers acceptés),
V8.1.1 (documentation des règles d'autorisation), V3.2.1 (contenu non interprété hors
contexte), V6.2.6/V6.2.7/V6.2.8 (masquage, collage,
absence de troncature du mot de passe), V15.1.1 et V15.2.1 (dépendances — vérifiées par
`oracle-sca`, hors méthode WSTG). Elles restent exigibles ; simplement, aucune méthode de
test WSTG n'est proposée pour elles en v0.

L'énumération ci-dessus est arrêtée au **sommaire WSTG 4.2 au 14/08/2026**. Avant tout usage,
recouper au sommaire du dépôt source : une v5.0 publiée renumérote et ajoute des cas.

## Limites — ce que ce référentiel n'est pas

- **Ni certification, ni pentest.** Dérouler ces 39 cas ne vaut ni certification OWASP, ni
  test d'intrusion : un pentest est conduit par un humain qui enchaîne les faiblesses,
  improvise hors scénario et juge l'exploitabilité réelle. Ce document ne fait que fixer une
  méthode reproductible sur un sous-ensemble.
- **Une méthode, avant d'être un outil.** Sur les 39 cas, 21 sont `manuel` seuls : ils décrivent le geste
  à faire, personne ne les exécute automatiquement. 4 autres (CONF-04, INPV-02, INPV-19, CLNT-01) restent manuels
  avec une part relevée par le mode actif d'`oracle-dast`. 7 sont confiés à `oracle-dast` en mode actif
  (ATHZ-01, INPV-01, -05, -07, -11, -12, CLNT-04) et 7 à `oracle-exposition`, dont 2 partiellement (ATHN-01,
  CRYP-03). Un cas coché sans geste exécuté n'est pas un cas tenu : seuls 5 cas (CONF-07, CONF-12, INFO-02,
  SESS-02, CLNT-09) sont rendus par un oracle exécuté sans qualification humaine ; une alerte d'`oracle-dast`
  est un signal à qualifier, et la forge n'en a constaté que trois sur sa cible de fixture (INPV-01, INPV-05,
  CLNT-01).
- **Couverture partielle assumée.** 2 chapitres entiers, plus les 56 cas nommés des chapitres
  partiellement couverts, sont hors périmètre (listés ci-dessus) : l'absence de constat sur
  ces cas n'est pas un constat d'absence de défaut.
- **Tout cas actif est soumis au garde-fou dual-use.** Les gestes qui sollicitent réellement
  la cible (ATHN-02, ATHN-03, ATHZ-*, INPV-*, BUSL-*, CONF-06…) ne s'exécutent que sur périmètre autorisé par
  écrit, sur instance dédiée, jamais sur un système tiers — mêmes règles que
  `oracles/oracle-dast.mjs`, qui les encode en refus fail-closed (le mode actif exige en plus `actif_autorise: true`).
- **Cité, jamais recopié.** Les résumés et gestes ci-dessus sont une reformulation ; ils ne se
  substituent pas aux fiches WSTG, qui restent la référence opératoire.
