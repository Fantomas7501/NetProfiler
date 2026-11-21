# NetProfiler — Cartographie, Profilage & Gestion Réseau

Application web sécurisée pour la cartographie des actifs réseau, l'inspection détaillée des ports exposés (bannières, CPE, scripts NSE, niveaux de risque), l'interrogation de l'historique des scans et la gestion multi-utilisateurs.

## Fonctionnalités

- **Authentification par mot de passe & contrôle d'accès (RBAC)**
  - Hachage `scrypt` avec sel aléatoire par utilisateur (`hashlib.scrypt`).
  - Sessions persistées en SQLite avec cookies `HttpOnly`, `SameSite=Lax` (tokens stockés sous forme de hash SHA-256).
  - Protection anti-brute-force sur la connexion.
  - Trois rôles : `admin` (accès complet + gestion utilisateurs/configuration), `analyst` (lecture + déclenchement de scans), `viewer` (lecture seule).
  - Gestion des utilisateurs : création, modification, changement de rôle, réinitialisation de mot de passe, activation/désactivation et suppression (avec garde-fous empêchant de supprimer/désactiver le dernier administrateur actif).
  - Page **Mon compte** : changement de mot de passe et révocation des autres sessions actives.
- **Page d'accueil : Cartographie réseau interactive (`#/map`)**
  - Topologie SVG interactive avec zoom, panoramique (pan), glisser-déposer des nœuds et 3 modes de disposition (*Étoile*, *Rôles*, *Grille*).
  - Filtres temps réel (recherche, catégories d'équipements, ports ouverts uniquement, nouveaux ports).
  - Infobulles au survol et **redirection directe vers la page de détails de l'actif** au clic sur un nœud.
- **Page de détails d'un actif (`#/asset/<ip>`)**
  - Identité complète (IP, MAC, constructeur OUI, OS estimé, latence, dates de détection) et sélecteur rapide d'actif.
  - Liste détaillée des ports exposés avec informations de profilage : service, produit, version, informations complémentaires, CPE, bannière réseau, résultats de scripts NSE et niveau de risque.
  - Historique des campagnes de scan pour l'actif.
- **Page Requête & Tableau (`#/query`)**
  - Conserve et enrichit la vue d'origine (4 indicateurs KPI, barre de recherche multi-champs, filtre *ports ouverts uniquement*).
  - Bascule entre **Cartes (vue d'origine)**, **Table Actifs** et **Table Ports** + export **CSV** / **JSON**.
- **Configuration (`#/config`)**
  - Paramètres du scanner (sous-réseau CIDR, fréquence, plage de ports, drapeaux Nmap, détection OS/NSE, alertes webhook, durée des sessions, rétention) et déclenchement manuel d'un scan.

## Démarrage rapide

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Ouvrez ensuite l'interface dans votre navigateur (port `8000`).

### Compte administrateur initial

Au premier démarrage (base vide), un compte administrateur est créé automatiquement :

- **Identifiant :** `admin` (personnalisable via `NETPROFILER_ADMIN_USER`)
- **Mot de passe :** `NetProfiler!2026` (personnalisable via `NETPROFILER_ADMIN_PASSWORD`)

> Pensez à modifier ce mot de passe dès la première connexion depuis la section **Mon compte**.

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `NETPROFILER_DB` | `./netprofiler.db` | Chemin vers la base SQLite |
| `NETPROFILER_ADMIN_USER` | `admin` | Identifiant admin initial |
| `NETPROFILER_ADMIN_PASSWORD` | `NetProfiler!2026` | Mot de passe admin initial |
| `NETPROFILER_SESSION_TTL_HOURS` | `24` | Durée de session par défaut (heures) |
| `NETPROFILER_COOKIE_SECURE` | `false` | Mettre à `true` derrière HTTPS |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Déploiement sur serveur Debian (`192.168.55.115`)

### Option 1 : Directement sur le serveur Debian (via GitHub)

```bash
git clone https://github.com/Fantomas7501/NetProfiler.git
cd NetProfiler
sudo ./deploy/install-debian.sh
```

### Option 2 : Depuis un poste du réseau local via SSH

```bash
./deploy/deploy-remote.sh <utilisateur>@192.168.55.115 8000
```

Le script installe l'application dans `/opt/netprofiler`, la base SQLite dans `/var/lib/netprofiler/netprofiler.db`, la configuration dans `/etc/netprofiler.env`, puis active et démarre le service `systemd` `netprofiler.service`.

