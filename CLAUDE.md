# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Vue d'ensemble

Middleware FastAPI qui orchestre le provisioning dynamique de desktops virtuels en combinant **l'API REST Proxmox VE** (linked clones) et **Apache Guacamole** (accès RDP/VNC/SSH via navigateur). Déployé en Docker sur un hôte Proxmox 8.4 à `192.168.80.10`, aux côtés de `guacd`, `guac-db` (PostgreSQL 15) et `guacamole`.

Le code est structuré en package Python `app/` (config, database, models, routers, services, templates Jinja2). Pas de tests, pas de lint, pas de build — toute itération passe par `docker compose up -d --build`.

## Commandes courantes

```bash
# (Re)build + (re)démarrer le stack
docker compose up -d --build

# Iteration rapide sur le middleware uniquement
docker compose up -d --build vdi-orchestrator

docker logs -f vdi-orchestrator

curl http://localhost:8000/api/health
```

Dev local (hors Docker) depuis `app/` : `python -m uvicorn app.main:app --reload --app-dir ..` — nécessite que les env vars `PROXMOX_*` / `GUAC_DB_*` pointent vers des services joignables.

Pas de suite de tests.

## Architecture

### Organisation du package

```
app/
├── main.py                  # FastAPI factory + middleware auth_gate + lifespan
├── config.py                # Settings depuis les env vars (singleton `settings`)
├── database.py              # get_db() psycopg2 + db_cursor() ctx + init_schema()
├── models.py                # Pydantic (TemplateIn/Out, CloneOut, CloneRequest)
├── routers/
│   ├── auth.py              # /login, /logout + helpers current_user/require_user/require_admin
│   ├── portal.py            # GET / (portail utilisateur)
│   ├── admin.py             # GET /admin (dashboard HTML)
│   └── api.py               # /api/* JSON REST
├── services/
│   ├── proxmox.py           # Client Proxmox (auth ticket, clone, start, destroy, agent IP)
│   ├── guacamole.py         # Accès direct DB Guacamole (auth SHA256, groupes, connexions)
│   ├── clone_manager.py     # Pipeline de provisioning + verrous asyncio par (user, template)
│   └── session_monitor.py   # Tâche background : auto-destroy, timeouts, orphelins
└── templates/               # Jinja2 (base.html avec CSS inliné, login/portal/admin)
```

### Trois intégrations critiques

1. **Proxmox REST API** (`services/proxmox.py`) — ticket cookie + `CSRFPreventionToken`, cache ~7000 s, TLS non vérifié (`PROXMOX_VERIFY_SSL = False`). Utilisé pour cloner, configurer, démarrer, détruire les VMs et lire leur IP via `qemu-guest-agent network-get-interfaces`.

2. **PostgreSQL de Guacamole en direct** (`services/guacamole.py`) — ne passe **jamais** par l'API REST de Guacamole, tout se fait par SQL direct sur `guacamole_db`. Schéma utilisé :
   - Auth : `guacamole_entity` + `guacamole_user` avec `SHA256(password + UPPER(HEX(salt)))` comparé à `password_hash` (bytea).
   - Groupes user : `guacamole_user_group_member` → `guacamole_user_group` → `guacamole_entity` (type=USER_GROUP).
   - Admin : `guacamole_system_permission.permission = 'ADMINISTER'` OU `username == 'guacadmin'` OU présence dans `settings.EXTRA_ADMINS` (env var).
   - Connexions : `INSERT INTO guacamole_connection` + `guacamole_connection_parameter` + permission via `guacamole_connection_permission` limitée au user demandeur.
   - Sessions : `guacamole_connection_history` avec `end_date IS NULL` = session active (c'est le signal principal pour l'auto-destroy).
   Toute modification du schéma Guacamole upstream peut casser ces requêtes.

3. **Guacamole Web UI** — uniquement pour construire une URL deep-link `/guacamole/#/client/<base64(id\0c\0postgresql)>` (`guacamole.guac_client_url`).

### Tables VDI propres (`database.py::VDI_SCHEMA`)

Créées au démarrage via `IF NOT EXISTS` dans la même DB que Guacamole :
- `vdi_template` — templates configurés (VMID, display_name, protocol, port, credentials par défaut, cores, memory, max_clones, enabled).
- `vdi_template_group` — association template → groupes Guacamole autorisés. Un template **sans groupe assigné est visible par tous**.
- `vdi_clone` — clones actifs. `UNIQUE(vmid)` sert de **verrou DB pour la réservation** (voir `clone_manager.request_clone`).
- `vdi_session_log` — historique des sessions terminées, avec `destroy_reason` (`manual`, `auto_disconnect`, `unused_timeout`, `timeout`, `cleanup`, `error`).
- `vdi_user_2fa` — 2FA email opt-in par utilisateur (`username`, `email`, `enabled`). Le code OTP n'est jamais stocké en clair : seul son HMAC (clé = `SECRET_KEY`) transite dans la session signée. SMTP configuré via `SMTP_*` ; envoi dans `services/mailer.py`, logique OTP dans `services/twofa.py`.

Pas d'ORM, pas de framework de migration — toutes les requêtes SQL sont explicites dans `database.py`, `services/guacamole.py`, `services/clone_manager.py`, `routers/*`.

### Pipeline de provisioning (`services/clone_manager.py::request_clone`)

Séquentiel avec statut avançant dans `vdi_clone.status` :
`creating → waiting_clone → starting → waiting_ip → creating_connection → ready`.

Étapes :
1. **Verrou asyncio** par `(username, template_id)` — `_lock_for()` bloque les doubles clics.
2. Check clone existant pour ce user+template ; si oui, retour idempotent.
3. Check `max_clones` non atteint.
4. **Réservation VMID** : `find_free_vmid` + `INSERT INTO vdi_clone` ; l'unique constraint sert de verrou DB en cas de race avec d'autres workers.
5. `create_linked_clone` → `wait_for_clone_task` → `start_vm` → `wait_for_vm_ip` (timeout `POLL_TIMEOUT`).
6. `guacamole.create_connection` + `grant_connection_permission(connection_id, username)` (permission user uniquement, pas global).
7. Update `vdi_clone.status = 'ready'` + `guac_connection_id`.
8. **Sur exception à n'importe quelle étape** : destroy_vm, delete_connection, insert `vdi_session_log` avec `reason='error'`, DELETE de `vdi_clone`.

### Session monitor (`services/session_monitor.py`)

Tâche asyncio lancée dans `lifespan`, boucle toutes les `MONITOR_INTERVAL` (15 s par défaut) :

- Pour chaque clone en statut `ready` avec un `guac_connection_id` :
  - `guacamole.session_state(conn_id)` retourne `{has_history, active, last_end}`.
  - Si `active` → update `last_activity` + `connected_at` (si null).
  - Si `has_history` mais pas `active` → session terminée → **destroy auto** avec `reason='auto_disconnect'`.
  - Si jamais utilisé (`not has_history`) et age > `UNUSED_TIMEOUT` (300 s) → destroy `reason='unused_timeout'`.
  - Si age > `MAX_CLONE_LIFETIME` (14400 s = 4 h) → destroy `reason='timeout'`.
- Clones bloqués en statut intermédiaire > 2× `POLL_TIMEOUT` → destroy `reason='error'`.
- **Orphan sweep** (toutes les `ORPHAN_SCAN_INTERVAL` s) : scan des VMs Proxmox dont le nom commence par `CLONE_NAME_PREFIX`, dans la plage du pool, absentes de `vdi_clone` → `proxmox.destroy_vm`.

Le redémarrage du container ne détruit plus les clones existants (comme c'était le cas avant le refactor) — l'état est persistant dans `vdi_clone`.

### Authentification & autorisation

- Tout accès HTTP passe par le middleware `auth_gate` dans `main.py` : routes publiques = `/login`, `/logout`, `/api/health`, `/static/*`. Tout le reste exige une session active (`request.session["user"]`).
- Session via `SessionMiddleware` (Starlette + `itsdangerous`), cookie signé par `SECRET_KEY` (env var, aléatoire par défaut à chaque démarrage — **définir `SECRET_KEY` en prod pour éviter les logouts au redémarrage**).
- Les routes protégées appellent manuellement `require_user(request)` ou `require_admin(request)` depuis `routers/auth.py`. Ces helpers lèvent `HTTPException(401/403)`.
- `is_admin` (`services/guacamole.is_admin`) : `guacadmin` OU `EXTRA_ADMINS` OU permission système `ADMINISTER` dans Guacamole.
- Filtre des templates visibles dans le portail (`routers/portal._templates_for_user`) : intersection `vdi_template_group.guacamole_group_name` ∩ groupes Guacamole de l'utilisateur, ou template sans groupe = visible par tous.

### Contrat avec les templates Proxmox

Les VMs template doivent avoir `qemu-guest-agent` installé + activé (sinon `wait_for_vm_ip` timeout) et le service correspondant au protocole/port déclaré (typiquement `xrdp` sur 3389). Ces prérequis ne sont pas vérifiés — un échec se manifeste comme un timeout générique.

### Dockerfile / layout d'exécution

- `build: ./app` dans `docker-compose.yml` → le contexte build est le dossier `app/`.
- Le Dockerfile fait `COPY . /srv/app/` puis `WORKDIR /srv/app`, et lance `uvicorn app.main:app --app-dir /srv`. `--app-dir /srv` ajoute `/srv` au `sys.path` pour que `app.main` soit importable comme package, mais le CWD reste `/srv/app` pour que `Jinja2Templates(directory="templates")` résolve vers `/srv/app/templates`.
- Si tu ajoutes un nouveau module Python, vérifie qu'il est dans `/srv/app/` (c'est-à-dire dans le contexte de build) et utilise un import relatif (`from .xxx` / `from ..xxx`).

### Variables d'environnement

Déclarées dans `app/config.py` (singleton `settings`). Critiques en prod : `PROXMOX_PASSWORD` (obligatoire), `SECRET_KEY` (sinon sessions jetables), `GUAC_DB_PASSWORD` (dupliqué dans 3 services du docker-compose — toute rotation doit les toucher tous les 3), `EXTRA_ADMINS` (liste CSV), `UNUSED_TIMEOUT`, `MAX_CLONE_LIFETIME`.

## À NE PAS faire

- Pas d'ORM (pas de SQLAlchemy) — toutes les requêtes SQL sont directes via `psycopg2` + `db_cursor()`.
- Pas d'`ALTER TABLE` (DDL) sur les tables `guacamole_*`. En revanche le DML est autorisé : `guacamole_connection*` / `guacamole_connection_permission` (connexions) **et** la gestion des comptes via `guacamole_entity`, `guacamole_user`, `guacamole_user_group_member`, `guacamole_system_permission` (création/édition/suppression d'utilisateurs et de groupes — voir `services/guacamole.py`). Toute écriture respecte le schéma upstream (hash `SHA256(password + UPPER(HEX(salt)))`, suppression par cascade de l'entité).
- Pas d'API REST Guacamole — tout passe par SQL direct.
- Pas de framework JS frontend — HTML server-side via Jinja2, CSS inliné dans `templates/base.html`, vanilla JS dans les pages.
- Pas de `localStorage` côté frontend — l'état de session côté client est dans le cookie signé.
- Pas d'emojis comme icônes.
