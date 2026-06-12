# ROPE

> Messagerie privée, numéro de téléphone uniquement, 100% Union Européenne, RGPD by design.

## Sprint 1 — Terminé ✅

| Fonctionnalité | Status | Fichiers clés |
|---|---|---|
| Auth OTP (bypass dev : `123456`) | ✅ | `backend/src/controllers/authController.js` |
| Chiffrement AES-256-GCM E2E | ✅ | `mobile/src/services/crypto.ts` (node-forge) |
| Serveur aveugle (jamais de plaintext) | ✅ | `backend/src/controllers/messagesController.js` |
| Messagerie temps réel WebSocket | ✅ | `backend/src/services/websocket.js` |
| Messages alignés gauche/droite | ✅ | `mobile/src/screens/ChatScreen.tsx` |
| Suppression de compte RGPD | ✅ | `backend/src/routes/account.js` |
| Backend Node.js + PostgreSQL + Redis | ✅ | `backend/src/` + `docker-compose.yml` |
| App React Native / Expo 54 | ✅ | `mobile/` |
| Batterie de tests automatisés (110 tests) | ✅ | `backend/src/__tests__/` |
| Token invalide → auto-logout | ✅ | `mobile/src/services/authContext.tsx` |

## Sprint 2 — Terminé ✅

| Fonctionnalité | Status | Fichiers clés |
|---|---|---|
| Fix Android `Alert.prompt` → Modal | ✅ | `mobile/src/screens/ChatScreen.tsx` |
| Index `phone_hash` + fix O(n) scan | ✅ | `backend/src/routes/contacts.js` |
| OTP réel via Infobip | ✅ | `backend/src/services/sms.js` |
| Redis rate-limit OTP (5 req/10 min) | ✅ | `backend/src/controllers/authController.js` |
| X3DH Curve25519 — échange de clés auto | ✅ | `mobile/src/services/crypto.ts` |
| Table `device_keys` + `one_time_prekeys` + `x3dh_sessions` | ✅ | `backend/src/models/db.js` |
| API keys (`/api/keys/bundle`, `/api/keys/x3dh-init`) | ✅ | `backend/src/routes/keys.js` |
| Upload key bundle après login | ✅ | `mobile/src/services/authContext.tsx` |
| Session X3DH auto à l'ouverture d'une conv | ✅ | `mobile/src/screens/ChatScreen.tsx` |
| Double Ratchet (forward secrecy par message) | ✅ | `mobile/src/services/crypto.ts` |

---

## Démarrage rapide

```bash
# Backend
docker compose up -d
curl http://localhost:3000/health

# Tests (Docker doit tourner)
cd backend && npm test

# App mobile
cd mobile
echo 'EXPO_PUBLIC_API_URL=http://<HOST_IP>:3000' > .env
npx expo start
```

**Deux simulateurs iOS** :
```bash
npx expo start --ios
open -n /Applications/Xcode.app/Contents/Developer/Applications/Simulator.app
# Appuyer 'i' dans le terminal Expo pour choisir le device
```

Flux de test complet :
1. iPhone A : n'importe quel numéro → OTP `123456` → connecté
2. iPhone B : numéro différent → OTP `123456` → connecté
3. iPhone A : trouver iPhone B → conversation s'ouvre → chiffrement établi automatiquement (X3DH)
4. iPhone B : ouvre la même conversation → récupère l'init X3DH → même clé dérivée
5. Les deux échangent des messages chiffrés `🔒`

> **Sur réseau réel** : `ifconfig | grep "inet "` pour l'IP locale, ou `ngrok http 3000`.

### ⚠️ Après tout `npm install` côté backend

Le `docker-compose.yml` utilise un volume anonyme `/app/node_modules` pour le hot-reload. Ce volume est créé une fois et **ne se met pas à jour** lors d'un simple `docker compose up -d`, même après un rebuild de l'image. Si le backend démarre avec `Cannot find module '...'` :

```bash
docker compose rm -sf backend && docker compose up -d backend
```

Cela supprime le container **et** son volume anonyme, puis le recrée depuis la nouvelle image avec les bons modules.

---

## Structure des fichiers clés

### Backend (`backend/src/`)

```
app.js                      — factory Express (utilisé par les tests)
index.js                    — entrée principale (DB + Redis + WebSocket + Cron)
controllers/
  authController.js         — request-otp (+ rate-limit Redis), verify-otp, refresh
  messagesController.js     — send (+ expiresIn + push offline), get (filtre expirés), delete
routes/
  auth.js                   — POST /api/auth/request-otp|verify-otp|refresh
  contacts.js               — POST /api/contacts/find, GET /api/contacts/conversations
  messages.js               — GET|POST|DELETE /api/messages
  account.js                — DELETE /api/account, GET /api/account/export (RGPD Art.20)
  keys.js                   — PUT /api/keys/bundle, GET /api/keys/bundle/:userId
                              POST|GET /api/keys/x3dh-init, GET /api/keys/status
  push.js                   — POST /api/push/register, DELETE /api/push/unregister
middleware/
  auth.js                   — JWT verify → req.userId
models/
  db.js                     — schéma PostgreSQL + pool
services/
  sms.js                    — Infobip SMS (OTP_BYPASS_ENABLED=true en dev)
  websocket.js              — socket.io, auth par JWT, online tracking Map<userId,Set<socketId>>
  redis.js                  — rate-limit OTP (5 req/10 min par numéro)
  push.js                   — expo-server-sdk, sendPushNotifications()
  cron.js                   — node-cron, purge messages expirés toutes les minutes
__tests__/
  auth.test.js              — 13 tests (OTP flow + rate-limit)
  contacts.test.js          — 11 tests
  messages.test.js          — 21 tests (+ éphémères)
  account.test.js           — 12 tests (+ export RGPD)
  keys.test.js              — 25 tests (+ /status, invalidation IK, DELETE x3dh-init, spkId)
  push.test.js              — 8 tests (register/unregister)
  security.unit.test.js     — 11 tests (deterministicPhoneHash, normalisePhone)
  crypto.unit.test.js       — 9 tests (AES-GCM Node WebCrypto)
  helpers/auth.js           — createUserAndLogin(), TEST_PUBLIC_KEY
  __mocks__/expo-server-sdk.js — mock CJS pour Jest (expo-server-sdk est ESM)
```

### Mobile (`mobile/src/`)

```
screens/
  AuthScreen.tsx                — login OTP
  ConversationListScreen.tsx    — liste conversations + menu RGPD (export/delete)
  ChatScreen.tsx                — messages, X3DH auto, Double Ratchet, TTL picker éphémères
services/
  api.ts                        — fetch wrapper + tous les endpoints (messages, keys, push, account)
  authContext.tsx               — session, logout, upload key bundle, rotation SPK/OPKs, push token,
                                  wipe si changement de compte (state_owner_phone)
  socket.ts                     — socket.io client, reconnect sur AppState, onReconnect (catch-up)
  aes.ts                        — primitives AES-256-GCM + helpers base64 (partagées)
  secureFiles.ts                — fichiers JSON chiffrés (état DR > 2048 octets SecureStore)
  crypto.ts                     — X3DH (SPK versionnés) + Double Ratchet (mutex par conv) + wipeAllCryptoState()
  messageStore.ts               — store local de plaintext chiffré (les clés DR sont à usage unique)
metro.config.js                 — unstable_enablePackageExports pour @noble/curves
```

---

## Architecture de sécurité

```
iPhone A                         Serveur                        iPhone B
   │                                │                               │
   │──IK/SPK/OPKs (pub)────────────►│                               │
   │                                │◄──────────────IK/SPK/OPKs──── │
   │                                │                               │
   │  X3DH(IK_A, EK_A, SPK_B, OPK_B) ──── X3DH init ─────────────►│
   │                    SK = HKDF(DH1‖DH2‖DH3‖DH4)                 │
   │                                │         X3DH(SPK_B,IK_B,EK_A) │
   │                                │                    même SK ←  │
   │                                │                               │
   │  ── Double Ratchet (par message) ──────────────────────────── │
   │  header={dh, n, pn}            │                               │
   │  MK = KDF_CK(CKs)             │                               │
   │──encrypt(AES-256-GCM, MK)─────►│                               │
   │                                │──ciphertext+iv+header────────►│
   │                                │              MK=KDF_CK(CKr) ← │──decrypt──► plaintext
   │                                │        DH ratchet si new dh ← │
```

**Serveur stocke** : `HMAC-SHA256(phone, SERVER_PEPPER)` · clés publiques X3DH · `ciphertext` + `iv` + `ratchet_header`  
**Serveur ne voit jamais** : phone en clair · plaintext · clés privées · SK · clés de message DR

Double Ratchet — propriétés :
- **Forward secrecy** : chaque message a sa propre clé dérivée via `HMAC-SHA256(CK, 0x01)`, effacée après usage
- **Post-compromise security** : DH ratchet automatique à chaque réponse, renouvelle `RK`, `CKs`, `CKr`
- **Messages hors-ordre** : cache des clés sautées jusqu'à 50 par chaîne

Format ciphertext : `base64(cipher_bytes ‖ 16-byte GCM auth tag)` — compatible Web Crypto.

---

## Variables d'environnement

| Variable | Dev | Prod | Rôle |
|---|---|---|---|
| `JWT_SECRET` | `dev_jwt_secret_...` | secret 64 chars aléatoires | Signer les tokens |
| `SERVER_PEPPER` | `dev_pepper_...` | secret 64 chars aléatoires | HMAC du numéro de téléphone |
| `OTP_BYPASS_ENABLED` | `true` | `false` | Bypass SMS Infobip |
| `OTP_BYPASS_CODE` | `123456` | *(non applicable)* | Code OTP fixe dev |
| `DATABASE_URL` | `postgres://rope_user:...@localhost` | URL Hetzner managed DB | PostgreSQL |
| `REDIS_URL` | `redis://localhost:6379` | URL Redis interne | Rate-limit + cache |
| `INFOBIP_BASE_URL` | *(vide)* | `https://api.infobip.com` | SMS OTP |
| `INFOBIP_API_KEY` | *(vide)* | clé API Infobip | SMS OTP |
| `PORT` | `3000` | `3000` (derrière Caddy) | Port HTTP |
| `NODE_ENV` | `development` | `production` | Active SSL DB, rate-limit global |

---

## RGPD

- Numéro hashé HMAC-SHA256 + pepper (jamais stocké en clair)
- `DELETE /api/account` : `phone_hash` → `DELETED_<id>`, ciphertext effacé
- Logs : UUID seulement, jamais de PII
- Hébergement cible : Hetzner Finland (UE)

---

## Sprint 3 — Terminé ✅

| Fonctionnalité | Status | Fichiers clés |
|---|---|---|
| Notifications push (APNs iOS / FCM Android via Expo) | ✅ | `backend/src/services/push.js`, `routes/push.js`, `mobile/src/services/authContext.tsx` |
| Table `device_tokens` + `/api/push/register` | ✅ | `backend/src/models/db.js`, `backend/src/routes/push.js` |
| Online tracking WebSocket → push si hors-ligne | ✅ | `backend/src/services/websocket.js`, `controllers/messagesController.js` |
| Messages éphémères (TTL: 1h / 24h / 7j, bouton 🔥 dans l'UI) | ✅ | `backend/src/controllers/messagesController.js`, `mobile/src/screens/ChatScreen.tsx` |
| Cron purge messages expirés (chaque minute) | ✅ | `backend/src/services/cron.js` |
| Export données RGPD Art. 20 | ✅ | `backend/src/routes/account.js`, `mobile/src/screens/ConversationListScreen.tsx` |
| Rotation SPK (> 7j) / replenishment OPKs (< 5) | ✅ | `backend/src/routes/keys.js`, `mobile/src/services/authContext.tsx`, `crypto.ts` |

---

## Tests manuels Sprint 3

### Push notifications (nécessite un **dev build EAS** — pas Expo Go)

> ⚠️ **Expo Go ne supporte plus les push distants depuis le SDK 53.** `registerPushToken()` est automatiquement sauté dans Expo Go (log `[Push] Expo Go ne supporte pas les push distants`). Le warning `No "projectId" found` est aussi lié : le token Expo nécessite un projet EAS.

Préparation (une fois) :
```bash
npm install -g eas-cli
eas login                       # compte Expo gratuit
cd mobile && eas init           # ajoute extra.eas.projectId dans app.json
eas build --profile development --platform ios   # nécessite Apple Developer (99$/an) pour APNs
# installer le build sur l'iPhone, puis : npx expo start --dev-client
```

Test :
1. iPhone A connecté → passer en arrière-plan (ou couper le WiFi)
2. iPhone B envoie un message → iPhone A doit recevoir une notification push
3. Tapper la notif → l'app s'ouvre sur la bonne conversation
4. Vérifier côté backend : `SELECT * FROM device_tokens;` doit contenir le token Expo
5. Au logout iPhone A → token supprimé de `device_tokens`

### Messages éphémères
1. Ouvrir une conversation → appuyer sur le bouton `∞` à gauche de l'input → passer à `🔥1h`
2. Envoyer un message → vérifier que la bulle affiche `🔥 59min`
3. Vérifier en DB : `SELECT expires_at FROM messages ORDER BY sent_at DESC LIMIT 1;`
4. Tester le cron : `UPDATE messages SET expires_at = NOW() - INTERVAL '1 second' WHERE id = '...';` → attendre 1 min → le message doit avoir `deleted_at` et `ciphertext = ''`
5. Recharger la conversation → le message expiré n'apparaît plus

### Export RGPD
1. Ouvrir le menu `⋯` → "Exporter mes données (RGPD)"
2. Une alerte doit s'afficher avec : date de création du compte, nb de conversations, nb total de messages
3. Vérifier que le ciphertext n'apparaît jamais dans la réponse : `GET /api/account/export` avec un token valide

### Rotation SPK / replenishment OPKs
1. Après login, vérifier : `GET /api/keys/status` → `{ opkCount: 10, spkId: 1, spkCreatedAt: "..." }`
2. Simuler OPKs bas : `DELETE FROM one_time_prekeys WHERE user_id = '...' AND key_id > 3;` → se déconnecter / reconnecter → `opkCount` doit remonter à 13 (10 nouveaux ajoutés)
3. Simuler SPK ancien : `UPDATE device_keys SET spk_created_at = NOW() - INTERVAL '8 days' WHERE user_id = '...';` → reconnecter → `spk_id` doit passer à 2

---

## ⚠️ Bugs connus — audit crypto (12/06/2026)

**Symptôme** : les messages s'affichent `[Clé incorrecte ou manquante]` ; le timer 🔥 reste correct car `expires_at` est une métadonnée hors chiffrement.

**Cause racine — architecture incompatible avec le Double Ratchet** : l'app re-télécharge l'historique du serveur et le re-déchiffre à **chaque** ouverture de conversation (`loadMessages`). Or les clés DR sont à usage unique (forward secrecy) : un message ne peut être déchiffré qu'**une seule fois**, puis sa clé est effacée et la chaîne avance. Tout re-déchiffrement échoue par design — y compris pour ses propres messages, qu'on n'a jamais pu déchiffrer (clé de la chaîne d'envoi, pas de réception). Le modèle correct (Signal) : déchiffrer une fois à la réception, stocker le plaintext en local, ne jamais re-déchiffrer.

| # | Gravité | Statut | Fichier | Bug | Fix |
|---|---|---|---|---|---|
| 1 | 🔴 Critique | ✅ Corrigé 12/06 | `ChatScreen.tsx` `loadMessages` | Re-déchiffrement de l'historique à chaque ouverture — impossible avec DR (clés à usage unique) → toute la conv affiche l'erreur dès la réouverture | **`messageStore.ts`** : plaintext persisté localement après le 1er (et seul possible) déchiffrement — fichier JSON par conv chiffré AES-256-GCM (clé en SecureStore), TTL éphémères honoré localement |
| 2 | 🔴 Critique | ✅ Corrigé 12/06 | `ChatScreen.tsx` `decrypt` | Ses **propres** messages étaient passés à `drDecrypt` (aucun test sur `sender_id`) → `header.dh` = sa propre clé ratchet → échec garanti | Cache-first ; plaintext stocké au moment de l'envoi ; jamais de `drDecrypt` sur ses propres messages |
| 3 | 🔴 Critique | ⚠️ Procédure | État SecureStore des 2 appareils | Ratchets des téléphones **déjà désynchronisés** par l'ancien `Promise.all` + l'ancien logout/delete ne purgeait **aucun** état crypto local (SecureStore survit) | La suppression de compte purge désormais tout (`wipeAllCryptoState` + `wipeMessageStore`). Pour des comptes supprimés avec l'ancien code : re-créer les comptes suffit (nouvelle conv = X3DH neuf, l'état périmé est orphelin) |
| 4 | 🟠 Élevé | ✅ Corrigé 12/06 | `ChatScreen.tsx`, `crypto.ts` | Race : message socket pendant la boucle `loadMessages` → deux `drDecrypt` concurrents (pas de mutex) + doublon dans la liste | Mutex par conversation (`withDRLock`) autour de `drEncrypt`/`drDecrypt` + dédup par `id` + merge au lieu d'écrasement dans `loadMessages` |
| 5 | 🟠 Élevé | ✅ Supprimé 12/06 | `ChatScreen.tsx` (migration) | La branche `initiator` de la migration Sprint-2 était inatteignable (404 serveur à l'initiateur) → les deux appareils migraient en `responder` → conv bloquée | Code de migration **supprimé** (plus aucune conv Sprint-2 n'existe) : `conv_key` sans état DR → ré-établissement X3DH complet |
| 6 | 🟠 Élevé | ✅ Corrigé 12/06 | `crypto.ts`, `keys.js`, `db.js` | La rotation écrasait `spk_priv` → un X3DH init posté contre l'**ancien** SPK devenait irrésoluble (`x3dhResponder` lisait le SPK courant) → SK divergents | SPK versionnés `spk_priv_<id>`/`spk_pub_<id>` conservés sur 3 rotations (~3 sem.) ; `spk_id` stocké dans `x3dh_sessions` et rejoué côté responder ; throw explicite si le SPK n'existe plus |
| 7 | 🟠 Élevé | ✅ Corrigé 12/06 | `keys.js` `PUT /bundle` | `spk_created_at` jamais rafraîchi à la rotation (le `DEFAULT NOW()` ne joue qu'à l'INSERT) → passé 7 jours, **rotation à chaque login** (aggrave le bug 6) | `spk_created_at = NOW()` dans le `ON CONFLICT DO UPDATE` quand `spk_id` change |
| 8 | 🟡 Moyen | ✅ Corrigé 12/06* | `keys.js` | `x3dh_sessions` jamais supprimée ni invalidée — après réinstallation, le réinstallé consommait un init périmé ; OPKs orphelines en DB | IK changé dans `PUT /bundle` → suppression OPKs + inits en attente ; `DELETE /x3dh-init/:convId` + retry client (409→404). *Limite restante : l'**autre** participant garde son vieux ratchet → protocole de reset de session à prévoir (Sprint 4) |
| 9 | 🟡 Moyen | ✅ Corrigé 12/06 | `crypto.ts` `x3dhResponder` | OPK privée manquante ignorée **en silence** → SK différent de celui de l'initiateur, sans erreur visible | `throw` explicite → l'UI affiche « Chiffrement non établi » au lieu de messages cassés |
| 10 | 🟡 Moyen | ✅ Corrigé 12/06 | `crypto.ts`, `secureFiles.ts` | L'état DR (jusqu'à 50 `MK_skipped`) peut dépasser la limite **2048 octets** de SecureStore → écriture en échec selon la plateforme | `dr_<convId>` déplacé vers un fichier chiffré AES-256-GCM (clé en SecureStore), migration transparente depuis SecureStore |
| 11 | ⚪ Mineur | ✅ Corrigé 12/06 | `ChatScreen.tsx` `formatExpiry` | Le compte à rebours 🔥 était figé (calculé au render, aucun tick) | Tick 30 s (`extraData` FlatList) |
| 12 | 🟠 Élevé | ✅ Corrigé 12/06 | `authContext.tsx` | Connexion d'un **autre compte** sur le même téléphone : l'état crypto du compte précédent (IK, ratchets, plaintexts) était réutilisé tel quel → sessions désynchronisées + fuite d'historique entre comptes | Marqueur `state_owner_phone` ; si le numéro change → `wipeAllCryptoState()` + `wipeMessageStore()` avant de générer les clés |
| 13 | 🟠 Élevé | ✅ Corrigé 12/06 | `ChatScreen.tsx`, `socket.ts` | iOS coupe le socket en arrière-plan ; les messages envoyés pendant ce temps n'étaient **jamais** affichés tant que la conv restait ouverte (« messages perdus ») — et le push ne réveille pas Expo Go | Catch-up : refetch sur reconnexion socket (`onReconnect`) + retour au premier plan (`AppState`) + **poll 8 s** tant que la conv est ouverte — peu coûteux car le store local rend l'opération idempotente (cache hits, re-render sauté si rien de neuf) |
| 14 | 🟡 Moyen | ✅ Corrigé 12/06 | `ChatScreen.tsx` | Seuls les 50 derniers messages étaient chargés (`LIMIT 50`), aucune pagination dans l'UI → au-delà, les anciens messages semblaient « perdus » | Pagination `before=` via `onStartReached` (scroll vers le haut) + `maintainVisibleContentPosition` |

### Architecture du store local (fix bugs 1+2 — modèle Signal)

```
Réception (socket ou fetch) ──► drDecrypt UNE fois ──► messageStore (fichier chiffré)
Envoi                        ──► drEncrypt           ──► messageStore (plaintext local)
Affichage (toute ouverture)  ──► messageStore d'abord ; déchiffrement seulement si jamais vu
```

- `mobile/src/services/messageStore.ts` — un fichier JSON par conversation dans `documentDirectory/msgstore/`, chiffré AES-256-GCM avec `msgstore_key` (SecureStore). Les entrées portent `expires_at` → les éphémères disparaissent aussi du store local, même hors-ligne.
- Ses propres messages sans cache (autre appareil) → placeholder `[Envoyé depuis un autre appareil]`, jamais de tentative de déchiffrement.
- Suppression de compte → `wipeAllCryptoState()` (IK, SPK, OPKs, états DR via le registre `conv_registry`) + `wipeMessageStore()` (RGPD).
- `expo-notifications` réaligné `^56.0.17` → `~0.32.17` (version SDK 54 — l'ancienne cassait les types et risquait des erreurs natives dans Expo Go).

**Reste à faire avant la prod** : protocole de reset de session (suite du bug 8 — quand un participant réinstalle, l'autre doit détecter le changement d'identité et ré-établir le X3DH au lieu de garder son vieux ratchet). Tout le reste du tableau est corrigé.

---

## Sprint 4 — Mise en ligne (Production EU)

### Infrastructure 100% Union Européenne

| Tâche | Service EU | Notes |
|---|---|---|
| VPS backend | **Hetzner Cloud** (Helsinki ou Nuremberg) | CX21 min, Ubuntu 24.04 LTS |
| Base de données | **Hetzner Managed PostgreSQL** ou self-hosted sur le même VPS | Évite les frais de transfert entre DC |
| Redis | Self-hosted sur le VPS (container Docker) | Ou Hetzner Managed Redis si dispo |
| Reverse proxy + TLS | **Caddy** (Let's Encrypt auto) | Remplace Nginx, zéro config SSL |
| Domaine | **Gandi.net** (FR) ou OVH | Évite Namecheap/GoDaddy (US) |
| SMS OTP | **Infobip** (déjà intégré) ou **Vonage EU** | Données traitées en EU |
| Push notifications | **Expo Push Service** (intermédiaire US) | Seul le token opaque transite, pas de contenu |
| Object storage (futures pièces jointes) | **Hetzner Object Storage** (région EU) | Compatible S3 |
| Monitoring | **Grafana Cloud EU** (région Frankfurt) ou self-hosted | Stack Grafana+Prometheus sur le VPS |
| Backups | **Hetzner Snapshots** + exports PostgreSQL chiffrés | Chiffrement AES-256 avant upload |

### Étapes de déploiement backend

```bash
# 1. Créer le VPS Hetzner (Helsinki — Finland, EU)
# 2. Installer Docker + Docker Compose
# 3. Cloner le repo, créer .env.production avec les vraies valeurs
# 4. Lancer
docker compose -f docker-compose.prod.yml up -d

# 5. Caddy comme reverse proxy (Caddyfile)
# api.rope.app {
#   reverse_proxy localhost:3000
# }
```

**Fichiers à créer pour la prod :**
- `docker-compose.prod.yml` — sans `OTP_BYPASS_ENABLED`, avec SSL PostgreSQL, volumes persistants
- `Caddyfile` — TLS auto Let's Encrypt, HSTS, headers sécurité
- `.env.production` — **ne jamais commiter** (gitignore)

### Étapes mobile (Expo / App Stores)

```bash
# Installer EAS CLI
npm install -g eas-cli
eas login

# Configurer le projet Expo (ajouter projectId dans app.json)
eas build:configure

# Build de préproduction (TestFlight / Internal Track)
eas build --platform ios --profile preview
eas build --platform android --profile preview

# Soumettre aux stores
eas submit --platform ios
eas submit --platform android
```

**Comptes à créer :**
- Apple Developer Program (99 $/an) → App Store + APNs
- Google Play Console (25 $ une fois) → Play Store + FCM
- Expo account → EAS Build (gratuit jusqu'à 30 builds/mois)

**Ajouter dans `app.json` avant le build EAS :**
```json
"extra": { "eas": { "projectId": "<votre-expo-project-id>" } }
```

**Variables à configurer dans EAS Secrets (`eas secret:create`) :**
- `EXPO_PUBLIC_API_URL` → `https://api.rope.app`

### Checklist sécurité avant mise en ligne

- [ ] `JWT_SECRET` et `SERVER_PEPPER` changés (64 chars, `openssl rand -hex 32`)
- [ ] `OTP_BYPASS_ENABLED=false` en prod
- [ ] PostgreSQL avec SSL forcé (`rejectUnauthorized: true` déjà en place si `NODE_ENV=production`)
- [ ] Firewall VPS : seuls les ports 80, 443, 22 (SSH key only) ouverts
- [ ] Fail2ban sur SSH
- [ ] `ALLOWED_ORIGINS` restreint au domaine de l'app mobile
- [ ] Rotation des secrets tous les 90 jours (agenda)
- [ ] Backups PostgreSQL testés (restore drill)
- [ ] Politique de rétention des logs (pas de PII, max 30 jours)
- [ ] DPA (Data Processing Agreement) signé avec Hetzner et Infobip

### Roadmap Sprint 4+

- Multi-appareils (refonte `device_keys` en `(user_id, device_id)`)
- Rotation automatique des tokens JWT (refresh token flow)
- CI/CD GitHub Actions → deploy auto sur Hetzner
- Audit de sécurité externe (pentest)
- Politique de confidentialité + CGU (obligatoire App Store)
