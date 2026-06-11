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
| Batterie de tests automatisés (88 tests) | ✅ | `backend/src/__tests__/` |
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

---

## Structure des fichiers clés

### Backend (`backend/src/`)

```
app.js                      — factory Express (utilisé par les tests)
index.js                    — entrée principale (DB + Redis + WebSocket)
controllers/
  authController.js         — request-otp (+ rate-limit Redis), verify-otp, refresh
  messagesController.js     — send, get, delete
routes/
  auth.js                   — POST /api/auth/request-otp|verify-otp|refresh
  contacts.js               — POST /api/contacts/find, GET /api/contacts/conversations
  messages.js               — GET|POST|DELETE /api/messages
  account.js                — DELETE /api/account
  keys.js                   — PUT /api/keys/bundle, GET /api/keys/bundle/:userId
                              POST|GET /api/keys/x3dh-init
middleware/
  auth.js                   — JWT verify → req.userId
models/
  db.js                     — schéma PostgreSQL + pool
services/
  sms.js                    — Infobip SMS (OTP_BYPASS_ENABLED=true en dev)
  websocket.js              — socket.io, auth par JWT, room par userId
  redis.js                  — rate-limit OTP (5 req/10 min par numéro)
__tests__/
  auth.test.js              — 13 tests (+ rate-limit)
  contacts.test.js          — 11 tests
  messages.test.js          — 17 tests (+ Double Ratchet header)
  account.test.js           — 9 tests
  keys.test.js              — 16 tests (bundle upload/fetch, x3dh-init)
  security.unit.test.js     — 11 tests (deterministicPhoneHash, normalisePhone)
  crypto.unit.test.js       — 9 tests (AES-GCM Node WebCrypto)
  helpers/auth.js           — createUserAndLogin(), TEST_PUBLIC_KEY
```

### Mobile (`mobile/src/`)

```
screens/
  AuthScreen.tsx                — login OTP
  ConversationListScreen.tsx    — liste conversations
  ChatScreen.tsx                — messages, X3DH auto à l'ouverture, chiffrement Double Ratchet
services/
  api.ts                        — fetch wrapper, gestion token SecureStore + keys API
  authContext.tsx               — restore session, logout sur token invalide, upload key bundle
  socket.ts                     — socket.io client, reconnect sur AppState
  crypto.ts                     — AES-256-GCM (node-forge) + X3DH + Double Ratchet (@noble/curves, @noble/hashes)
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

## Variables d'environnement (docker-compose.yml)

| Variable | Valeur dev | Rôle |
|---|---|---|
| `JWT_SECRET` | `dev_jwt_secret_...` | Signer les tokens — **changer en prod** |
| `SERVER_PEPPER` | `dev_pepper_...` | HMAC du numéro — **changer en prod** |
| `OTP_BYPASS_ENABLED` | `true` | Bypass SMS en dev |
| `OTP_BYPASS_CODE` | `123456` | Code fixe dev |
| `DATABASE_URL` | `postgres://rope_user:...` | PostgreSQL |
| `INFOBIP_BASE_URL` | `` | URL Infobip — mettre en staging/prod |
| `INFOBIP_API_KEY` | `` | Clé API Infobip — mettre en staging/prod |

---

## RGPD

- Numéro hashé HMAC-SHA256 + pepper (jamais stocké en clair)
- `DELETE /api/account` : `phone_hash` → `DELETED_<id>`, ciphertext effacé
- Logs : UUID seulement, jamais de PII
- Hébergement cible : Hetzner Finland (UE)

---

## Sprint 3 — Roadmap

- Notifications push (APNs iOS, FCM Android)
- Multi-appareils
- Messages éphémères
- Export données (RGPD article 20)
- Rotation automatique des SPK / replenishment des OPKs
