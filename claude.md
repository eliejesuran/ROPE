# ROPE

> Messagerie privée, numéro de téléphone uniquement, 100% Union Européenne, RGPD by design.

## Sprint 1 — Terminé ✅

| Fonctionnalité | Status | Fichiers clés |
|---|---|---|
| Auth OTP (bypass dev : `123456`) | ✅ | `backend/src/controllers/authController.js` |
| Chiffrement AES-256-GCM E2E | ✅ | `mobile/src/services/crypto.ts` (node-forge) |
| Serveur aveugle (jamais de plaintext) | ✅ | `backend/src/controllers/messagesController.js` |
| Messagerie temps réel WebSocket | ✅ | `backend/src/services/websocket.js` |
| Messages alignés gauche/droite | ✅ | `mobile/src/screens/ChatScreen.tsx:188` |
| Suppression de compte RGPD | ✅ | `backend/src/routes/account.js` |
| Backend Node.js + PostgreSQL + Redis | ✅ | `backend/src/` + `docker-compose.yml` |
| App React Native / Expo 54 | ✅ | `mobile/` |
| Batterie de tests automatisés (67 tests) | ✅ | `backend/src/__tests__/` |
| Token invalide → auto-logout | ✅ | `mobile/src/services/authContext.tsx:42` |
| OTP réel SMS (Infobip) | 🔜 Sprint 2 | `backend/src/services/sms.js` |
| Signal Protocol (X3DH + Double Ratchet) | 🔜 Sprint 2 | `mobile/src/services/crypto.ts:28` |
| Notifications push | 🔜 Sprint 3 | |

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
3. iPhone A : trouver iPhone B → `🔑` → "Générer une clé" (copié dans presse-papier)
4. iPhone B : même conversation → `🔑` → "Entrer une clé" → coller
5. Les deux échangent des messages chiffrés `🔒`

> **Sur réseau réel** : `ifconfig | grep "inet "` pour l'IP locale, ou `ngrok http 3000`.

---

## Structure des fichiers clés

### Backend (`backend/src/`)

```
app.js                      — factory Express (utilisé par les tests)
index.js                    — entrée principale (DB + Redis + WebSocket)
controllers/
  authController.js         — request-otp, verify-otp, refresh
  messagesController.js     — send, get, delete
routes/
  auth.js                   — POST /api/auth/request-otp|verify-otp|refresh
  contacts.js               — POST /api/contacts/find, GET /api/contacts/conversations
  messages.js               — GET|POST|DELETE /api/messages
  account.js                — DELETE /api/account
middleware/
  auth.js                   — JWT verify → req.userId
models/
  db.js                     — schéma PostgreSQL + pool
services/
  sms.js                    — stub SMS (décommenter bloc Infobip pour Sprint 2)
  websocket.js              — socket.io, auth par JWT, room par userId
  redis.js                  — importé, non utilisé en Sprint 1
__tests__/
  auth.test.js              — 12 tests
  contacts.test.js          — 11 tests
  messages.test.js          — 15 tests
  account.test.js           — 9 tests
  security.unit.test.js     — 11 tests (deterministicPhoneHash, normalisePhone)
  crypto.unit.test.js       — 9 tests (AES-GCM Node WebCrypto)
  helpers/auth.js           — createUserAndLogin(), TEST_PUBLIC_KEY
```

### Mobile (`mobile/src/`)

```
screens/
  AuthScreen.tsx                — login OTP
  ConversationListScreen.tsx    — liste conversations
  ChatScreen.tsx                — messages gauche/droite, gestion clé 🔑
services/
  api.ts                        — fetch wrapper, gestion token SecureStore
  authContext.tsx               — restore session, logout sur token invalide
  socket.ts                     — socket.io client, reconnect sur AppState
  crypto.ts                     — AES-256-GCM via node-forge (pure JS)
```

---

## Architecture de sécurité

```
iPhone A                    Serveur                    iPhone B
   │                           │                           │
   │──encrypt(AES-256-GCM)────►│                           │
   │                           │──ciphertext + IV─────────►│
   │                           │                           │──decrypt──► plaintext
```

**Serveur stocke** : `HMAC-SHA256(phone, SERVER_PEPPER)` · `publicKey` (stub) · `ciphertext` + `iv`  
**Serveur ne voit jamais** : phone en clair · plaintext · clés de conversation

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

---

## RGPD

- Numéro hashé HMAC-SHA256 + pepper (jamais stocké en clair)
- `DELETE /api/account` : `phone_hash` → `DELETED_<id>`, ciphertext effacé
- Logs : UUID seulement, jamais de PII
- Hébergement cible : Hetzner Finland (UE)

---

## Sprint 2 — Plan

### 1. OTP réel via Infobip

**Fichier** : `backend/src/services/sms.js:28`  
Décommenter le bloc `fetch` Infobip. Ajouter `INFOBIP_API_KEY` et `INFOBIP_BASE_URL` dans `.env`.  
Mettre `OTP_BYPASS_ENABLED=false` en staging/prod.

### 2. Signal Protocol — X3DH (échange de clés automatique)

**Fichier à modifier** : `mobile/src/services/crypto.ts:28` — `getOrCreateDeviceKeypair()`  
Remplacer les bytes aléatoires par une vraie paire Curve25519.  
Bibliothèque recommandée : `curve25519-js` (pure JS, compatible Hermes) ou `@signalapp/libsignal-client` (natif).

Côté serveur : nouvelle table `device_keys` (identity key + signed prekey + one-time prekeys).  
Bob récupère les prekeys d'Alice → session établie sans échange manuel de clé.

### 3. Double Ratchet (forward secrecy)

Après X3DH, chaque message dérive une nouvelle clé. La lib Signal gère ça automatiquement.  
Retirer le flow manuel `🔑` dans `ChatScreen.tsx` une fois X3DH en place.

### 4. Fix Android : `Alert.prompt`

**Fichier** : `mobile/src/screens/ChatScreen.tsx:110` — `handleEnterReceivedKey()`  
`Alert.prompt` est iOS uniquement. Remplacer par un `Modal` React Native avec `TextInput`.

---

## Points d'attention pour Sprint 2

| Problème | Fichier | Impact |
|---|---|---|
| `contacts/find` O(n) bcrypt scan | `backend/src/routes/contacts.js:30` | Ne scale pas — ajouter index sur `phone_hash` |
| Keypair stub (random bytes) | `mobile/src/services/crypto.ts:34` | Bloque X3DH — remplacer par Curve25519 |
| `Alert.prompt` iOS uniquement | `mobile/src/screens/ChatScreen.tsx:110` | Bloque Android — remplacer par Modal |
| Redis importé mais non utilisé | `backend/src/services/redis.js` | Peut servir pour rate-limit OTP en Sprint 2 |

---

## Sprint 3 — Roadmap

- Notifications push (APNs iOS, FCM Android)
- Multi-appareils
- Messages éphémères
- Export données (RGPD article 20)
