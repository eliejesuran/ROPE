# ROPE

> Messagerie privée, basée sur le numéro de téléphone, 100% Union Européenne, RGPD by design.

## Sprint 1 — État actuel

| Fonctionnalité | Status |
|---|---|
| Auth par numéro de téléphone (OTP dev hardcodé) | ✅ |
| Chiffrement AES-256-GCM bout en bout | ✅ |
| Serveur aveugle (ne voit jamais le plaintext) | ✅ |
| Messagerie temps réel (WebSocket) | ✅ |
| Suppression de compte RGPD | ✅ |
| Backend Node.js + PostgreSQL + Redis | ✅ |
| App React Native / Expo 54 (iOS + Android) | ✅ |
| OTP réel par SMS (Infobip) | 🔜 Sprint 2 |
| Signal Protocol (X3DH + Double Ratchet) | 🔜 Sprint 2 |
| Notifications push | 🔜 Sprint 3 |

---

## Démarrage rapide

### 1. Backend

```bash
docker-compose up -d
curl http://localhost:3000/health
# → {"status":"ok","version":"0.1.0","region":"EU"}
```

### 2. App mobile

```bash
cd mobile
npm install
echo 'EXPO_PUBLIC_API_URL=http://localhost:3000' > .env
npx expo start
```

### 3. Tester sur simulateur iOS (sans iPhone physique)

Xcode doit être installé (gratuit, Mac App Store).

```bash
# Simulateur 1 (iPhone A)
npx expo start --ios

# Simulateur 2 (iPhone B) — ouvrir un second simulateur
open -n /Applications/Xcode.app/Contents/Developer/Applications/Simulator.app
# Expo détecte automatiquement les deux simulateurs
# Appuyer 'i' dans le terminal Expo pour choisir le device
```

Flux de test complet sur les deux simulateurs :
1. **iPhone A** : numéro quelconque → code OTP = `123456` → connecté
2. **iPhone B** : numéro différent → code OTP = `123456` → connecté
3. **iPhone A** : ajouter iPhone B par son numéro
4. **iPhone A** : dans la conversation → 🔑 → "Générer une clé"
5. Copier la clé (déjà dans le presse-papier)
6. **iPhone B** : même conversation → 🔑 → "Entrer une clé" → coller
7. Les deux peuvent s'envoyer des messages chiffrés 🔒

> **Sur réseau réel** : remplacer `localhost` par l'IP locale (`ifconfig | grep "inet "`) ou un tunnel ngrok (`ngrok http 3000`).

---

## Architecture de sécurité

```
iPhone A                    Serveur                    iPhone B
   │                           │                           │
   │──encrypt(AES-256-GCM)────►│                           │
   │                           │──ciphertext + IV─────────►│
   │                           │                           │──decrypt──► plaintext
```

**Ce que le serveur stocke** : hash bcrypt du numéro · clé publique appareil · ciphertext + IV  
**Ce que le serveur ne voit jamais** : numéro en clair · plaintext des messages · clés de conversation

---

## RGPD

- Minimisation : numéro de téléphone uniquement. Pas d'email, pas de nom réel.
- Hébergement UE exclusif (Hetzner Finland recommandé)
- Droit à l'effacement : `DELETE /api/account` supprime toutes les données immédiatement
- Logs pseudonymisés : UUID seulement, jamais de PII

---

## Roadmap

### Sprint 2
- OTP réel via Infobip (Croatie, RGPD) — stub `sms.js` déjà en place, décommenter
- Signal Protocol : X3DH pour échange de clés automatique
- Double Ratchet : perfect forward secrecy
- Remplacer le keypair stub (`getOrCreateDeviceKeypair`) par Curve25519 réel

### Sprint 3
- Notifications push (APNs iOS, FCM Android)
- Multi-appareils
- Messages éphémères
- Export données (RGPD article 20)

---

## Points d'attention pour Sprint 2

| Problème | Fichier | Impact |
|---|---|---|
| `Alert.prompt` iOS uniquement | `ChatScreen.tsx:117` | Entrée de clé impossible sur Android |
| `contacts/find` O(n) users | `routes/contacts.js:25` | Scan bcrypt de tous les users — ne scale pas |
| `AppState.addEventListener` leak | `socket.ts:33` | Listener ajouté à chaque reconnexion |
| Keypair stub (bytes aléatoires) | `crypto.ts:23` | Remplacer par Curve25519 pour X3DH |
