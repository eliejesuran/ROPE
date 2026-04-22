# ROPE

> Messagerie privée, basée sur le numéro de téléphone, 100% Union Européenne, RGPD by design.

---

## Sprint 1 — État actuel

| Fonctionnalité | Status |
|---|---|
| Auth par numéro de téléphone (OTP hardcodé dev) | ✅ |
| Chiffrement AES-256-GCM bout en bout | ✅ |
| Serveur aveugle (ne voit jamais le plaintext) | ✅ |
| Messagerie temps réel (WebSocket) | ✅ |
| Suppression de compte RGPD | ✅ |
| Backend Node.js + PostgreSQL + Redis | ✅ |
| App React Native / Expo (iOS + Android) | ✅ |
| OTP réel par SMS (Infobip) | 🔜 Sprint 2 |
| Signal Protocol (X3DH + Double Ratchet) | 🔜 Sprint 2 |
| Notifications push | 🔜 Sprint 3 |

---

## Démarrage rapide

### 1. Backend (local avec Docker)

```bash
# Cloner et entrer dans le projet
cd rope

# Lancer PostgreSQL + Redis + Backend
docker-compose up -d

# Vérifier que le backend tourne
curl http://localhost:3000/health
# → {"status":"ok","version":"0.1.0","region":"EU"}
```

### 2. Exposer le backend aux iPhones (ngrok)

Pour tester sur de vrais iPhones sur le même réseau ou depuis internet :

```bash
# Option A : réseau local (plus simple)
# Trouver votre IP locale
ifconfig | grep "inet " | grep -v 127
# Ex: 192.168.1.42

# Option B : tunnel ngrok (accès depuis n'importe où)
brew install ngrok
ngrok http 3000
# → https://xxxx.ngrok-free.app
```

### 3. App mobile (Expo)

```bash
cd mobile
npm install

# Configurer l'URL du backend
# Créer mobile/.env :
echo 'EXPO_PUBLIC_API_URL=http://192.168.1.42:3000' > .env
# ou avec ngrok :
# echo 'EXPO_PUBLIC_API_URL=https://xxxx.ngrok-free.app' > .env

# Lancer Expo
npx expo start

# Scanner le QR code avec l'app "Expo Go" sur chaque iPhone
```

### 4. Premier test entre deux iPhones

1. **iPhone A** : entrer son numéro → code OTP = `123456` → connecté
2. **iPhone B** : entrer son numéro → code OTP = `123456` → connecté
3. **iPhone A** : ajouter iPhone B par son numéro
4. **iPhone A** : dans la conversation → 🔑 → "Générer une clé"
5. **iPhone A** : partager la clé affichée à iPhone B (copier/coller, IRL, ou appel)
6. **iPhone B** : dans la même conversation → 🔑 → "Entrer une clé" → coller
7. **Les deux iPhones peuvent maintenant s'envoyer des messages chiffrés** 🔒

---

## Architecture de sécurité

```
iPhone A                    Serveur                    iPhone B
   │                           │                           │
   │  plaintext                │                           │
   │ ──encrypt(AES-256-GCM)──► │                           │
   │                           │  ciphertext + IV only     │
   │                           │ ────────────────────────► │
   │                           │                           │ decrypt(AES-256-GCM)
   │                           │                           │ plaintext
```

Le serveur ne stocke et ne transmet que du ciphertext.  
Il est **cryptographiquement aveugle** au contenu des messages.

### Ce que le serveur stocke
- Hash bcrypt du numéro de téléphone (jamais le numéro en clair)
- Clé publique de l'appareil (pour identification, pas pour déchiffrement)
- Ciphertext + IV des messages (illisibles sans la clé partagée)
- UUID des utilisateurs et conversations

### Ce que le serveur ne voit jamais
- Le numéro de téléphone en clair
- Le contenu des messages
- La clé de conversation partagée entre les utilisateurs

---

## RGPD

- **Minimisation** : numéro de téléphone, c'est tout. Pas d'email, pas de nom réel.
- **Hébergement** : exclusivement en Union Européenne (Hetzner Finland recommandé)
- **Droit à l'effacement** : `DELETE /api/account` supprime toutes les données immédiatement
- **Pas de tracking**, pas d'analytics, pas de publicité
- **Journaux** : UUID seulement, jamais de PII

---

## Hébergement production recommandé (UE)

| Service | Pays | Usage |
|---|---|---|
| [Hetzner](https://hetzner.com) | 🇩🇪 Allemagne / 🇫🇮 Finlande | VPS backend |
| [Infobip](https://infobip.com) | 🇭🇷 Croatie | SMS OTP (Sprint 2) |
| [Scaleway](https://scaleway.com) | 🇫🇷 France | Alternative VPS |
| [Exoscale](https://exoscale.com) | 🇨🇭 Suisse | Alternative VPS |

---

## Roadmap

### Sprint 2
- OTP réel via Infobip (Croatie, RGPD)
- Signal Protocol — échange de clés automatique (X3DH)
- Double Ratchet — perfect forward secrecy
- Gestion des contacts (carnet local, pas uploadé)

### Sprint 3
- Notifications push (APNs iOS, FCM Android)
- Multi-appareils
- Messages éphémères
- Export données (RGPD article 20)
