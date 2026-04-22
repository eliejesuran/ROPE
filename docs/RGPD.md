# Registre des traitements — EuroMsg
## Article 30 RGPD

Dernière mise à jour : 2025

---

### Responsable du traitement
À définir lors de la création de la société / association.

---

### Traitements effectués

| # | Finalité | Base légale | Données | Durée |
|---|---|---|---|---|
| 1 | Authentification | Consentement (Art. 6.1.a) | Hash du numéro de téléphone | Durée du compte |
| 2 | Messagerie | Exécution du contrat (Art. 6.1.b) | Ciphertext des messages (contenu illisible) | 90 jours après suppression |
| 3 | Sécurité | Intérêt légitime (Art. 6.1.f) | Logs d'accès (UUID uniquement, pas de PII) | 30 jours |

---

### Données collectées

**Ce que nous collectons :**
- Hash bcrypt du numéro de téléphone (irréversible)
- 4 derniers chiffres du numéro (affichage uniquement)
- Nom d'affichage (optionnel, choisi par l'utilisateur)
- Clé publique de l'appareil
- Messages chiffrés (ciphertext) — contenu illisible par nos soins
- Horodatages d'envoi/réception

**Ce que nous ne collectons PAS :**
- Numéro de téléphone en clair
- Contenu des messages (chiffré côté client)
- Carnet d'adresses / contacts
- Localisation
- Métadonnées de navigation
- Données publicitaires

---

### Droits des personnes concernées

| Droit | Comment l'exercer | Délai de réponse |
|---|---|---|
| Accès (Art. 15) | Paramètres → Mes données | Immédiat (export JSON) |
| Rectification (Art. 16) | Paramètres → Profil | Immédiat |
| Effacement (Art. 17) | Paramètres → Supprimer mon compte | Immédiat + purge 90j |
| Portabilité (Art. 20) | Paramètres → Exporter mes données | Sprint 3 |
| Opposition (Art. 21) | contact@euromsg.eu | 30 jours |

---

### Sous-traitants

| Sous-traitant | Pays | Rôle | Garanties |
|---|---|---|---|
| Hetzner Online | 🇩🇪 / 🇫🇮 UE | Hébergement serveur | DPA signé, ISO 27001 |
| Infobip | 🇭🇷 UE | Envoi SMS OTP (Sprint 2) | DPA signé, RGPD natif |

Aucun transfert de données hors Union Européenne.

---

### Sécurité

- Chiffrement en transit : TLS 1.3
- Chiffrement des messages : AES-256-GCM (bout en bout, clé côté client)
- Stockage des mots de passe / codes : bcrypt (facteur 10)
- Journaux : pseudonymisés (UUID uniquement)
- Accès serveur : restreint, authentification à deux facteurs
