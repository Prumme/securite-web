# 🔐 TP Sécurité Web – Failles et remédiations

Ce projet Node.js met en place un serveur web avec plusieurs failles de sécurité volontairement implémentées pour un TP, ainsi que leurs remédiations.

## ⚙️ Stack utilisée

- Node.js + Express
- MongoDB
- JSON Web Tokens (JWT)
- Nginx (reverse proxy)
- Certbot (HTTPS via Let's Encrypt)

## 💥 Failles implémentées

- 🛢️ **NoSQL Injection**  
  → Exploitable via des objets JSON non filtrés dans la route `/login`.

- 📂 **LFI (Local File Inclusion)**  
  → Lecture arbitraire de fichiers via `/read-file?file=...`.

- 🪙 **JWT forgery**  
  → Signature faible permettant de falsifier un rôle admin dans `/jwt-profile`.

## ✅ Remédiations ajoutées

- Filtrage strict sur `/login-secure`
- Liste blanche sur `/read-file-secure`
- Vérification du rôle réel de l’utilisateur dans `/jwt-profile-secure`

## 🚀 Lancement

```bash
npm install
pm2 start index.js --name tp-secu
