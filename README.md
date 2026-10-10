# 🛡️ Sentinelle

**Sentinelle** est un outil en **Rust** qui protège tes données sensibles (tokens, cookies,
mots de passe, portefeuilles crypto, sauvegardes de jeux…) contre les *stealers*.

Il **détecte automatiquement** les dossiers sensibles de ton PC, puis les **chiffre
(AES-256-GCM)** quand tu t'absentes et les **déchiffre à ton retour**. Un dossier verrouillé
ne contient plus que des fichiers illisibles sans ton mot de passe. Même si un malware
s'exécute pendant que tu es absent, il ne récupère que du charabia.

> ⚠️ Sentinelle n'est **pas** un antivirus. C'est une couche de protection des données **au
> repos**. Elle ne remplace pas la prudence (ne pas lancer d'`.exe` douteux, activer la 2FA…).

---

## ✨ Fonctionnalités

- 🔍 **Détection automatique** de dizaines d'emplacements sensibles : tous les navigateurs
  (Chrome, Edge, Brave, Firefox, Opera…), Discord/Telegram/Signal, launchers de jeux
  (Steam, Epic, Riot, Battle.net, EA, Ubisoft, Minecraft, Roblox…), portefeuilles crypto
  (Exodus, Electrum, Ledger Live, Bitcoin Core…), Google Drive/Dropbox, gestionnaires de
  mots de passe, clés SSH/AWS, etc.
- 🔒 **Verrouillage automatique** quand tu t'absentes : écran verrouillé (Win+L),
  inactivité, arrêt/déconnexion de Windows.
- 🔓 **Déverrouillage automatique** à ton retour (clé gardée en mémoire le temps de la session).
- 🧠 **Intelligent** : ne verrouille jamais le dossier d'une application **ouverte**
  (sinon il la corromprait) — seulement celles qui sont fermées.
- 🔑 **Chiffrement sérieux** : AES-256-GCM (authentifié) + dérivation de clé **Argon2id**
  (résistant au brute-force). La clé s'efface de la mémoire en fin d'exécution.

---

## 🚀 Installation & utilisation

### Prérequis
- Windows 10/11
- [Rust](https://rustup.rs) (pour compiler) — ou récupère l'`.exe` dans les *Releases*.

### Compiler
```bash
git clone https://github.com/<ton-pseudo>/Sentinelle.git
cd Sentinelle
cargo build --release
```
L'exécutable est généré dans `target\release\sentinelle.exe`.

### Mise en route (3 commandes)
```bash
sentinelle scan      # détecte automatiquement tes dossiers sensibles
sentinelle init      # définit ton mot de passe maître (une seule fois)
sentinelle guard     # lance l'agent : verrouille quand tu t'absentes
```
Laisse la fenêtre `guard` ouverte : c'est elle qui surveille. Ferme-la pour arrêter la protection.

### Autres commandes
```bash
sentinelle list                     # liste les dossiers suivis et leur état
sentinelle lock   "C:\un\dossier"   # verrouille un dossier à la main
sentinelle unlock "C:\un\dossier"   # déverrouille un dossier à la main
sentinelle status "C:\un\dossier"   # affiche l'état d'un dossier
```

### Lancer au démarrage de Windows (optionnel)
Crée un raccourci vers `sentinelle.exe guard` dans le dossier Démarrage :
appuie sur `Win+R`, tape `shell:startup`, et place-y un raccourci.
Sentinelle te demandera le mot de passe à chaque ouverture de session.

---

## ⚠️ À lire absolument

- **N'OUBLIE PAS ton mot de passe maître.** Il n'existe aucune récupération : c'est le but.
- **Ferme une application avant de verrouiller son dossier** (l'agent le fait automatiquement
  en ignorant les applis ouvertes ; mais pour un `lock` manuel, ferme l'appli d'abord).
- **Teste d'abord sur un dossier sans importance** et **garde une sauvegarde** de tes données
  importantes ailleurs.

---

## 🔧 Comment ça marche

- Chaque fichier `x` devient `x.sfl` : `[ magic | nonce(12o) | ciphertext+tag (AES-256-GCM) ]`.
- Un marqueur `.sentinelle.lock` (sans secret) stocke le sel Argon2 + un vérificateur qui
  permet de détecter un mauvais mot de passe **avant** de toucher aux fichiers.
- La configuration (dossiers suivis, réglages, sel maître) est dans
  `%APPDATA%\Sentinelle\config.json`. Le journal est dans `%APPDATA%\Sentinelle\sentinelle.log`.

### Limites connues
- Chaque fichier est chiffré entièrement en mémoire : idéal pour des configs/tokens (petits),
  moins adapté à de très gros fichiers (plusieurs Go).
- Seul le *contenu* est chiffré, pas les noms de fichiers.
- La clé reste en mémoire pendant la session (nécessaire au déverrouillage auto) : protège
  contre un vol de données sur disque, pas contre un malware qui lirait la mémoire en direct.

---

## 📂 Structure du projet
```
src/
  main.rs      CLI (scan, init, guard, lock, unlock, status, list)
  catalog.rs   catalogue des emplacements sensibles connus
  scanner      (dans main) détection + écriture de la config
  config.rs    config.json (%APPDATA%\Sentinelle)
  crypto.rs    AES-256-GCM + Argon2id
  vault.rs     verrouillage/déverrouillage d'un dossier
  guard.rs     agent arrière-plan (événements de session Windows, inactivité)
  sysutil.rs   process en cours, inactivité
```

## 📜 Licence
MIT — voir [LICENSE](LICENSE).
