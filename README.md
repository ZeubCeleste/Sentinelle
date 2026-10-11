# 🛡️ Sentinelle

**Sentinelle** is a **Rust** tool that protects your sensitive data (tokens, cookies,
passwords, crypto wallets, game saves…) against *stealers*.

It **automatically detects** the sensitive folders on your PC, then **encrypts them
(AES-256-GCM)** when you step away and **decrypts them when you return**. A locked folder
only holds files that are unreadable without your password. Even if malware runs while
you're away, all it gets is gibberish.

> ⚠️ Sentinelle is **not** an antivirus. It is a layer that protects data **at rest**. It
> does not replace good habits (don't run shady `.exe` files, enable 2FA…).

---

## ✨ Features

- 🔍 **Automatic detection** of dozens of sensitive locations: every browser (Chrome, Edge,
  Brave, Firefox, Opera…), Discord/Telegram/Signal, game launchers (Steam, Epic, Riot,
  Battle.net, EA, Ubisoft, Minecraft, Roblox…), crypto wallets (Exodus, Electrum, Ledger
  Live, Bitcoin Core…), Google Drive/Dropbox, password managers, SSH/AWS keys, and more.
- 🔒 **Automatic locking** when you step away: workstation locked (Win+L), inactivity,
  shutdown/logoff.
- 🔓 **Automatic unlocking** when you return (key kept in memory for the session).
- 🧠 **Smart**: it never locks the folder of a **running** application (that would corrupt
  it) — only the ones that are closed.
- 🔑 **Serious encryption**: AES-256-GCM (authenticated) + **Argon2id** key derivation
  (brute-force resistant). The key is wiped from memory when the program exits.

---

## 🚀 Install & use

### Requirements
- Windows 10/11
- [Rust](https://rustup.rs) (to build) — or grab the `.exe` from the *Releases*.

### Build
```bash
git clone https://github.com/ZeubCeleste/Sentinelle.git
cd Sentinelle
cargo build --release
```
The executable is produced at `target\release\sentinelle.exe`.

### Easiest way: double-click
Just run `sentinelle.exe`. It has **no console window** (nothing in the taskbar): a small
dialog asks for the master password once, then it watches silently in the background.
On first launch it also detects your sensitive folders and lets you create the password.
To stop it, end the `sentinelle.exe` process from Task Manager.

### Command line
```bash
sentinelle scan                     # auto-detect your sensitive folders
sentinelle init                     # set your master password (once)
sentinelle guard                    # start the agent (auto-lock when you step away)
sentinelle list                     # list tracked folders and their state
sentinelle lock   "C:\some\folder"  # lock a folder manually
sentinelle unlock "C:\some\folder"  # unlock a folder manually
sentinelle status "C:\some\folder"  # show a folder's state
```

### Start with Windows (optional)
Create a shortcut to `sentinelle.exe` in your Startup folder: press `Win+R`, type
`shell:startup`, and drop a shortcut there. Sentinelle will ask for the password at each
login.

---

## ⚠️ Must read

- **Don't forget your master password.** There is no recovery — that's the whole point.
- **Close an app before locking its folder** (the agent does this automatically by skipping
  running apps; but for a manual `lock`, close the app first).
- **Test on an unimportant folder first** and **keep a backup** of important data elsewhere.

---

## 🔧 How it works

- Each file `x` becomes `x.sfl`: `[ magic | nonce(12B) | ciphertext+tag (AES-256-GCM) ]`.
- A `.sentinelle.lock` marker (holds no secret) stores the Argon2 salt + a verifier that
  detects a wrong password **before** touching any file.
- Configuration (tracked folders, settings, master salt) lives in
  `%APPDATA%\Sentinelle\config.json`. The log is at `%APPDATA%\Sentinelle\sentinelle.log`.

### Known limitations
- Each file is encrypted fully in memory: ideal for configs/tokens (small), less suited to
  very large files (several GB).
- Only file *contents* are encrypted, not file names.
- The key stays in memory during the session (needed for auto-unlock): it protects against
  data theft from disk, not against malware reading live memory.

---

## 📂 Project layout
```
src/
  main.rs      CLI (scan, init, guard, lock, unlock, status, list) + double-click mode
  catalog.rs   catalog of known sensitive locations
  config.rs    config.json (%APPDATA%\Sentinelle)
  crypto.rs    AES-256-GCM + Argon2id
  vault.rs     lock/unlock a folder
  guard.rs     background agent (Windows session events, inactivity)
  sysutil.rs   running processes, inactivity
```

## 📜 License
MIT — see [LICENSE](LICENSE).
