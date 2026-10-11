mod catalog;
mod config;
mod crypto;
mod guard;
mod sysutil;
mod vault;

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::Zeroize;

use config::{Config, FolderEntry};

/// Journalise une ligne horodatée dans %APPDATA%\Sentinelle\sentinelle.log + stderr.
pub fn logln(msg: &str) {
    let ts = unsafe {
        let st = windows::Win32::System::SystemInformation::GetLocalTime();
        format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
    };
    let line = format!("[{ts}] {msg}");
    eprintln!("{line}");
    if let Ok(dir) = config::config_dir() {
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("sentinelle.log")) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn prompt_password(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("SENTINELLE_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let pass = rpassword::prompt_password("Mot de passe : ")?;
    if pass.is_empty() {
        bail!("mot de passe vide refusé");
    }
    if confirm {
        let again = rpassword::prompt_password("Confirmer le mot de passe : ")?;
        if pass != again {
            bail!("les mots de passe ne correspondent pas");
        }
    }
    Ok(pass)
}

// ------------------------------------------------------------------- init
fn cmd_init() -> Result<()> {
    let mut cfg = Config::load()?;
    if cfg.is_initialized() {
        println!("Déjà initialisé. Le mot de passe maître est déjà défini.");
        return Ok(());
    }
    println!("Définis le mot de passe maître de Sentinelle.");
    println!("⚠️  Il protège TOUS tes dossiers. Si tu l'oublies, les données sont irrécupérables.");
    let mut password = prompt_password(true)?;
    let salt = crypto::random_bytes::<16>();
    let key = crypto::derive_key(password.as_bytes(), &salt)?;
    password.zeroize();
    let (vnonce, v) = crypto::make_verifier(&key)?;
    cfg.salt = B64.encode(salt);
    cfg.verifier_nonce = B64.encode(vnonce);
    cfg.verifier = B64.encode(v);
    cfg.save()?;
    println!("✅ Mot de passe maître défini. Lance 'sentinelle scan' puis 'sentinelle guard'.");
    Ok(())
}

// ------------------------------------------------------------------- scan
fn cmd_scan() -> Result<()> {
    let mut cfg = Config::load()?;
    let found = catalog::detect();
    println!("🔍 Détection des dossiers sensibles...\n");

    let mut known: std::collections::HashSet<String> =
        cfg.folders.iter().map(|f| f.path.to_lowercase()).collect();
    let mut added = 0usize;
    let mut current = String::new();
    for f in &found {
        if f.category != current {
            current = f.category.clone();
            println!("  [{}]", current);
        }
        let key = f.path.to_string_lossy().to_lowercase();
        let marker = if known.contains(&key) { "déjà suivi" } else { "NOUVEAU" };
        println!("    • {:<22} {}  ({})", f.label, f.path.display(), marker);
        if !known.contains(&key) {
            known.insert(key);
            cfg.folders.push(FolderEntry {
                path: f.path.to_string_lossy().to_string(),
                category: f.category.clone(),
                processes: f.processes.clone(),
            });
            added += 1;
        }
    }
    cfg.save()?;
    write_dossiers_txt(&cfg)?;
    println!("\n✅ {} dossier(s) détecté(s), {} nouveau(x) ajouté(s).", found.len(), added);
    println!("   Total suivi : {} dossier(s).", cfg.folders.len());
    println!("   Liste lisible : dossiers.txt");
    if !cfg.is_initialized() {
        println!("\n👉 Étape suivante : 'sentinelle init' pour définir le mot de passe maître.");
    }
    Ok(())
}

fn write_dossiers_txt(cfg: &Config) -> Result<()> {
    let mut out = String::from("# Dossiers suivis par Sentinelle (généré par 'scan').\n# Liste indicative, modifiable. La vraie config est dans %APPDATA%\\Sentinelle\\config.json\n\n");
    let mut current = String::new();
    for f in &cfg.folders {
        if f.category != current {
            current = f.category.clone();
            out.push_str(&format!("# --- {} ---\n", current));
        }
        out.push_str(&f.path);
        out.push('\n');
    }
    std::fs::write("dossiers.txt", out).context("écriture de dossiers.txt")?;
    Ok(())
}

// ------------------------------------------------------------------- list
fn cmd_list() -> Result<()> {
    let cfg = Config::load()?;
    println!("Mot de passe maître : {}", if cfg.is_initialized() { "défini ✅" } else { "NON défini ❌ (lance 'init')" });
    println!("Réglages agent : écran={}  inactivité={}({}min)  arrêt={}  déverrouillage-retour={}",
        cfg.lock_on_session_lock, cfg.lock_on_idle, cfg.idle_minutes, cfg.lock_on_shutdown, cfg.auto_unlock_on_resume);
    println!("\n{} dossier(s) suivi(s) :", cfg.folders.len());
    let mut current = String::new();
    for f in &cfg.folders {
        if f.category != current {
            current = f.category.clone();
            println!("  [{}]", current);
        }
        let dir = Path::new(&f.path);
        let state = if !dir.exists() {
            "introuvable"
        } else if vault::is_locked(dir) {
            "🔒 verrouillé"
        } else {
            "🔓 en clair"
        };
        println!("    {:<12} {}", state, f.path);
    }
    Ok(())
}

// ------------------------------------------------------------------- guard
fn cmd_guard() -> Result<()> {
    let cfg = Config::load()?;
    if !cfg.is_initialized() {
        bail!("mot de passe maître non défini. Lance d'abord 'sentinelle init'.");
    }
    if cfg.folders.is_empty() {
        bail!("aucun dossier suivi. Lance d'abord 'sentinelle scan'.");
    }
    println!("Sentinelle — agent de protection. Entre le mot de passe maître pour démarrer.");
    let password = prompt_password(false)?;
    let key = crypto::derive_key(password.as_bytes(), &B64.decode(&cfg.salt)?)?;
    let vnonce = B64.decode(&cfg.verifier_nonce)?;
    let v = B64.decode(&cfg.verifier)?;
    if !crypto::check_verifier(&key, &vnonce, &v) {
        bail!("❌ mauvais mot de passe");
    }
    drop(key);
    println!("✅ Agent lancé. Il verrouille tes dossiers quand tu t'absentes.");
    println!("   Laisse cette fenêtre ouverte. Ferme-la pour arrêter la protection.");
    guard::run(cfg, password)
}

// ------------------------------------------------------- lock/unlock/status manuels
fn cmd_lock(dir: &Path) -> Result<()> {
    if vault::is_locked(dir) {
        bail!("déjà verrouillé. Utilise 'unlock'.");
    }
    let cfg = Config::load()?;
    // Si le mot de passe maître est défini, on l'utilise (cohérent avec l'agent) :
    // tout dossier verrouillé devient déverrouillable par l'agent et inversement.
    let (salt_b64, vnonce_b64, v_b64, key) = if cfg.is_initialized() {
        let mut password = prompt_password(false)?;
        let key = crypto::derive_key(password.as_bytes(), &B64.decode(&cfg.salt)?)?;
        password.zeroize();
        if !crypto::check_verifier(&key, &B64.decode(&cfg.verifier_nonce)?, &B64.decode(&cfg.verifier)?) {
            bail!("❌ mauvais mot de passe maître");
        }
        (cfg.salt.clone(), cfg.verifier_nonce.clone(), cfg.verifier.clone(), key)
    } else {
        // pas de mot de passe maître : dossier autonome avec son propre sel
        let mut password = prompt_password(true)?;
        let salt = crypto::random_bytes::<16>();
        let key = crypto::derive_key(password.as_bytes(), &salt)?;
        password.zeroize();
        let (vnonce, v) = crypto::make_verifier(&key)?;
        (B64.encode(salt), B64.encode(vnonce), B64.encode(v), key)
    };
    let n = vault::lock_with_key(dir, &key, &salt_b64, &vnonce_b64, &v_b64)?;
    println!("✅ Dossier verrouillé : {} fichier(s) chiffré(s).", n);
    Ok(())
}

fn cmd_unlock(dir: &Path) -> Result<()> {
    let salt = vault::salt_of(dir)?.ok_or_else(|| anyhow::anyhow!("ce dossier n'est pas verrouillé"))?;
    let mut password = prompt_password(false)?;
    let key = crypto::derive_key(password.as_bytes(), &B64.decode(&salt)?)?;
    password.zeroize();
    let n = vault::unlock_with_key(dir, &key)?;
    println!("🔓 Dossier déverrouillé : {} fichier(s) restauré(s).", n);
    Ok(())
}

fn cmd_status(dir: &Path) -> Result<()> {
    if vault::is_locked(dir) {
        println!("🔒 VERROUILLÉ — {} fichier(s) chiffré(s).", vault::count_encrypted(dir));
    } else {
        println!("🔓 Déverrouillé (en clair).");
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "Sentinelle — protège tes données sensibles des stealers.\n\n\
         Mise en route :\n  \
         sentinelle scan                 détecte les dossiers sensibles\n  \
         sentinelle init                 définit le mot de passe maître\n  \
         sentinelle guard                lance l'agent (verrouillage auto quand tu t'absentes)\n\n\
         Autres :\n  \
         sentinelle list                 liste les dossiers suivis et leur état\n  \
         sentinelle lock|unlock|status <dossier>   opération manuelle"
    );
}

/// Lancement par double-clic (sans argument) : met en place la config la première
/// fois (détection + mot de passe), puis lance la surveillance en arrière-plan.
fn run_default() -> Result<()> {
    println!("🛡️  Sentinelle — surveillance de tes dossiers sensibles\n");

    // 1re utilisation : détecter les dossiers
    let cfg = Config::load()?;
    if cfg.folders.is_empty() {
        println!("Première utilisation : détection des dossiers sensibles...\n");
        cmd_scan()?;
        println!();
    }

    // 1re utilisation : créer le mot de passe maître
    let cfg = Config::load()?;
    if !cfg.is_initialized() {
        cmd_init()?;
        println!();
    }

    // surveillance (demande le mot de passe, puis veille en arrière-plan)
    cmd_guard()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        if let Err(e) = run_default() {
            eprintln!("Erreur : {e:#}");
            // laisse la fenêtre ouverte pour lire le message en cas de double-clic
            let _ = std::io::stdin().read_line(&mut String::new());
            std::process::exit(1);
        }
        return;
    }
    let need_dir = |a: &[String]| -> Result<PathBuf> {
        a.get(2).map(PathBuf::from).ok_or_else(|| anyhow::anyhow!("chemin du dossier manquant"))
    };
    let res = match args[1].as_str() {
        "scan" => cmd_scan(),
        "init" => cmd_init(),
        "list" => cmd_list(),
        "guard" => cmd_guard(),
        "lock" => need_dir(&args).and_then(|d| cmd_lock(&d)),
        "unlock" => need_dir(&args).and_then(|d| cmd_unlock(&d)),
        "status" => need_dir(&args).and_then(|d| cmd_status(&d)),
        other => {
            eprintln!("Commande inconnue : {other}\n");
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("Erreur : {e:#}");
        std::process::exit(1);
    }
}
