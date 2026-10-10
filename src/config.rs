//! Configuration persistante de Sentinelle (%APPDATA%\Sentinelle\config.json).

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FolderEntry {
    pub path: String,
    pub category: String,
    /// Exécutables qui possèdent ce dossier (ne pas verrouiller s'ils tournent).
    #[serde(default)]
    pub processes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    /// Sel maître Argon2 (base64) — défini par `init`.
    #[serde(default)]
    pub salt: String,
    /// Vérificateur maître (base64) pour valider le mot de passe.
    #[serde(default)]
    pub verifier_nonce: String,
    #[serde(default)]
    pub verifier: String,
    /// Dossiers gérés par l'agent.
    #[serde(default)]
    pub folders: Vec<FolderEntry>,
    // --- réglages de l'agent ---
    #[serde(default = "d_true")]
    pub lock_on_session_lock: bool,
    #[serde(default = "d_true")]
    pub lock_on_idle: bool,
    #[serde(default = "d_idle")]
    pub idle_minutes: u64,
    #[serde(default = "d_true")]
    pub lock_on_shutdown: bool,
    #[serde(default = "d_true")]
    pub auto_unlock_on_resume: bool,
}

fn d_true() -> bool {
    true
}
fn d_idle() -> u64 {
    10
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 1,
            salt: String::new(),
            verifier_nonce: String::new(),
            verifier: String::new(),
            folders: Vec::new(),
            lock_on_session_lock: true,
            lock_on_idle: true,
            idle_minutes: 10,
            lock_on_shutdown: true,
            auto_unlock_on_resume: true,
        }
    }
}

pub fn config_dir() -> Result<PathBuf> {
    let appdata = std::env::var("APPDATA").map_err(|_| anyhow!("variable APPDATA absente"))?;
    Ok(PathBuf::from(appdata).join("Sentinelle"))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

impl Config {
    pub fn load() -> Result<Config> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(Config::default());
        }
        let txt = fs::read_to_string(&p).context("lecture de config.json")?;
        // tolère un BOM UTF-8 (ajouté par certains éditeurs comme le Bloc-notes)
        let txt = txt.trim_start_matches('\u{feff}');
        serde_json::from_str(txt).context("config.json corrompu")
    }

    pub fn save(&self) -> Result<()> {
        let dir = config_dir()?;
        fs::create_dir_all(&dir).context("création du dossier de config")?;
        fs::write(config_path()?, serde_json::to_vec_pretty(self)?).context("écriture de config.json")?;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        !self.salt.is_empty() && !self.verifier.is_empty()
    }
}
