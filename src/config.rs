//! Persistent Sentinelle configuration (%APPDATA%\Sentinelle\config.json).

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FolderEntry {
    pub path: String,
    pub category: String,
    /// Executables that own this folder (don't lock while they are running).
    #[serde(default)]
    pub processes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    /// Argon2 master salt (base64) — set by `init`.
    #[serde(default)]
    pub salt: String,
    /// Master verifier (base64) used to validate the password.
    #[serde(default)]
    pub verifier_nonce: String,
    #[serde(default)]
    pub verifier: String,
    /// Folders managed by the agent.
    #[serde(default)]
    pub folders: Vec<FolderEntry>,
    // --- agent settings ---
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
    let appdata = std::env::var("APPDATA").map_err(|_| anyhow!("APPDATA variable missing"))?;
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
        let txt = fs::read_to_string(&p).context("reading config.json")?;
        // tolerate a UTF-8 BOM (added by some editors such as Notepad)
        let txt = txt.trim_start_matches('\u{feff}');
        serde_json::from_str(txt).context("config.json is corrupted")
    }

    pub fn save(&self) -> Result<()> {
        let dir = config_dir()?;
        fs::create_dir_all(&dir).context("creating the config directory")?;
        fs::write(config_path()?, serde_json::to_vec_pretty(self)?).context("writing config.json")?;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        !self.salt.is_empty() && !self.verifier.is_empty()
    }
}
