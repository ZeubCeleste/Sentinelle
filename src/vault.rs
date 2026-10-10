//! Verrouillage / déverrouillage d'un dossier (chiffrement fichier par fichier).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::crypto::{self, SessionKey};

pub const MARKER: &str = ".sentinelle.lock";
pub const ENC_EXT: &str = "sfl";

/// Marqueur en clair déposé dans un dossier verrouillé (ne contient aucun secret).
#[derive(Serialize, Deserialize)]
pub struct Marker {
    pub version: u32,
    pub salt: String,
    pub verifier_nonce: String,
    pub verifier: String,
}

pub fn read_marker(dir: &Path) -> Result<Option<Marker>> {
    let p = dir.join(MARKER);
    if !p.exists() {
        return Ok(None);
    }
    let txt = fs::read_to_string(&p).context("lecture du marqueur")?;
    Ok(Some(serde_json::from_str(&txt).context("marqueur corrompu")?))
}

pub fn is_locked(dir: &Path) -> bool {
    dir.join(MARKER).exists()
}

fn write_marker(dir: &Path, m: &Marker) -> Result<()> {
    fs::write(dir.join(MARKER), serde_json::to_vec_pretty(m)?).context("écriture du marqueur")?;
    Ok(())
}

fn write_atomic(target: &Path, data: &[u8]) -> Result<()> {
    let tmp = target.with_extension(format!("sfltmp{}", u32::from_le_bytes(crypto::random_bytes::<4>())));
    {
        let mut f = fs::File::create(&tmp).context("création du fichier temporaire")?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, target).context("remplacement du fichier")?;
    Ok(())
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name != MARKER && !name.contains(".sfltmp")
        })
        .collect()
}

/// `a/b/fichier.txt` -> `a/b/fichier.txt.sfl`
fn append_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// `a/b/fichier.txt.sfl` -> `a/b/fichier.txt`
fn strip_ext(p: &Path) -> PathBuf {
    p.with_extension("")
}

/// Verrouille un dossier avec une clé déjà dérivée + le sel/vérificateur à inscrire.
/// Renvoie le nombre de fichiers chiffrés.
pub fn lock_with_key(
    dir: &Path,
    key: &SessionKey,
    salt_b64: &str,
    verifier_nonce_b64: &str,
    verifier_b64: &str,
) -> Result<usize> {
    if !dir.is_dir() {
        bail!("dossier introuvable : {}", dir.display());
    }
    if is_locked(dir) {
        bail!("déjà verrouillé : {}", dir.display());
    }
    let mut done = 0usize;
    for path in files_in(dir) {
        if path.extension().and_then(|e| e.to_str()) == Some(ENC_EXT) {
            continue;
        }
        let data = fs::read(&path).with_context(|| format!("lecture {}", path.display()))?;
        let blob = crypto::encrypt_blob(key, &data)?;
        let enc = append_ext(&path, ENC_EXT);
        write_atomic(&enc, &blob)?;
        fs::remove_file(&path).with_context(|| format!("suppression {}", path.display()))?;
        done += 1;
    }
    write_marker(
        dir,
        &Marker {
            version: 1,
            salt: salt_b64.to_string(),
            verifier_nonce: verifier_nonce_b64.to_string(),
            verifier: verifier_b64.to_string(),
        },
    )?;
    Ok(done)
}

/// Déverrouille un dossier avec une clé déjà dérivée (valide d'abord le vérificateur).
pub fn unlock_with_key(dir: &Path, key: &SessionKey) -> Result<usize> {
    let marker = read_marker(dir)?.ok_or_else(|| anyhow!("pas verrouillé : {}", dir.display()))?;
    let vnonce = B64.decode(&marker.verifier_nonce).context("nonce invalide")?;
    let vct = B64.decode(&marker.verifier).context("vérificateur invalide")?;
    if !crypto::check_verifier(key, &vnonce, &vct) {
        bail!("mauvais mot de passe");
    }
    let mut done = 0usize;
    for path in files_in(dir) {
        if path.extension().and_then(|e| e.to_str()) != Some(ENC_EXT) {
            continue;
        }
        let blob = fs::read(&path).with_context(|| format!("lecture {}", path.display()))?;
        let data = crypto::decrypt_blob(key, &blob).with_context(|| format!("fichier {}", path.display()))?;
        write_atomic(&strip_ext(&path), &data)?;
        fs::remove_file(&path).with_context(|| format!("suppression {}", path.display()))?;
        done += 1;
    }
    fs::remove_file(dir.join(MARKER)).context("suppression du marqueur")?;
    Ok(done)
}

/// Nombre de fichiers chiffrés présents.
pub fn count_encrypted(dir: &Path) -> usize {
    files_in(dir)
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(ENC_EXT))
        .count()
}

/// Lit le sel d'un dossier verrouillé (base64), si présent.
pub fn salt_of(dir: &Path) -> Result<Option<String>> {
    Ok(read_marker(dir)?.map(|m| m.salt))
}
