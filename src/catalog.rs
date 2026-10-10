//! Catalogue des emplacements sensibles connus sous Windows.
//!
//! On ne lit JAMAIS le contenu de ces dossiers : on détecte seulement s'ils EXISTENT,
//! pour proposer de les verrouiller. Chaque entrée indique les exécutables qui possèdent
//! le dossier, afin que l'agent ne verrouille pas un dossier dont l'appli tourne.

use std::path::PathBuf;

/// (catégorie, libellé, variable d'env de base, sous-chemin, exécutables propriétaires)
pub struct Spec {
    pub category: &'static str,
    pub label: &'static str,
    pub base: &'static str, // USERPROFILE | APPDATA | LOCALAPPDATA | PROGRAMDATA | PF | PFX86
    pub sub: &'static str,
    pub processes: &'static [&'static str],
}

pub struct Found {
    pub path: PathBuf,
    pub category: String,
    pub label: String,
    pub processes: Vec<String>,
}

const fn s(category: &'static str, label: &'static str, base: &'static str, sub: &'static str, processes: &'static [&'static str]) -> Spec {
    Spec { category, label, base, sub, processes }
}

/// Table complète. Ajoute ici tout nouvel emplacement à couvrir.
pub const SPECS: &[Spec] = &[
    // ---------------------------------------------------------------- Navigateurs
    s("Navigateurs", "Google Chrome", "LOCALAPPDATA", r"Google\Chrome\User Data", &["chrome.exe"]),
    s("Navigateurs", "Microsoft Edge", "LOCALAPPDATA", r"Microsoft\Edge\User Data", &["msedge.exe"]),
    s("Navigateurs", "Brave", "LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data", &["brave.exe"]),
    s("Navigateurs", "Vivaldi", "LOCALAPPDATA", r"Vivaldi\User Data", &["vivaldi.exe"]),
    s("Navigateurs", "Chromium", "LOCALAPPDATA", r"Chromium\User Data", &["chromium.exe"]),
    s("Navigateurs", "Yandex", "LOCALAPPDATA", r"Yandex\YandexBrowser\User Data", &["browser.exe"]),
    s("Navigateurs", "Opera", "APPDATA", r"Opera Software\Opera Stable", &["opera.exe"]),
    s("Navigateurs", "Opera GX", "APPDATA", r"Opera Software\Opera GX Stable", &["opera.exe"]),
    s("Navigateurs", "Firefox (profils)", "APPDATA", r"Mozilla\Firefox\Profiles", &["firefox.exe"]),
    s("Navigateurs", "Waterfox", "APPDATA", r"Waterfox\Profiles", &["waterfox.exe"]),
    s("Navigateurs", "Tor Browser", "APPDATA", r"tor-browser", &["firefox.exe", "tor.exe"]),

    // ---------------------------------------------------------------- Messageries
    s("Messageries", "Discord", "APPDATA", r"discord", &["Discord.exe"]),
    s("Messageries", "Discord PTB", "APPDATA", r"discordptb", &["DiscordPTB.exe"]),
    s("Messageries", "Discord Canary", "APPDATA", r"discordcanary", &["DiscordCanary.exe"]),
    s("Messageries", "Telegram", "APPDATA", r"Telegram Desktop\tdata", &["Telegram.exe"]),
    s("Messageries", "Signal", "APPDATA", r"Signal", &["Signal.exe"]),
    s("Messageries", "WhatsApp", "APPDATA", r"WhatsApp", &["WhatsApp.exe"]),
    s("Messageries", "Slack", "APPDATA", r"Slack", &["slack.exe"]),
    s("Messageries", "Element", "APPDATA", r"Element", &["Element.exe"]),
    s("Messageries", "Skype", "APPDATA", r"Microsoft\Skype for Desktop", &["Skype.exe"]),

    // ---------------------------------------------------------------- Jeux / launchers
    s("Jeux", "Steam (config)", "PFX86", r"Steam\config", &["steam.exe"]),
    s("Jeux", "Epic Games", "LOCALAPPDATA", r"EpicGamesLauncher\Saved\Config", &["EpicGamesLauncher.exe"]),
    s("Jeux", "Riot Games", "LOCALAPPDATA", r"Riot Games", &["RiotClientServices.exe", "LeagueClient.exe"]),
    s("Jeux", "Battle.net", "APPDATA", r"Battle.net", &["Battle.net.exe"]),
    s("Jeux", "Blizzard", "LOCALAPPDATA", r"Blizzard Entertainment", &["Battle.net.exe"]),
    s("Jeux", "EA App / Origin", "APPDATA", r"Origin", &["Origin.exe", "EADesktop.exe"]),
    s("Jeux", "EA (local)", "LOCALAPPDATA", r"Electronic Arts", &["EADesktop.exe"]),
    s("Jeux", "Ubisoft Connect", "LOCALAPPDATA", r"Ubisoft Game Launcher", &["upc.exe", "UbisoftConnect.exe"]),
    s("Jeux", "GOG Galaxy", "PROGRAMDATA", r"GOG.com\Galaxy", &["GalaxyClient.exe"]),
    s("Jeux", "Rockstar", "LOCALAPPDATA", r"Rockstar Games", &["Launcher.exe", "PlayGTAV.exe"]),
    s("Jeux", "Minecraft", "APPDATA", r".minecraft", &["javaw.exe", "Minecraft.exe"]),
    s("Jeux", "Roblox (local)", "LOCALAPPDATA", r"Roblox\LocalStorage", &["RobloxPlayerBeta.exe", "RobloxStudioBeta.exe"]),

    // ---------------------------------------------------------------- Crypto
    s("Crypto", "Exodus", "APPDATA", r"Exodus", &["Exodus.exe"]),
    s("Crypto", "Electrum", "APPDATA", r"Electrum\wallets", &["electrum.exe"]),
    s("Crypto", "Atomic Wallet", "APPDATA", r"atomic", &["Atomic Wallet.exe"]),
    s("Crypto", "Ledger Live", "APPDATA", r"Ledger Live", &["Ledger Live.exe"]),
    s("Crypto", "Bitcoin Core", "APPDATA", r"Bitcoin", &["bitcoin-qt.exe"]),
    s("Crypto", "Litecoin", "APPDATA", r"Litecoin", &["litecoin-qt.exe"]),
    s("Crypto", "Monero", "APPDATA", r"monero-project", &["monero-wallet-gui.exe"]),
    s("Crypto", "Wasabi", "APPDATA", r"WalletWasabi", &["wassabee.exe"]),
    s("Crypto", "Coinomi", "LOCALAPPDATA", r"Coinomi\Coinomi\wallets", &["Coinomi.exe"]),

    // ---------------------------------------------------------------- Cloud / Google
    s("Cloud", "Google Drive", "LOCALAPPDATA", r"Google\DriveFS", &["GoogleDriveFS.exe"]),
    s("Cloud", "Google (gcloud)", "APPDATA", r"gcloud", &[]),
    s("Cloud", "Dropbox", "APPDATA", r"Dropbox", &["Dropbox.exe"]),
    s("Cloud", "Mega", "LOCALAPPDATA", r"Mega Limited\MEGAsync", &["MEGAsync.exe"]),
    s("Cloud", "pCloud", "APPDATA", r"pCloud", &["pCloud.exe"]),

    // ---------------------------------------------------------------- Gestionnaires de mots de passe
    s("Mots de passe", "Bitwarden", "APPDATA", r"Bitwarden", &["Bitwarden.exe"]),
    s("Mots de passe", "1Password", "LOCALAPPDATA", r"1Password", &["1Password.exe"]),
    s("Mots de passe", "KeePassXC", "APPDATA", r"KeePassXC", &["KeePassXC.exe"]),
    s("Mots de passe", "NordPass", "APPDATA", r"NordPass", &["NordPass.exe"]),

    // ---------------------------------------------------------------- FTP / réseau
    s("FTP/Réseau", "FileZilla", "APPDATA", r"FileZilla", &["filezilla.exe"]),
    s("FTP/Réseau", "WinSCP", "APPDATA", r"WinSCP.ini", &["WinSCP.exe"]),
    s("FTP/Réseau", "OpenVPN", "APPDATA", r"OpenVPN Connect", &["openvpnconnect.exe"]),

    // ---------------------------------------------------------------- Dév / secrets
    s("Développement", "SSH (.ssh)", "USERPROFILE", r".ssh", &[]),
    s("Développement", "AWS (.aws)", "USERPROFILE", r".aws", &[]),
    s("Développement", "Azure", "USERPROFILE", r".azure", &[]),
    s("Développement", "GitHub CLI", "APPDATA", r"GitHub CLI", &[]),
    s("Développement", "npm (.npmrc)", "USERPROFILE", r".npmrc", &[]),
    s("Développement", "Docker", "USERPROFILE", r".docker", &["Docker Desktop.exe"]),
    s("Développement", "Kube (.kube)", "USERPROFILE", r".kube", &[]),
];

fn base_dir(base: &str) -> Option<PathBuf> {
    let var = match base {
        "USERPROFILE" => "USERPROFILE",
        "APPDATA" => "APPDATA",
        "LOCALAPPDATA" => "LOCALAPPDATA",
        "PROGRAMDATA" => "PROGRAMDATA",
        "PF" => "ProgramFiles",
        "PFX86" => "ProgramFiles(x86)",
        _ => return None,
    };
    std::env::var(var).ok().map(PathBuf::from)
}

/// Parcourt le catalogue et renvoie les emplacements présents et non vides.
pub fn detect() -> Vec<Found> {
    let mut out = Vec::new();
    for spec in SPECS {
        let Some(base) = base_dir(spec.base) else { continue };
        let path = base.join(spec.sub);
        if !path.exists() {
            continue;
        }
        // on ignore les dossiers vides (rien à protéger)
        if path.is_dir() {
            let empty = std::fs::read_dir(&path).map(|mut d| d.next().is_none()).unwrap_or(true);
            if empty {
                continue;
            }
        }
        out.push(Found {
            path,
            category: spec.category.to_string(),
            label: spec.label.to_string(),
            processes: spec.processes.iter().map(|p| p.to_string()).collect(),
        });
    }
    out
}
