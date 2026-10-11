//! Catalog of known sensitive locations on Windows.
//!
//! We NEVER read the contents of these folders: we only detect whether they EXIST,
//! to offer to lock them. Each entry lists the executables that own the folder, so the
//! agent does not lock a folder whose app is running.

use std::path::PathBuf;

/// (category, label, base env variable, subpath, owning executables)
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

/// Full table. Add any new location to cover here.
pub const SPECS: &[Spec] = &[
    // ---------------------------------------------------------------- Browsers
    s("Browsers", "Google Chrome", "LOCALAPPDATA", r"Google\Chrome\User Data", &["chrome.exe"]),
    s("Browsers", "Microsoft Edge", "LOCALAPPDATA", r"Microsoft\Edge\User Data", &["msedge.exe"]),
    s("Browsers", "Brave", "LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data", &["brave.exe"]),
    s("Browsers", "Vivaldi", "LOCALAPPDATA", r"Vivaldi\User Data", &["vivaldi.exe"]),
    s("Browsers", "Chromium", "LOCALAPPDATA", r"Chromium\User Data", &["chromium.exe"]),
    s("Browsers", "Yandex", "LOCALAPPDATA", r"Yandex\YandexBrowser\User Data", &["browser.exe"]),
    s("Browsers", "Opera", "APPDATA", r"Opera Software\Opera Stable", &["opera.exe"]),
    s("Browsers", "Opera GX", "APPDATA", r"Opera Software\Opera GX Stable", &["opera.exe"]),
    s("Browsers", "Firefox (profiles)", "APPDATA", r"Mozilla\Firefox\Profiles", &["firefox.exe"]),
    s("Browsers", "Waterfox", "APPDATA", r"Waterfox\Profiles", &["waterfox.exe"]),
    s("Browsers", "Tor Browser", "APPDATA", r"tor-browser", &["firefox.exe", "tor.exe"]),

    // ---------------------------------------------------------------- Messaging
    s("Messaging", "Discord", "APPDATA", r"discord", &["Discord.exe"]),
    s("Messaging", "Discord PTB", "APPDATA", r"discordptb", &["DiscordPTB.exe"]),
    s("Messaging", "Discord Canary", "APPDATA", r"discordcanary", &["DiscordCanary.exe"]),
    s("Messaging", "Telegram", "APPDATA", r"Telegram Desktop\tdata", &["Telegram.exe"]),
    s("Messaging", "Signal", "APPDATA", r"Signal", &["Signal.exe"]),
    s("Messaging", "WhatsApp", "APPDATA", r"WhatsApp", &["WhatsApp.exe"]),
    s("Messaging", "Slack", "APPDATA", r"Slack", &["slack.exe"]),
    s("Messaging", "Element", "APPDATA", r"Element", &["Element.exe"]),
    s("Messaging", "Skype", "APPDATA", r"Microsoft\Skype for Desktop", &["Skype.exe"]),

    // ---------------------------------------------------------------- Games / launchers
    s("Games", "Steam (config)", "PFX86", r"Steam\config", &["steam.exe"]),
    s("Games", "Epic Games", "LOCALAPPDATA", r"EpicGamesLauncher\Saved\Config", &["EpicGamesLauncher.exe"]),
    s("Games", "Riot Games", "LOCALAPPDATA", r"Riot Games", &["RiotClientServices.exe", "LeagueClient.exe"]),
    s("Games", "Battle.net", "APPDATA", r"Battle.net", &["Battle.net.exe"]),
    s("Games", "Blizzard", "LOCALAPPDATA", r"Blizzard Entertainment", &["Battle.net.exe"]),
    s("Games", "EA App / Origin", "APPDATA", r"Origin", &["Origin.exe", "EADesktop.exe"]),
    s("Games", "EA (local)", "LOCALAPPDATA", r"Electronic Arts", &["EADesktop.exe"]),
    s("Games", "Ubisoft Connect", "LOCALAPPDATA", r"Ubisoft Game Launcher", &["upc.exe", "UbisoftConnect.exe"]),
    s("Games", "GOG Galaxy", "PROGRAMDATA", r"GOG.com\Galaxy", &["GalaxyClient.exe"]),
    s("Games", "Rockstar", "LOCALAPPDATA", r"Rockstar Games", &["Launcher.exe", "PlayGTAV.exe"]),
    s("Games", "Minecraft", "APPDATA", r".minecraft", &["javaw.exe", "Minecraft.exe"]),
    s("Games", "Roblox (local)", "LOCALAPPDATA", r"Roblox\LocalStorage", &["RobloxPlayerBeta.exe", "RobloxStudioBeta.exe"]),

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

    // ---------------------------------------------------------------- Password managers
    s("Password managers", "Bitwarden", "APPDATA", r"Bitwarden", &["Bitwarden.exe"]),
    s("Password managers", "1Password", "LOCALAPPDATA", r"1Password", &["1Password.exe"]),
    s("Password managers", "KeePassXC", "APPDATA", r"KeePassXC", &["KeePassXC.exe"]),
    s("Password managers", "NordPass", "APPDATA", r"NordPass", &["NordPass.exe"]),

    // ---------------------------------------------------------------- FTP / network
    s("FTP/Network", "FileZilla", "APPDATA", r"FileZilla", &["filezilla.exe"]),
    s("FTP/Network", "WinSCP", "APPDATA", r"WinSCP.ini", &["WinSCP.exe"]),
    s("FTP/Network", "OpenVPN", "APPDATA", r"OpenVPN Connect", &["openvpnconnect.exe"]),

    // ---------------------------------------------------------------- Development / secrets
    s("Development", "SSH (.ssh)", "USERPROFILE", r".ssh", &[]),
    s("Development", "AWS (.aws)", "USERPROFILE", r".aws", &[]),
    s("Development", "Azure", "USERPROFILE", r".azure", &[]),
    s("Development", "GitHub CLI", "APPDATA", r"GitHub CLI", &[]),
    s("Development", "npm (.npmrc)", "USERPROFILE", r".npmrc", &[]),
    s("Development", "Docker", "USERPROFILE", r".docker", &["Docker Desktop.exe"]),
    s("Development", "Kube (.kube)", "USERPROFILE", r".kube", &[]),
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

/// Walks the catalog and returns the locations that exist and are non-empty.
pub fn detect() -> Vec<Found> {
    let mut out = Vec::new();
    for spec in SPECS {
        let Some(base) = base_dir(spec.base) else { continue };
        let path = base.join(spec.sub);
        if !path.exists() {
            continue;
        }
        // skip empty folders (nothing to protect)
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
