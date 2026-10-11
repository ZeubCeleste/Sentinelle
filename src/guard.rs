//! Background agent: locks when you step away, unlocks when you return.
//!
//! Lock triggers: workstation locked (Win+L), inactivity, shutdown/logoff.
//! When locking, it does NOT touch folders whose owning app is still running (that would
//! corrupt their files). The key stays in memory for the session so it can auto-unlock
//! when you return.

use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use windows::core::w;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW, TranslateMessage,
    HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
};

use crate::config::Config;
use crate::crypto::{self, SessionKey};
use crate::{logln, vault};

const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const WM_QUERYENDSESSION: u32 = 0x0011;
const WM_ENDSESSION: u32 = 0x0016;
const WTS_SESSION_LOCK: u32 = 0x7;
const WTS_SESSION_UNLOCK: u32 = 0x8;
const NOTIFY_FOR_THIS_SESSION: u32 = 0;

struct GuardState {
    cfg: Config,
    password: String,
    locked: bool,
}

static STATE: OnceLock<Mutex<GuardState>> = OnceLock::new();

fn derive(cfg: &Config, password: &str) -> Result<SessionKey> {
    let salt = B64.decode(&cfg.salt)?;
    crypto::derive_key(password.as_bytes(), &salt)
}

/// Locks every eligible folder (owning app closed, not already locked).
fn lock_all() {
    let Some(m) = STATE.get() else { return };
    let mut st = m.lock().unwrap();
    if st.locked {
        return;
    }
    let key = match derive(&st.cfg, &st.password) {
        Ok(k) => k,
        Err(e) => {
            logln(&format!("cannot lock (key): {e}"));
            return;
        }
    };
    let running = crate::sysutil::running_processes();
    let (vnonce, v) = (st.cfg.verifier_nonce.clone(), st.cfg.verifier.clone());
    let salt = st.cfg.salt.clone();
    let mut n = 0usize;
    let mut skipped = 0usize;
    // borrow the fields separately to avoid borrow-checker issues
    let folders: Vec<(String, Vec<String>)> =
        st.cfg.folders.iter().map(|f| (f.path.clone(), f.processes.clone())).collect();
    for (path, procs) in &folders {
        let dir = Path::new(path);
        if !dir.is_dir() || vault::is_locked(dir) {
            continue;
        }
        if crate::sysutil::any_running(procs, &running) {
            skipped += 1;
            continue;
        }
        match vault::lock_with_key(dir, &key, &salt, &vnonce, &v) {
            Ok(c) => {
                n += 1;
                logln(&format!("locked {} ({} files)", path, c));
            }
            Err(e) => logln(&format!("lock failed {}: {e}", path)),
        }
    }
    st.locked = true;
    logln(&format!("--- auto-lock: {} folder(s), {} skipped (app open) ---", n, skipped));
}

/// Unlocks every locked folder.
fn unlock_all() {
    let Some(m) = STATE.get() else { return };
    let mut st = m.lock().unwrap();
    let key = match derive(&st.cfg, &st.password) {
        Ok(k) => k,
        Err(e) => {
            logln(&format!("cannot unlock (key): {e}"));
            return;
        }
    };
    let folders: Vec<String> = st.cfg.folders.iter().map(|f| f.path.clone()).collect();
    let mut n = 0usize;
    for path in &folders {
        let dir = Path::new(path);
        if !vault::is_locked(dir) {
            continue;
        }
        match vault::unlock_with_key(dir, &key) {
            Ok(c) => {
                n += 1;
                logln(&format!("unlocked {} ({} files)", path, c));
            }
            Err(e) => logln(&format!("unlock failed {}: {e}", path)),
        }
    }
    st.locked = false;
    logln(&format!("--- auto-unlock: {} folder(s) ---", n));
}

fn setting(f: impl Fn(&Config) -> bool) -> bool {
    STATE.get().map(|m| f(&m.lock().unwrap().cfg)).unwrap_or(false)
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_WTSSESSION_CHANGE => {
            match wparam.0 as u32 {
                WTS_SESSION_LOCK => {
                    if setting(|c| c.lock_on_session_lock) {
                        logln("event: workstation locked (Win+L)");
                        lock_all();
                    }
                }
                WTS_SESSION_UNLOCK => {
                    if setting(|c| c.auto_unlock_on_resume) {
                        logln("event: user returned");
                        unlock_all();
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_QUERYENDSESSION => {
            if setting(|c| c.lock_on_shutdown) {
                logln("event: shutdown / logoff");
                lock_all();
            }
            LRESULT(1) // allow the shutdown
        }
        WM_ENDSESSION => {
            if setting(|c| c.lock_on_shutdown) {
                lock_all();
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Runs the agent (blocking). `password` has already been validated.
pub fn run(cfg: Config, password: String) -> Result<()> {
    // validate the key first
    {
        let key = derive(&cfg, &password)?;
        let vnonce = B64.decode(&cfg.verifier_nonce)?;
        let v = B64.decode(&cfg.verifier)?;
        if !crypto::check_verifier(&key, &vnonce, &v) {
            bail!("wrong password");
        }
    }

    let idle_minutes = cfg.idle_minutes;
    let lock_on_idle = cfg.lock_on_idle;
    STATE
        .set(Mutex::new(GuardState { cfg, password, locked: false }))
        .map_err(|_| anyhow::anyhow!("agent already initialized"))?;

    logln("=== Sentinelle started ===");
    // at session start, unlock anything that was left locked
    unlock_all();

    // watch inactivity in a separate thread
    if lock_on_idle {
        std::thread::spawn(move || {
            let threshold = idle_minutes.saturating_mul(60).max(60);
            loop {
                std::thread::sleep(Duration::from_secs(15));
                let already = STATE.get().map(|m| m.lock().unwrap().locked).unwrap_or(true);
                if !already && crate::sysutil::idle_seconds() >= threshold {
                    logln(&format!("inactivity >= {} min", idle_minutes));
                    lock_all();
                }
            }
        });
    }

    // message-only window + session notifications
    unsafe {
        let hmod = GetModuleHandleW(None)?;
        let hinst = HINSTANCE(hmod.0);
        let class = w!("SentinelleGuardWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("Sentinelle"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            None,
            hinst,
            None,
        )?;
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)?;

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let _ = WTSUnRegisterSessionNotification(hwnd);
    }
    Ok(())
}
