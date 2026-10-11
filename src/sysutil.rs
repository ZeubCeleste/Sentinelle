//! Windows system helpers: running processes, user inactivity.

use std::collections::HashSet;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

/// Returns the set (lowercased) of currently running executables.
pub fn running_processes() -> HashSet<String> {
    let mut set = HashSet::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return set;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                );
                if !name.is_empty() {
                    set.insert(name.to_lowercase());
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    set
}

/// True if at least one of the executables is currently running.
pub fn any_running(procs: &[String], running: &HashSet<String>) -> bool {
    procs.iter().any(|p| running.contains(&p.to_lowercase()))
}

/// Seconds since the user's last keyboard/mouse activity.
pub fn idle_seconds() -> u64 {
    unsafe {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if GetLastInputInfo(&mut info).as_bool() {
            let now = GetTickCount64();
            let last = info.dwTime as u64;
            // GetTickCount64 and dwTime share the same time base (ms since boot)
            now.saturating_sub(last) / 1000
        } else {
            0
        }
    }
}
