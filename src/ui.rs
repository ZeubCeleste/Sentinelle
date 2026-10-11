//! Minimal graphical UI (no console): a password dialog and message boxes.
//!
//! Lets Sentinelle run without a console window (so nothing shows in the taskbar),
//! while still asking for the master password through a small, visible dialog.

use std::cell::RefCell;
use std::sync::Once;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::*;

thread_local! {
    static EDIT: RefCell<Option<HWND>> = const { RefCell::new(None) };
    static RESULT: RefCell<Option<String>> = const { RefCell::new(None) };
}

static CLASS_REGISTERED: Once = Once::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Shows an information or error message box.
pub fn message(text: &str, error: bool) {
    let t = wide(text);
    let icon = if error { MB_ICONERROR } else { MB_ICONINFORMATION };
    unsafe {
        MessageBoxW(None, PCWSTR(t.as_ptr()), w!("Sentinelle"), MB_OK | icon);
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_COMMAND => {
                let id = (wparam.0 & 0xffff) as i32;
                if id == 1 {
                    // OK
                    EDIT.with(|e| {
                        if let Some(h) = *e.borrow() {
                            let mut buf = [0u16; 512];
                            let n = GetWindowTextW(h, &mut buf);
                            RESULT.with(|r| {
                                *r.borrow_mut() = Some(String::from_utf16_lossy(&buf[..n as usize]));
                            });
                        }
                    });
                    let _ = DestroyWindow(hwnd);
                } else if id == 2 {
                    // Cancel / Esc
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Shows a modal password dialog. Returns the entered password, or None if cancelled.
pub fn password_dialog(prompt: &str) -> Option<String> {
    unsafe {
        let hmod = GetModuleHandleW(None).ok()?;
        let hinst = HINSTANCE(hmod.0);
        let class = w!("SentinellePwdDlg");
        CLASS_REGISTERED.call_once(|| {
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: hinst,
                lpszClassName: class,
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
                hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(16 as *mut core::ffi::c_void), // COLOR_BTNFACE+1
                ..Default::default()
            };
            RegisterClassW(&wc);
        });

        RESULT.with(|r| *r.borrow_mut() = None);
        EDIT.with(|e| *e.borrow_mut() = None);

        let title = wide("Sentinelle");
        let (w, h) = (380, 180);
        let sw = GetSystemMetrics(SM_CXSCREEN);
        let sh = GetSystemMetrics(SM_CYSCREEN);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0x00000080 | 0x00000008), // WS_EX_TOOLWINDOW | WS_EX_TOPMOST
            class,
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            (sw - w) / 2,
            (sh - h) / 2,
            w,
            h,
            None,
            None,
            hinst,
            None,
        )
        .ok()?;

        let prompt_w = wide(prompt);
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            PCWSTR(prompt_w.as_ptr()),
            WS_CHILD | WS_VISIBLE,
            20,
            18,
            340,
            22,
            hwnd,
            None,
            hinst,
            None,
        );
        let edit = CreateWindowExW(
            WINDOW_EX_STYLE(0x00000200), // WS_EX_CLIENTEDGE
            w!("EDIT"),
            w!(""),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(0x0020 | 0x0080), // ES_PASSWORD | ES_AUTOHSCROLL
            20,
            48,
            340,
            26,
            hwnd,
            HMENU(100 as *mut core::ffi::c_void),
            hinst,
            None,
        )
        .ok()?;
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("BUTTON"),
            w!("OK"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(0x0001), // BS_DEFPUSHBUTTON
            150,
            92,
            90,
            30,
            hwnd,
            HMENU(1 as *mut core::ffi::c_void),
            hinst,
            None,
        );

        EDIT.with(|e| *e.borrow_mut() = Some(edit));
        let _ = SetForegroundWindow(hwnd);
        let _ = SetFocus(edit);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if !IsDialogMessageW(hwnd, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        RESULT.with(|r| r.borrow_mut().take())
    }
}
