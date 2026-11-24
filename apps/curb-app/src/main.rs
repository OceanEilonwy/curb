#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
mod elevate;
mod ipc_client;
mod local_mode;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use slint::ComponentHandle;

use crate::app::{clear_active_controller, create_main_window, CurbTray, MainWindow};
use crate::backend::CurbBackend;

fn main() {
    let demo_mode = std::env::args().any(|a| a == "--demo")
        || std::env::var("CURB_DEMO").map(|v| v == "1").unwrap_or(false);

    let backend = CurbBackend::new(demo_mode);
    backend.maybe_autostart_standard_proxy();

    let theme_dark_pref = Rc::new(Cell::new(true));
    let active_window: Rc<RefCell<Option<(u64, MainWindow)>>> = Rc::new(RefCell::new(None));

    let open_or_focus: Rc<dyn Fn()> = {
        let backend = backend.clone();
        let theme_dark_pref = theme_dark_pref.clone();
        let active_window = active_window.clone();
        Rc::new(move || {
            if let Some((_, existing)) = active_window.borrow().as_ref() {
                let _ = existing.show();
                return;
            }

            let active_for_drop = active_window.clone();
            let on_drop: Rc<dyn Fn()> = Rc::new(move || {
                *active_for_drop.borrow_mut() = None;
            });

            match create_main_window(backend.clone(), theme_dark_pref.clone(), on_drop) {
                Ok((gen_id, win)) => {
                    let _ = win.show();
                    *active_window.borrow_mut() = Some((gen_id, win));
                }
                Err(e) => {
                    eprintln!("Failed to open Curb window: {e}");
                }
            }
        })
    };

    let tray = match CurbTray::new() {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("Warning: system tray unavailable ({e}); running window-only.");
            None
        }
    };

    if let Some(tray) = &tray {
        let open_menu = open_or_focus.clone();
        tray.on_open_requested(move || open_menu());

        let backend_quit = backend.clone();
        let active_quit = active_window.clone();
        tray.on_quit_requested(move || {
            backend_quit.deactivate_proxy();
            if let Some((gen_id, win)) = active_quit.borrow_mut().take() {
                clear_active_controller(gen_id);
                let _ = win.hide();
            }
            let _ = slint::quit_event_loop();
        });

        let _ = tray.show();
    }

    // Show the main window on startup
    open_or_focus();

    if let Err(e) = slint::run_event_loop() {
        eprintln!("Slint event loop error: {e}");
    }

    // Ensure Standard Mode HKCU proxy is always cleaned up on process exit
    backend.deactivate_proxy();
}
