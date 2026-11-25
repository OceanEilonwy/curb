#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backend;
mod elevate;
mod ipc_client;
mod local_mode;
mod remote;
mod single_instance;
mod window_placement;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use slint::ComponentHandle;

use crate::app::{clear_active_controller, create_main_window, CurbTray, MainWindow};
use crate::backend::CurbBackend;
use crate::window_placement::{
    focus_existing_window, place_after_show, prepare_before_show, SavedWindowGeometry,
};

fn main() {
    let demo_mode = std::env::args().any(|a| a == "--demo")
        || std::env::var("CURB_DEMO").map(|v| v == "1").unwrap_or(false);
    let no_tray_flag = std::env::args().any(|a| a == "--no-tray");

    // On Linux (especially Sway, Mango, dwl), re-running `curb-app` from a keybind
    // or launcher focuses/reopens the existing window instead of spawning a duplicate.
    if !demo_mode && single_instance::try_activate_existing() {
        return;
    }

    let backend = CurbBackend::new(demo_mode);
    backend.maybe_autostart_standard_proxy();

    let theme_dark_pref = Rc::new(Cell::new(true));
    let last_geometry: Rc<RefCell<Option<SavedWindowGeometry>>> = Rc::new(RefCell::new(None));
    let active_window: Rc<RefCell<Option<(u64, MainWindow)>>> = Rc::new(RefCell::new(None));

    let tray_host_available = if no_tray_flag {
        false
    } else {
        #[cfg(target_os = "linux")]
        {
            curb_xdg::has_status_notifier_watcher()
        }
        #[cfg(not(target_os = "linux"))]
        {
            true
        }
    };

    let tray = if tray_host_available {
        match CurbTray::new() {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("Warning: system tray unavailable ({e}); running window-only.");
                None
            }
        }
    } else {
        None
    };

    // When no system tray host is present (e.g. dwl, Mango, bare Sway, or `--no-tray`),
    // closing the window quits `curb-app` cleanly instead of hiding into an unreachable tray.
    let close_quits_app = tray.is_none();

    let open_or_focus: Rc<dyn Fn()> = {
        let backend = backend.clone();
        let theme_dark_pref = theme_dark_pref.clone();
        let last_geometry = last_geometry.clone();
        let active_window = active_window.clone();
        Rc::new(move || {
            if let Some((_, existing)) = active_window.borrow().as_ref() {
                focus_existing_window(existing);
                return;
            }

            let active_for_drop = active_window.clone();
            let on_drop: Rc<dyn Fn()> = Rc::new(move || {
                *active_for_drop.borrow_mut() = None;
            });

            let saved = *last_geometry.borrow();
            match create_main_window(
                backend.clone(),
                theme_dark_pref.clone(),
                last_geometry.clone(),
                close_quits_app,
                on_drop,
            ) {
                Ok((gen_id, win)) => {
                    prepare_before_show(&win, saved);
                    let _ = win.show();
                    place_after_show(&win, saved);
                    *active_window.borrow_mut() = Some((gen_id, win));
                }
                Err(e) => {
                    eprintln!("Failed to open Curb window: {e}");
                }
            }
        })
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

    let _single_instance_guard = if !demo_mode {
        // Trigger `open_or_focus` via a thread-safe wakeup channel bridged into Slint's loop.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let open_on_activate = open_or_focus.clone();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(150),
            move || {
                let mut should_open = false;
                while rx.try_recv().is_ok() {
                    should_open = true;
                }
                if should_open {
                    open_on_activate();
                }
            },
        );
        let guard = single_instance::start_listener(move || {
            let _ = tx.send(());
        });
        Some((guard, timer))
    } else {
        None
    };

    // Show the main window on startup
    open_or_focus();

    if let Err(e) = slint::run_event_loop() {
        eprintln!("Slint event loop error: {e}");
    }

    // Ensure Standard Mode proxy is always cleaned up on process exit
    backend.deactivate_proxy();
}
