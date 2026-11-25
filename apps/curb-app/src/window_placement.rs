use std::time::Duration;

use slint::winit_030::{winit, WinitWindowAccessor};
use slint::{ComponentHandle, PhysicalPosition, PhysicalSize, Timer};

use crate::app::MainWindow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedWindowGeometry {
    pub position: PhysicalPosition,
    pub size: PhysicalSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Computes a centered top-left `(x, y)` for a window of `(win_w, win_h)` inside
/// `monitor`. If the window is larger than the monitor along an axis, pins to
/// `monitor.x`/`monitor.y` so the titlebar stays reachable.
pub fn center_in_rect(monitor: MonitorRect, win_w: u32, win_h: u32) -> (i32, i32) {
    let x = monitor.x + ((monitor.width as i32 - win_w as i32) / 2).max(0);
    let y = monitor.y + ((monitor.height as i32 - win_h as i32) / 2).max(0);
    (x, y)
}

/// Clamps a window's top-left `(x, y)` so the window remains inside `monitor`.
pub fn clamp_to_rect(
    pos: (i32, i32),
    win_size: (u32, u32),
    monitor: MonitorRect,
) -> (i32, i32) {
    let max_x = monitor.x + (monitor.width as i32 - win_size.0 as i32).max(0);
    let max_y = monitor.y + (monitor.height as i32 - win_size.1 as i32).max(0);
    (pos.0.clamp(monitor.x, max_x), pos.1.clamp(monitor.y, max_y))
}

fn is_wayland_session() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var("WAYLAND_DISPLAY")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Captures the window's current physical position and inner size so it can be
/// restored when reopened from the system tray.
pub fn capture_geometry(win: &MainWindow) -> Option<SavedWindowGeometry> {
    if is_wayland_session() {
        return None;
    }
    win.window()
        .with_winit_window(|winit_win| {
            if winit_win.is_minimized().unwrap_or(false) {
                return None;
            }
            let pos = winit_win.outer_position().ok()?;
            let size = winit_win.inner_size();
            if size.width == 0 || size.height == 0 {
                return None;
            }
            Some(SavedWindowGeometry {
                position: PhysicalPosition::new(pos.x, pos.y),
                size: PhysicalSize::new(size.width, size.height),
            })
        })
        .flatten()
}

/// Applies previously saved size & position before `win.show()` so reopening from
/// the tray does not flash at a default OS position.
pub fn prepare_before_show(win: &MainWindow, saved: Option<SavedWindowGeometry>) {
    if is_wayland_session() {
        return;
    }
    if let Some(geo) = saved {
        win.window().set_size(geo.size);
        win.window().set_position(geo.position);
    }
}

/// Centers the window on the primary monitor on first open, or clamps a restored
/// position to stay within a connected monitor. If called before the event loop
/// creates the underlying winit window, defers placement to the first event-loop turn.
pub fn place_after_show(win: &MainWindow, saved: Option<SavedWindowGeometry>) {
    if is_wayland_session() {
        return;
    }
    if apply_winit_placement(win, saved) {
        return;
    }

    let weak = win.as_weak();
    Timer::single_shot(Duration::ZERO, move || {
        if let Some(w) = weak.upgrade() {
            let _ = apply_winit_placement(&w, saved);
        }
    });
}

/// Shows, unminimizes, and focuses an already-open window.
pub fn focus_existing_window(win: &MainWindow) {
    let _ = win.show();
    let _ = win.window().with_winit_window(|winit_win| {
        winit_win.set_minimized(false);
        winit_win.focus_window();
    });
}

fn apply_winit_placement(win: &MainWindow, saved: Option<SavedWindowGeometry>) -> bool {
    if is_wayland_session() {
        return true;
    }
    win.window()
        .with_winit_window(|winit_win| {
            let outer = winit_win.outer_size();
            let win_size = if outer.width > 0 && outer.height > 0 {
                outer
            } else {
                winit_win.inner_size()
            };
            if win_size.width == 0 || win_size.height == 0 {
                return;
            }

            if let Some(geo) = saved {
                let center_x = geo.position.x + (win_size.width as i32) / 2;
                let center_y = geo.position.y + (win_size.height as i32) / 2;
                let monitor = winit_win
                    .available_monitors()
                    .find(|m| {
                        let p = m.position();
                        let s = m.size();
                        center_x >= p.x
                            && center_x < p.x + s.width as i32
                            && center_y >= p.y
                            && center_y < p.y + s.height as i32
                    })
                    .or_else(|| winit_win.primary_monitor())
                    .or_else(|| winit_win.current_monitor());

                if let Some(mon) = monitor {
                    let mp = mon.position();
                    let ms = mon.size();
                    let rect = MonitorRect {
                        x: mp.x,
                        y: mp.y,
                        width: ms.width,
                        height: ms.height,
                    };
                    let (x, y) = clamp_to_rect(
                        (geo.position.x, geo.position.y),
                        (win_size.width, win_size.height),
                        rect,
                    );
                    winit_win.set_outer_position(winit::dpi::PhysicalPosition::new(x, y));
                }
            } else if let Some(mon) = winit_win
                .primary_monitor()
                .or_else(|| winit_win.current_monitor())
            {
                let mp = mon.position();
                let ms = mon.size();
                let rect = MonitorRect {
                    x: mp.x,
                    y: mp.y,
                    width: ms.width,
                    height: ms.height,
                };
                let (x, y) = center_in_rect(rect, win_size.width, win_size.height);
                winit_win.set_outer_position(winit::dpi::PhysicalPosition::new(x, y));
            }
        })
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HD_MONITOR: MonitorRect = MonitorRect {
        x: 0,
        y: 0,
        width: 1920,
        height: 1080,
    };

    #[test]
    fn center_in_rect_standard_monitor() {
        assert_eq!(center_in_rect(HD_MONITOR, 480, 600), (720, 240));
    }

    #[test]
    fn center_in_rect_secondary_monitor_offset() {
        let left_mon = MonitorRect {
            x: -1920,
            y: 0,
            width: 1920,
            height: 1080,
        };
        assert_eq!(center_in_rect(left_mon, 480, 600), (-1200, 240));
    }

    #[test]
    fn center_in_rect_pins_when_window_exceeds_monitor() {
        let small = MonitorRect {
            x: 100,
            y: 50,
            width: 400,
            height: 500,
        };
        assert_eq!(center_in_rect(small, 480, 600), (100, 50));
    }

    #[test]
    fn clamp_to_rect_keeps_in_bounds_position() {
        assert_eq!(clamp_to_rect((300, 200), (480, 600), HD_MONITOR), (300, 200));
    }

    #[test]
    fn clamp_to_rect_pulls_offscreen_window_back() {
        assert_eq!(
            clamp_to_rect((1800, 900), (480, 600), HD_MONITOR),
            (1440, 480)
        );
        assert_eq!(clamp_to_rect((-200, -100), (480, 600), HD_MONITOR), (0, 0));
    }
}
