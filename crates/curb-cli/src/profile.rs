use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use curb_core::presets::PresetHost;
use curb_core::steam::discover_steam_games_with;
use curb_games::profiler::{ProfileSession, ProfileState};
use curb_games::telemetry::TelemetrySampler;
use curb_games::{resolve_watched_dirs, DetectorRegistry, GameTelemetrySnapshot};
use curb_preset_steam::SteamPresetPlugin;

pub struct ProfileArgs {
    pub game: String,
    pub no_launch: bool,
    pub output: Option<PathBuf>,
    pub pre_guard_secs: f64,
    pub post_guard_secs: f64,
}

pub fn run_profile(args: ProfileArgs, host: &dyn PresetHost) {
    let mut registry = DetectorRegistry::default();
    let Some((app_id, resolved_name)) = registry.resolve_app_id(&args.game) else {
        eprintln!(
            "Could not resolve game '{}'. Pass a Steam AppID (e.g. 976730, 4178190) or alias ('halo', 'astro').",
            args.game
        );
        std::process::exit(1);
    };

    let steam_root = SteamPresetPlugin::find_steam_root(host);
    let discovered = steam_root
        .as_deref()
        .and_then(|r| {
            discover_steam_games_with(
                r,
                |p| host.is_executable(p),
                |p| host.peek_binary(p),
            )
            .ok()
        })
        .and_then(|games| games.into_iter().find(|g| g.app_id == app_id));

    let game_name = discovered
        .as_ref()
        .map(|g| g.name.clone())
        .unwrap_or(resolved_name);
    let install_dir = discovered.as_ref().map(|g| g.install_dir.clone());

    let mut exe_hints_owned: Vec<String> = Vec::new();
    if let Some(info) = registry.info(app_id) {
        for &h in info.exe_hints {
            exe_hints_owned.push(h.to_string());
        }
    }
    if let Some(disc) = &discovered {
        if !exe_hints_owned
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&disc.exe_name))
        {
            exe_hints_owned.push(disc.exe_name.clone());
        }
    }

    let watched_rel = registry
        .get_mut(app_id)
        .map(|d| d.watched_relative_paths())
        .unwrap_or(&[]);
    let watched_dirs = resolve_watched_dirs(app_id, steam_root.as_deref(), watched_rel);

    println!("============================================================");
    println!(" Curb Interactive Game Profiler");
    println!("============================================================");
    println!(" Game         : {game_name} (AppID {app_id})");
    if let Some(dir) = &install_dir {
        println!(" Install Dir  : {}", dir.display());
    } else {
        println!(" Install Dir  : (not auto-discovered; matching by exe hints)");
    }
    if !exe_hints_owned.is_empty() {
        println!(" Exe Hints    : {}", exe_hints_owned.join(", "));
    }
    if !watched_dirs.is_empty() {
        println!(
            " Watched Dirs : {}",
            watched_dirs
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        " Delay Guards : -{:.0}s before transitions, +{:.0}s after transitions",
        args.pre_guard_secs, args.post_guard_secs
    );
    println!("------------------------------------------------------------");

    if !args.no_launch {
        println!("Launching via Steam (steam://rungameid/{app_id})...");
        if let Err(e) = launch_steam_game(app_id) {
            eprintln!("Warning: could not auto-launch Steam game: {e}");
            println!("Please launch {game_name} manually — profiling is already recording.");
        }
    } else {
        println!("Skipping auto-launch (--no-launch).");
    }

    println!();
    println!("Assuming initial state: [MENU]");
    println!("As you play, alt-tab back here and type the current state:");
    println!("  menu     (or m)  - Main menu / title screen");
    println!("  lobby    (or l)  - Matchmaking / pre-game or post-game lobby");
    println!("  playing  (or p)  - Actively in a live match");
    println!("  status   (or s)  - Print live telemetry snapshot right now");
    println!("  note <text>      - Attach a timestamped note");
    println!("  done     (or q)  - Finish, analyze (accounting for alt-tab delay), and save JSON");
    println!();

    let mut session = ProfileSession::new(app_id, game_name.clone());
    session.pre_transition_guard_secs = args.pre_guard_secs;
    session.post_transition_guard_secs = args.post_guard_secs;

    let session_arc = Arc::new(Mutex::new(session));
    let latest_snap: Arc<Mutex<Option<GameTelemetrySnapshot>>> = Arc::new(Mutex::new(None));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let started_at = Instant::now();

    let bg_session = session_arc.clone();
    let bg_latest = latest_snap.clone();
    let bg_stop = stop_flag.clone();
    let bg_install_dir = install_dir.clone();
    let bg_watched_dirs = watched_dirs.clone();
    let bg_hints = exe_hints_owned.clone();

    let sampler_thread = std::thread::spawn(move || {
        let mut sampler = TelemetrySampler::new();
        let hint_refs: Vec<&str> = bg_hints.iter().map(|s| s.as_str()).collect();
        let mut announced_found = false;

        while !bg_stop.load(Ordering::Relaxed) {
            let snap = sampler.sample(
                app_id,
                bg_install_dir.as_deref(),
                &hint_refs,
                &bg_watched_dirs,
            );
            if !announced_found && !snap.pids.is_empty() {
                announced_found = true;
                println!(
                    "\n[detected game process: PID(s) {:?}]",
                    snap.pids
                );
                print!("curb-profile [menu]> ");
                let _ = io::stdout().flush();
            }
            let elapsed = started_at.elapsed().as_secs_f64();
            {
                let mut latest = bg_latest.lock().unwrap();
                *latest = Some(snap.clone());
            }
            {
                let mut sess = bg_session.lock().unwrap();
                sess.add_sample(elapsed, snap);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    let mut current_state = ProfileState::Menu;
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    loop {
        print!("curb-profile [{}]> ", current_state.as_str());
        let _ = io::stdout().flush();

        let Some(Ok(line)) = lines.next() else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        if matches!(lower.as_str(), "done" | "quit" | "q" | "exit") {
            break;
        }

        if matches!(lower.as_str(), "status" | "s") {
            let elapsed = started_at.elapsed().as_secs_f64();
            let snap_opt = latest_snap.lock().unwrap().clone();
            match snap_opt {
                Some(snap) => {
                    println!(
                        "  t={elapsed:.1}s | state={} | pids={:?} | udp_sockets={} | tcp_conns={} | io={:.1} KB/s | files={}",
                        current_state.as_str(),
                        snap.pids,
                        snap.non_loopback_udp_count(),
                        snap.tcp_endpoints.len(),
                        snap.total_bytes_per_sec() as f64 / 1024.0,
                        snap.file_activities.len()
                    );
                }
                None => println!("  No telemetry sample collected yet..."),
            }
            continue;
        }

        if let Some(note_text) = trimmed.strip_prefix("note ").or_else(|| trimmed.strip_prefix("NOTE ")) {
            let elapsed = started_at.elapsed().as_secs_f64();
            session_arc
                .lock()
                .unwrap()
                .add_marker(elapsed, current_state, Some(note_text.trim().to_string()));
            println!("  Recorded note at t={elapsed:.1}s.");
            continue;
        }

        if let Some(new_state) = ProfileState::parse(trimmed) {
            let elapsed = started_at.elapsed().as_secs_f64();
            current_state = new_state;
            session_arc
                .lock()
                .unwrap()
                .add_marker(elapsed, new_state, None);
            println!(
                "  Marked state -> [{}] at t={elapsed:.1}s (will trim -{:.0}s/+{:.0}s around transition).",
                new_state.as_str().to_uppercase(),
                args.pre_guard_secs,
                args.post_guard_secs
            );
            continue;
        }

        println!("  Unknown command '{trimmed}'. Use: menu | lobby | playing | status | note <text> | done");
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = sampler_thread.join();

    let final_session = session_arc.lock().unwrap().clone();
    let analysis = final_session.analyze();

    println!();
    println!("============================================================");
    println!(" Calibration Summary: {} (AppID {})", analysis.game_name, analysis.app_id);
    println!(
        " Total samples: {} | Trimmed transition samples: {}",
        analysis.total_samples, analysis.trimmed_transition_samples
    );
    println!("------------------------------------------------------------");
    println!(
        " {:<10} {:>8} {:>10} {:>10} {:>12} {:>12}",
        "State", "Samples", "Med UDP", "Med TCP", "Med KB/s", "P90 KB/s"
    );
    for (state, stats) in &analysis.state_stats {
        println!(
            " {:<10} {:>8} {:>10} {:>10} {:>12.1} {:>12.1}",
            state.as_str(),
            stats.sample_count,
            stats.median_udp_sockets,
            stats.median_tcp_conns,
            stats.median_bytes_per_sec as f64 / 1024.0,
            stats.p90_bytes_per_sec as f64 / 1024.0
        );
    }
    if let Some(rec) = &analysis.recommendation {
        println!("------------------------------------------------------------");
        println!(" Suggested min_udp_sockets   : {}", rec.suggested_min_udp_sockets);
        println!(
            " Suggested min_bytes_per_sec : {} ({:.1} KB/s)",
            rec.suggested_min_bytes_per_sec,
            rec.suggested_min_bytes_per_sec as f64 / 1024.0
        );
        println!(" Assessment: {}", rec.notes);
    }
    println!("============================================================");

    let out_path = args.output.unwrap_or_else(|| {
        let ts = Utc::now().format("%Y%m%d-%H%M%S");
        PathBuf::from(format!("curb-profile-{app_id}-{ts}.json"))
    });

    let report = serde_json::json!({
        "analysis": analysis,
        "session": final_session,
    });
    match write_report(&out_path, &report) {
        Ok(()) => println!("Saved full calibration profile to: {}", out_path.display()),
        Err(e) => eprintln!("Failed to save profile JSON: {e}"),
    }
}

fn write_report(path: &Path, value: &serde_json::Value) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    std::fs::write(path, bytes)
}

fn launch_steam_game(app_id: u32) -> io::Result<()> {
    let url = format!("steam://rungameid/{app_id}");
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn()?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open").arg(&url).spawn()?;
        Ok(())
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = url;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "auto-launch not supported on this OS",
        ))
    }
}
