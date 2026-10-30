//! Fixed, build-time configuration for a dedicated unattended client.
//!
//! A build with these values is meant to be deployed on the controlled side only: it
//! registers with [`RENDEZVOUS_SERVER`] under the id [`PEER_ID`], accepts the password
//! [`PEER_PASSWORD`] without asking its local user to confirm, and, when launched with
//! no arguments, runs without any UI at all.
//!
//! The id, the password and the keypair seed are generated once per build (see
//! `gen_peer_identity` in `build.rs`), so every build is a different peer. On the
//! controlling side (any other RustDesk client), configure it with the id and password
//! printed by `-show` / `--show`.

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

/// Id of the controlled peer, generated once per build.
pub const PEER_ID: &str = env!("RD_PEER_ID");

/// Password accepted by the controlled peer, generated once per build.
pub const PEER_PASSWORD: &str = env!("RD_PEER_PASSWORD");

/// Rendezvous (hbbs) server of the self-hosted rustdesk-server this build registers
/// with and connects through. Use a `host` or `host:21116` form. Edit this to match the
/// deployment.
pub const RENDEZVOUS_SERVER: &str = "192.168.8.199";

/// Key of the self-hosted hbbs, when it is started with `-k`. Leave empty when the
/// server runs without a key.
pub const RENDEZVOUS_KEY: &str = "YTiykQE+KSgL963pwsgA2ByoHUMExjSUm45pLqG+EY4=";

/// Seed of this build's Ed25519 identity, generated once per build (hex, 32 bytes).
///
/// RustDesk otherwise generates a random keypair whenever its stored one is missing, and
/// the rendezvous server answers a changed public key for an already registered id with
/// `UUID_MISMATCH`, which upstream resolves by abandoning the id. A restored machine
/// snapshot wipes the stored config and therefore triggers exactly that, so the identity
/// is baked in instead: every copy, every launch and every wiped config present the same
/// peer key.
const PEER_SEED: &str = env!("RD_PEER_SEED");

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

/// Whether another process of this build already owns the main IPC endpoint.
///
/// The endpoint is a named pipe on Windows and a unix socket elsewhere; both disappear
/// with the owning process, so the probe only reports a live instance. After a crash or a
/// reboot nothing answers and a fresh launch proceeds.
pub fn instance_already_running() -> bool {
    let path = Config::ipc_path("");
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_ok()
    }
    #[cfg(not(windows))]
    {
        std::os::unix::net::UnixStream::connect(path).is_ok()
    }
}

/// Writes the build's identity into the config file RustDesk reads its keypair from.
///
/// [`Config::get_key_pair`] returns a freshly generated random keypair whenever the stored
/// one is missing, and hbbs refuses a new public key for an already registered id with
/// `UUID_MISMATCH`. Since the id must stay fixed for this build's controller, the key must
/// stay fixed too. Runs before the first `Config::get_key_pair` (the server registers its
/// key at startup), so the injected value is the one that goes out.
pub fn ensure_fixed_keypair() {
    use hbb_common::{
        config::{store_path, Config},
        log, toml,
    };

    let Some((sk, pk)) = peer_keypair() else {
        log::error!("Build-time keypair seed is invalid; keeping the generated keypair");
        return;
    };
    let path = Config::file();
    let mut value = match std::fs::read_to_string(&path) {
        Ok(text) => match toml::from_str::<toml::Value>(&text) {
            Ok(value) => value,
            Err(err) => {
                // Never rewrite a config this build cannot read: doing so would drop the
                // stored id and password of the deployment.
                log::error!(
                    "Failed to parse {}: {}; keeping the generated keypair",
                    path.display(), err
                );
                return;
            }
        },
        Err(_) => toml::Value::Table(Default::default()),
    };
    let key_pair = toml::Value::Array(vec![byte_array(&sk), byte_array(&pk)]);
    let Some(table) = value.as_table_mut() else {
        log::error!(
            "{} is not a TOML table; keeping the generated keypair",
            path.display()
        );
        return;
    };
    if table.get("key_pair") == Some(&key_pair) {
        return;
    }
    table.insert("key_pair".to_owned(), key_pair);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(err) = store_path(path.clone(), value) {
        log::error!(
            "Failed to store the fixed keypair in {}: {}",
            path.display(), err
        );
    }
}

/// Derives the build's Ed25519 keypair from [`PEER_SEED`], as `(secret key, public key)`.
fn peer_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
    use hbb_common::sodiumoxide::crypto::sign;

    let mut seed = [0u8; sign::SEEDBYTES];
    if PEER_SEED.len() != seed.len() * 2 {
        return None;
    }
    for (byte, chunk) in seed.iter_mut().zip(PEER_SEED.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    let (pk, sk) = sign::keypair_from_seed(&sign::Seed(seed));
    Some((sk.0.to_vec(), pk.0.to_vec()))
}

fn byte_array(bytes: &[u8]) -> hbb_common::toml::Value {
    hbb_common::toml::Value::Array(
        bytes
            .iter()
            .map(|b| hbb_common::toml::Value::Integer(*b as i64))
            .collect(),
    )
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

/// Prints this build's id and password, for `-show` / `--show`.
///
/// This is all `-show` does: no config is written and neither a server nor a UI starts, so
/// a deployment can read its credentials off the controlled machine once, before the real
/// launch.
pub fn show_credentials() {
    #[cfg(windows)]
    if !crate::platform::windows::attach_console() {
        crate::platform::windows::message_box(&format!(
            "ID: {}\nPassword: {}",
            PEER_ID, PEER_PASSWORD
        ));
        return;
    }
    println!("ID: {}", PEER_ID);
    println!("Password: {}", PEER_PASSWORD);
}
