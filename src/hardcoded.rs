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

use hbb_common::config::Config;
use std::sync::atomic::{AtomicBool, Ordering};

/// Fixed id of the controlled peer.
pub const PEER_ID: &str = "888888888";

/// Fixed password accepted by the controlled peer.
pub const PEER_PASSWORD: &str = "RustDesk-888888";

/// Rendezvous (hbbs) server of the self-hosted rustdesk-server this build registers
/// with and connects through. Use a `host` or `host:21116` form. Edit this to match the
/// deployment.
pub const RENDEZVOUS_SERVER: &str = "rd.example.com";

/// Key of the self-hosted hbbs, when it is started with `-k`. Leave empty when the
/// server runs without a key.
pub const RENDEZVOUS_KEY: &str = "";

static HEADLESS: AtomicBool = AtomicBool::new(false);

/// Applies the fixed server and id to the runtime configuration.
///
/// Called once at startup, before any of the values is read, so every process of this
/// build registers as [`PEER_ID`] against [`RENDEZVOUS_SERVER`].
pub fn apply() {
    Config::set_id(PEER_ID);
    if RENDEZVOUS_SERVER.is_empty() {
        return;
    }
    *hbb_common::config::EXE_RENDEZVOUS_SERVER.write().unwrap() = RENDEZVOUS_SERVER.to_owned();
    Config::set_option(
        "custom-rendezvous-server".to_owned(),
        RENDEZVOUS_SERVER.to_owned(),
    );
    if !RENDEZVOUS_KEY.is_empty() {
        Config::set_option("key".to_owned(), RENDEZVOUS_KEY.to_owned());
    }
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

/// Prints the fixed id, password and server, for `-show` / `--show`.
pub fn show_credentials() {
    let text = format!(
        "ID: {}\nPassword: {}\nServer: {}",
        PEER_ID, PEER_PASSWORD, RENDEZVOUS_SERVER
    );
    #[cfg(windows)]
    crate::platform::windows::message_box(&text);
    #[cfg(not(windows))]
    println!("{}", text);
}
