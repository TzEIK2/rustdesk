/// File that carries one build's identity to every later cargo invocation of the same
/// working tree, so all artifacts of one CI job share the id, password and seed.
const PEER_IDENTITY_FILE: &str = ".peer_identity";

/// Identity baked into the built client: the id the controlled peer registers with, the
/// password it accepts and the seed its Ed25519 keypair is derived from.
#[derive(Default, PartialEq)]
struct PeerIdentity {
    id: String,
    password: String,
    seed: String,
}

/// Bakes a random id and password into the build.
///
/// The values come from `RD_PEER_ID` / `RD_PEER_PASSWORD` / `RD_PEER_SEED` when set, else
/// from [`PEER_IDENTITY_FILE`], else are generated here. They are exported to the crate as
/// compile-time environment variables and only visible through `-show`: printing them in
/// the build log would leak the password into CI output.
fn gen_peer_identity() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(&manifest_dir).join(PEER_IDENTITY_FILE);
    let stored = read_peer_identity(&path);
    let mut identity = PeerIdentity {
        id: std::env::var("RD_PEER_ID").unwrap_or_else(|_| stored.id.clone()),
        password: std::env::var("RD_PEER_PASSWORD").unwrap_or_else(|_| stored.password.clone()),
        seed: std::env::var("RD_PEER_SEED").unwrap_or_else(|_| stored.seed.clone()),
    };
    if !is_valid_peer_id(&identity.id) {
        identity.id = random_peer_id();
    }
    if identity.password.is_empty() {
        identity.password = random_password(12);
    }
    if !is_valid_seed(&identity.seed) {
        identity.seed = hex(&random_bytes(32));
    }
    if identity != stored {
        write_peer_identity(&path, &identity);
    }
    println!("cargo:rustc-env=RD_PEER_ID={}", identity.id);
    println!("cargo:rustc-env=RD_PEER_PASSWORD={}", identity.password);
    println!("cargo:rustc-env=RD_PEER_SEED={}", identity.seed);
    println!("cargo:rerun-if-env-changed=RD_PEER_ID");
    println!("cargo:rerun-if-env-changed=RD_PEER_PASSWORD");
    println!("cargo:rerun-if-env-changed=RD_PEER_SEED");
    println!("cargo:rerun-if-changed={}", path.display());
}

/// Optional customizations baked into every build of this binary. Any of these can be
/// provided as environment variables at CI time, so the single build script produces
/// differently-named payloads without patching sources.
fn gen_app_name() {
    let name = std::env::var("RD_APP_NAME")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "RustDesk".to_owned());
    println!("cargo:rustc-env=RD_APP_NAME={name}");
    println!("cargo:rerun-if-env-changed=RD_APP_NAME");
}

fn read_peer_identity(path: &std::path::Path) -> PeerIdentity {
    let mut identity = PeerIdentity::default();
    let Ok(text) = std::fs::read_to_string(path) else {
        return identity;
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "id" => identity.id = value.trim().to_owned(),
            "password" => identity.password = value.trim().to_owned(),
            "seed" => identity.seed = value.trim().to_owned(),
            _ => {}
        }
    }
    identity
}

fn write_peer_identity(path: &std::path::Path, identity: &PeerIdentity) {
    let text = format!(
        "# Generated at build time; every cargo invocation of this build reuses it.\nid={}\npassword={}\nseed={}\n",
        identity.id, identity.password, identity.seed
    );
    if let Err(err) = std::fs::write(path, text) {
        println!("cargo:warning=failed to store {}: {err}", path.display());
    }
}

/// hbbs rejects ids shorter than six characters.
fn is_valid_peer_id(id: &str) -> bool {
    (6..=16).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// The keypair seed is 32 bytes written as hex.
fn is_valid_seed(seed: &str) -> bool {
    seed.len() == 64 && seed.chars().all(|c| c.is_ascii_hexdigit())
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            if file.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
    }
    // Fallback for hosts without /dev/urandom: splitmix64 seeded by the clock and pid.
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ ((std::process::id() as u64) << 32);
    for chunk in buf.chunks_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
    buf
}

fn random_peer_id() -> String {
    let bytes = random_bytes(9);
    let mut id = String::with_capacity(bytes.len());
    id.push((b'1' + bytes[0] % 9) as char);
    for b in &bytes[1..] {
        id.push((b'0' + b % 10) as char);
    }
    id
}

/// Password without characters that are easy to confuse when copied by hand.
fn random_password(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    random_bytes(len)
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        text.push_str(&format!("{:02x}", b));
    }
    text
}

/// The payload exe gets its icon from `Runner.rc` when `flutter build windows` compiles it,
/// which happens after this build script (build.py: cargo build, then flutter build), so
/// the selected icon is copied over the file Runner.rc references. Without a selection the
/// committed file is left untouched.
#[cfg(windows)]
fn set_runner_icon() {
    println!("cargo:rerun-if-changed=icon");
    println!("cargo:rerun-if-changed=icon/selected.txt");
    println!("cargo:rerun-if-changed=icon/index.txt");
    if let Some(icon) = build_icon::pick_icon("icon") {
        let target = "flutter/windows/runner/resources/app_icon.ico";
        if let Err(err) = std::fs::copy(&icon, target) {
            eprintln!("icon: failed to copy {icon} over {target}: {err}");
            std::process::exit(1);
        }
    }
}

#[path = "build_icon.rs"]
mod build_icon;

#[cfg(windows)]
fn build_windows() {
    set_runner_icon();
    let file = "src/platform/windows.cc";
    let file2 = "src/platform/windows_delete_test_cert.cc";
    cc::Build::new().file(file).file(file2).compile("windows");
    println!("cargo:rustc-link-lib=WtsApi32");
    println!("cargo:rerun-if-changed={}", file);
    println!("cargo:rerun-if-changed={}", file2);
}

#[cfg(target_os = "macos")]
fn build_mac() {
    let file = "src/platform/macos.mm";
    let mut b = cc::Build::new();
    if let Ok(os_version::OsVersion::MacOS(v)) = os_version::detect() {
        let v = v.version;
        if v.contains("10.14") {
            b.flag("-DNO_InputMonitoringAuthStatus=1");
        }
    }
    b.flag("-std=c++17").file(file).compile("macos");
    println!("cargo:rerun-if-changed={}", file);
}

#[cfg(all(windows, feature = "inline"))]
fn build_manifest() {
    use std::io::Write;
    if std::env::var("PROFILE").unwrap() == "release" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("res/icon.ico")
            .set_language(winapi::um::winnt::MAKELANGID(
                winapi::um::winnt::LANG_ENGLISH,
                winapi::um::winnt::SUBLANG_ENGLISH_US,
            ))
            .set_manifest_file("res/manifest.xml");
        match res.compile() {
            Err(e) => {
                write!(std::io::stderr(), "{}", e).unwrap();
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }
}

// bionic only exports getifaddrs()/freeifaddrs() from API 24, while the jniLibs
// are built against the API 21 sysroot (flutter/ndk_*.sh). webrtc-util calls
// them, so without this the android link fails on undefined symbols.
fn build_android_ifaddrs() {
    let file = "src/platform/android_ifaddrs.c";
    cc::Build::new().file(file).compile("android_ifaddrs");
    println!("cargo:rerun-if-changed={}", file);
}

fn install_android_deps() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "android" {
        return;
    }
    let mut target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch == "x86_64" {
        target_arch = "x64".to_owned();
    } else if target_arch == "x86" {
        target_arch = "x86".to_owned();
    } else if target_arch == "aarch64" {
        target_arch = "arm64".to_owned();
    } else {
        target_arch = "arm".to_owned();
    }
    let target = format!("{}-android", target_arch);
    let vcpkg_root = std::env::var("VCPKG_ROOT").unwrap();
    let mut path: std::path::PathBuf = vcpkg_root.into();
    if let Ok(vcpkg_root) = std::env::var("VCPKG_INSTALLED_ROOT") {
        path = vcpkg_root.into();
    } else {
        path.push("installed");
    }
    path.push(target);
    println!(
        "cargo:rustc-link-search={}",
        path.join("lib").to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=ndk_compat");
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-lib=OpenSLES");
}

fn main() {
    gen_peer_identity();
    gen_app_name();
    hbb_common::gen_version();
    install_android_deps();
    #[cfg(all(windows, feature = "inline"))]
    build_manifest();
    #[cfg(windows)]
    build_windows();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        #[cfg(target_os = "macos")]
        build_mac();
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
    }
    if target_os == "android" {
        build_android_ifaddrs();
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_icon.rs");
}
