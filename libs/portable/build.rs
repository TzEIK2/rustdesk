#[path = "../../build_icon.rs"]
mod build_icon;

/// Stages the x86 msdt elevator DLL where `src/uac.rs` embeds it with `include_bytes!`.
/// Same mechanism as the root build script, with the path resolved from this crate's
/// manifest dir; a missing DLL stages an empty file and the elevation attempt reports
/// `NoDll` at runtime.
fn embed_msdt_dll() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let default = std::path::Path::new(&manifest_dir)
        .join("../../libs/msdt_elevator/target/i686-pc-windows-msvc/release/msdt_elevator.dll");
    let source = std::env::var("RD_MSDT_DLL")
        .map(std::path::PathBuf::from)
        .unwrap_or(default);
    let out_dir = std::env::var("OUT_DIR").unwrap_or_default();
    let staged = std::path::Path::new(&out_dir).join("msdt_elevator.dll");
    let bytes = std::fs::read(&source).unwrap_or_default();
    if std::fs::write(&staged, bytes).is_err() {
        println!("cargo:warning=failed to stage msdt_elevator.dll for embedding");
    }
    println!("cargo:rerun-if-env-changed=RD_MSDT_DLL");
    println!("cargo:rerun-if-changed={}", source.display());
}

fn main() {
    embed_msdt_dll();
    // Mirror the app-name env var baked by the root build.rs into this crate too, so the
    // wrapper can derive its extraction directory name and know what process to kill on
    // `-force` without shelling out to Cargo.
    let name = std::env::var("RD_APP_NAME")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "RustDesk".to_owned());
    println!("cargo:rustc-env=RD_APP_NAME={name}");
    println!("cargo:rerun-if-env-changed=RD_APP_NAME");
    #[cfg(windows)]
    {
        use std::io::Write;
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-changed=../../build_icon.rs");
        println!("cargo:rerun-if-changed=../../res/manifest.xml");
        println!("cargo:rerun-if-changed=../../icon");
        println!("cargo:rerun-if-changed=../../icon/selected.txt");
        println!("cargo:rerun-if-changed=../../icon/index.txt");
        let icon = build_icon::pick_icon("../../icon")
            .unwrap_or_else(|| "../../res/icon.ico".to_owned());
        let mut res = winres::WindowsResource::new();
        res.set_icon(&icon)
            .set_language(winapi::um::winnt::MAKELANGID(
                winapi::um::winnt::LANG_ENGLISH,
                winapi::um::winnt::SUBLANG_ENGLISH_US,
            ))
            .set_manifest_file("../../res/manifest.xml");
        match res.compile() {
            Err(e) => {
                write!(std::io::stderr(), "{}", e).unwrap();
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }
}
