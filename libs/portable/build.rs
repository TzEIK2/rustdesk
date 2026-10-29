#[path = "../../build_icon.rs"]
mod build_icon;

fn main() {
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
