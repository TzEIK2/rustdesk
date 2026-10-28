#![windows_subsystem = "windows"]

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use bin_reader::{normalize_path, BinaryReader};

pub mod bin_reader;
#[cfg(windows)]
mod ui;

#[cfg(windows)]
const APP_METADATA: &[u8] = include_bytes!("../app_metadata.toml");
#[cfg(not(windows))]
const APP_METADATA: &[u8] = &[];
const APP_METADATA_CONFIG: &str = "meta.toml";
const META_LINE_PREFIX_TIMESTAMP: &str = "timestamp = ";
const META_LINE_PREFIX_FILE: &str = "file = ";
const APP_PREFIX: &str = "rustdesk";
#[cfg(windows)]
const VERIFIED_UPDATE_FILE_PREFIX: &str = "rustdesk-verified-";
const APPNAME_RUNTIME_ENV_KEY: &str = "RUSTDESK_APPNAME";
#[cfg(windows)]
const SET_FOREGROUND_WINDOW_ENV_KEY: &str = "SET_FOREGROUND_WINDOW";

// The extraction directory follows whatever executable the payload asks for, so a
// custom client gets its own directory instead of sharing RustDesk's. Falls back to
// APP_PREFIX when no package is injected, which keeps stock builds unchanged.
fn app_dir_name(exe: &str) -> String {
    Path::new(&exe.replace('\\', "/"))
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| stem.trim().to_lowercase())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| APP_PREFIX.to_owned())
}

fn is_timestamp_matches(dir: &Path, ts: &mut u64) -> bool {
    let Ok(app_metadata) = std::str::from_utf8(APP_METADATA) else {
        return true;
    };
    for line in app_metadata.lines() {
        if line.starts_with(META_LINE_PREFIX_TIMESTAMP) {
            if let Ok(stored_ts) = line.replace(META_LINE_PREFIX_TIMESTAMP, "").parse::<u64>() {
                *ts = stored_ts;
                break;
            }
        }
    }
    if *ts == 0 {
        return true;
    }

    if let Ok(content) = std::fs::read_to_string(dir.join(APP_METADATA_CONFIG)) {
        for line in content.lines() {
            if line.starts_with(META_LINE_PREFIX_TIMESTAMP) {
                if let Ok(stored_ts) = line.replace(META_LINE_PREFIX_TIMESTAMP, "").parse::<u64>() {
                    return *ts == stored_ts;
                }
            }
        }
    }
    false
}

fn write_meta(dir: &Path, ts: u64, package_paths: &[String]) {
    let meta_file = dir.join(APP_METADATA_CONFIG);
    let mut content = format!("{}{}\n", META_LINE_PREFIX_TIMESTAMP, ts);
    for path in package_paths {
        content.push_str(&format!("{}{}\n", META_LINE_PREFIX_FILE, path));
    }
    // Ignore is ok here
    let _ = std::fs::write(meta_file, content);
}

fn previous_package_files(dir: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(dir.join(APP_METADATA_CONFIG)) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| line.strip_prefix(META_LINE_PREFIX_FILE))
        .map(|path| path.trim().to_owned())
        .collect()
}

// meta.toml is plain text in a user-writable directory, and it now drives deletion,
// so the path is rebuilt from plain components rather than joined as written. A
// prefix, root or parent component would otherwise escape the extraction directory:
// Path::join replaces the base entirely when given an absolute path.
fn resolve_within(dir: &Path, relative: &str) -> Option<PathBuf> {
    use std::path::Component;
    let mut path = dir.to_path_buf();
    let mut any = false;
    for component in Path::new(&relative.replace('\\', "/")).components() {
        match component {
            Component::Normal(part) => {
                // A drive-relative name like "C:x" parses as Normal, and only a
                // Windows host would classify "C:/..." as a Prefix, so the colon is
                // rejected outright rather than relying on the host's parser.
                if part.to_string_lossy().contains(':') {
                    return None;
                }
                path.push(part);
                any = true;
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    if any {
        Some(path)
    } else {
        None
    }
}

// A customer who drops a branding asset gets a package without it, and the file
// would otherwise linger in an existing extraction and keep being used. The wipe
// cannot cover this: it is keyed on the packer's build timestamp, which is now the
// same for every customer of a release.
fn remove_dropped_package_files_with<F>(
    dir: &Path,
    current: &[String],
    mut remove_file: F,
) -> Vec<String>
where
    F: FnMut(&Path) -> std::io::Result<()>,
{
    let keep: std::collections::HashSet<String> =
        current.iter().map(|p| normalize_path(p)).collect();
    let mut failed = Vec::new();
    for previous in previous_package_files(dir) {
        if keep.contains(&normalize_path(&previous)) {
            continue;
        }
        let Some(path) = resolve_within(dir, &previous) else {
            continue;
        };
        if path.is_file() {
            println!("removing dropped {}", previous);
            if let Err(error) = remove_file(&path) {
                eprintln!("failed to remove dropped {}: {}", previous, error);
                failed.push(previous);
            }
        }
    }
    failed
}

fn remove_dropped_package_files(dir: &Path, current: &[String]) -> Vec<String> {
    remove_dropped_package_files_with(dir, current, |path| std::fs::remove_file(path))
}

fn setup(
    reader: BinaryReader,
    dir: Option<PathBuf>,
    clear: bool,
    _args: &Vec<String>,
    _ui: &mut bool,
) -> Option<PathBuf> {
    let dir = if let Some(dir) = dir {
        dir
    } else {
        // home dir
        if let Some(dir) = dirs::data_local_dir() {
            dir.join(app_dir_name(&reader.exe))
        } else {
            eprintln!("not found data local dir");
            return None;
        }
    };

    let mut ts = 0;
    if clear || !is_timestamp_matches(&dir, &mut ts) {
        #[cfg(windows)]
        if _args.is_empty() && !cfg!(feature = "no-ui") {
            *_ui = true;
            ui::setup();
        }
        std::fs::remove_dir_all(&dir).ok();
    }
    let mut metadata_paths = reader.package_paths.clone();
    metadata_paths.extend(remove_dropped_package_files(&dir, &reader.package_paths));
    for file in reader.files.iter() {
        file.write_to_file(&dir);
    }
    write_meta(&dir, ts, &metadata_paths);
    #[cfg(windows)]
    win::copy_runtime_broker(&dir);
    #[cfg(linux)]
    reader.configure_permission(&dir);
    Some(dir.join(&reader.exe))
}

fn use_null_stdio() -> bool {
    #[cfg(windows)]
    {
        // When running in CMD on Windows 7, using Stdio::inherit() with spawn returns an "invalid handle" error.
        // Since using Stdio::null() didn’t cause any issues, and determining whether the program is launched from CMD or by double-clicking would require calling more APIs during startup, we also use Stdio::null() when launched by double-clicking on Windows 7.
        let is_windows_7 = is_windows_7();
        println!("is windows7: {}", is_windows_7);
        return is_windows_7;
    }
    #[cfg(not(windows))]
    false
}

#[cfg(windows)]
fn is_windows_7() -> bool {
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    unsafe {
        let mut version_info = OSVERSIONINFOW::default();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if RtlGetVersion(&mut version_info).is_ok() {
            // Windows 7 is version 6.1
            println!(
                "Windows version: {}.{}",
                version_info.dwMajorVersion, version_info.dwMinorVersion
            );
            return version_info.dwMajorVersion == 6 && version_info.dwMinorVersion == 1;
        }
    }
    false
}

#[cfg(windows)]
fn attach_console() {
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    #[allow(non_snake_case)]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    // Failing means there is no console to attach to; the payload then falls back to a
    // message box.
    let _ = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
}

/// Whether this invocation is a read-only `-show` / `--show`: prints creds and exits.
fn is_show(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "-show" || arg == "--show")
}

/// Spawns the payload and returns the [`std::process::Child`] handle.
///
/// Callers normally drop the handle (the payload keeps running after the wrapper exits),
/// but [`main`] holds on to it for a `-show` invocation so it can wait for the child to
/// finish before wiping the extracted directory.
fn execute(path: PathBuf, args: Vec<String>, _ui: bool) -> Option<std::process::Child> {
    // The payload reports its credentials on stdout for `-show`; that only reaches the
    // caller's terminal when this wrapper is attached to it first.
    #[cfg(windows)]
    if is_show(&args) {
        attach_console();
    }
    // `-show` output on its own lines only; suppress the wrapper's echo so the user sees
    // nothing but `ID: ...` and `Password: ...`.
    if !is_show(&args) {
        println!("executing {}", path.display());
    }
    // setup env
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_name = exe.file_name().unwrap_or_default();
    // run executable
    let mut cmd = Command::new(path);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
        if _ui {
            cmd.env(SET_FOREGROUND_WINDOW_ENV_KEY, "1");
        }
    }

    cmd.env(APPNAME_RUNTIME_ENV_KEY, exe_name);
    if use_null_stdio() && !is_show(&args) {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    } else {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
    let child = cmd.spawn();

    #[cfg(windows)]
    if _ui {
        match &child {
            Ok(child) => unsafe {
                winapi::um::winuser::AllowSetForegroundWindow(child.id() as u32);
            },
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
    child.ok()
}

fn main() -> Result<(), String> {
    let mut args = Vec::new();
    let mut arg_exe = Default::default();
    let mut i = 0;
    for arg in std::env::args() {
        if i == 0 {
            arg_exe = arg.clone();
        } else {
            args.push(arg);
        }
        i += 1;
    }
    let click_setup = args.is_empty() && arg_exe.to_lowercase().ends_with("install.exe");
    let is_show_run = is_show(&args);
    #[cfg(windows)]
    let quick_support = args.is_empty() && win::is_quick_support_exe(&arg_exe);
    #[cfg(not(windows))]
    let quick_support = false;

    #[cfg(windows)]
    if args.first().is_some_and(|arg| arg == "--update") {
        if let Err(err) = win::schedule_verified_update_cleanup() {
            eprintln!("Failed to schedule verified update file cleanup: {}", err);
        }
    }

    let mut ui = false;
    let reader = BinaryReader::new()?;
    let mut extracted_root = None;
    if let Some(exe) = setup(
        reader,
        None,
        click_setup || args.contains(&"--silent-install".to_owned()),
        &args,
        &mut ui,
    ) {
        // Remember the extraction directory before `execute` consumes `exe`.
        extracted_root = exe.parent().map(|p| p.to_path_buf());
        if click_setup {
            args = vec!["--install".to_owned()];
        } else if quick_support {
            args = vec!["--quick_support".to_owned()];
        }
        let child = execute(exe, args, ui);
        if is_show_run {
            // Wait for the child to print its credentials and exit, then remove the
            // extracted payload so a `-show` run leaves nothing behind on disk.
            if let Some(mut child) = child {
                let _ = child.wait();
            }
            if let Some(dir) = extracted_root {
                // Windows lingers on file handles after process exit: the child exe itself,
                // and sometimes an antivirus real-time scan that touched it. Keep retrying
                // for up to 3s (100ms * 30) before giving up. Giving up is silent: the
                // directory simply stays behind and the user can remove it by hand.
                const MAX_RETRIES: u32 = 30;
                #[cfg(windows)]
                {
                    for i in 0..MAX_RETRIES {
                        match std::fs::remove_dir_all(&dir) {
                            Ok(_) => break,
                            Err(_) if i + 1 < MAX_RETRIES => std::thread::sleep(
                                std::time::Duration::from_millis(100),
                            ),
                            Err(_) => {}
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = std::fs::remove_dir_all(&dir);
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
mod win {
    use std::{fs, os::windows::process::CommandExt, path::Path, process::Command};

    // Used for privacy mode(magnifier impl).
    pub const RUNTIME_BROKER_EXE: &'static str = "C:\\Windows\\System32\\RuntimeBroker.exe";
    pub const WIN_TOPMOST_INJECTED_PROCESS_EXE: &'static str = "RuntimeBroker_rustdesk.exe";

    pub(super) fn schedule_verified_update_cleanup() -> std::io::Result<()> {
        use windows::{
            core::{HSTRING, PCWSTR},
            Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT},
        };

        let current_exe = std::env::current_exe()?;
        let is_verified_update = current_exe
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with(super::VERIFIED_UPDATE_FILE_PREFIX) && name.ends_with(".exe")
            });
        if !is_verified_update {
            return Ok(());
        }

        unsafe {
            MoveFileExW(
                &HSTRING::from(current_exe.as_path()),
                PCWSTR::null(),
                MOVEFILE_DELAY_UNTIL_REBOOT,
            )
        }
        .map_err(std::io::Error::other)
    }

    pub(super) fn copy_runtime_broker(dir: &Path) {
        let src = RUNTIME_BROKER_EXE;
        let tgt = WIN_TOPMOST_INJECTED_PROCESS_EXE;
        let target_file = dir.join(tgt);
        if target_file.exists() {
            if let (Ok(src_file), Ok(tgt_file)) = (fs::read(src), fs::read(&target_file)) {
                let src_md5 = format!("{:x}", md5::compute(&src_file));
                let tgt_md5 = format!("{:x}", md5::compute(&tgt_file));
                if src_md5 == tgt_md5 {
                    return;
                }
            }
        }
        let _allow_err = Command::new("taskkill")
            .args(&["/F", "/IM", "RuntimeBroker_rustdesk.exe"])
            .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
            .output();
        let _allow_err = std::fs::copy(src, &format!("{}\\{}", dir.to_string_lossy(), tgt));
    }

    /// Check if the executable is a Quick Support version.
    /// Note: This function must be kept in sync with `src/core_main.rs`.
    #[inline]
    pub(super) fn is_quick_support_exe(exe: &str) -> bool {
        let exe = exe.to_lowercase();
        exe.contains("-qs-") || exe.contains("-qs.exe") || exe.contains("_qs.exe")
    }
}

#[cfg(test)]
mod meta_tests {
    use super::*;

    #[test]
    fn resolve_within_rejects_paths_that_escape() {
        let base = Path::new("/base");
        assert_eq!(
            resolve_within(base, "./data/logo.png"),
            Some(base.join("data").join("logo.png"))
        );
        assert_eq!(
            resolve_within(base, ".\\data\\logo.png"),
            Some(base.join("data").join("logo.png"))
        );
        // meta.toml is user-writable, so these must not reach remove_file.
        assert_eq!(resolve_within(base, "../../etc/passwd"), None);
        assert_eq!(resolve_within(base, "/etc/passwd"), None);
        assert_eq!(resolve_within(base, "C:\\Windows\\System32\\x.dll"), None);
        assert_eq!(resolve_within(base, "."), None);
        assert_eq!(resolve_within(base, ""), None);
    }
}
