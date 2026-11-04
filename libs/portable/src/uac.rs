//! Silent elevation for Windows launches.
//!
//! `CMSTPLUA` ({3E5FC7F9-9A51-4367-9063-A120244FBEC7}) is an auto-elevate COM object, so
//! `CoGetObject` with an `Elevation:Administrator` moniker returns an elevated
//! `ICMLuaUtil` without showing a UAC prompt. `ICMLuaUtil::ShellExec` then starts this
//! executable as a high-integrity child of the elevated COM server.
//!
//! If silent elevation is unavailable (UAC disabled, AppInfo service stopped, policy
//! restriction, or an antivirus blocking it), the attempt fails cleanly and the process
//! continues running as a normal medium-integrity user. No UAC prompt is ever shown.
//!
//! Windows cannot raise an existing process's integrity level, so the caller starts a
//! second copy and exits. That copy carries [`ELEVATED_FLAG`] so it does not try again.
//!
//! `libs/portable` builds independently of the app and its `windows` dependency enables
//! neither the COM nor the security feature, so the few vtable-ordered calls are declared
//! here directly rather than widening that feature set for one function.

use std::{ffi::c_void, mem, os::windows::ffi::OsStrExt, ptr::null_mut};

/// Private argument marking the copy started by [`relaunch_elevated`].
pub const ELEVATED_FLAG: &str = "--elevated";

const COINIT_APARTMENTTHREADED: u32 = 0x0000_0002;
const CLSCTX_LOCAL_SERVER: u32 = 0x0000_0004;
const TOKEN_QUERY: u32 = 0x0000_0008;
const TOKEN_ELEVATION_CLASS: u32 = 20;

const ELEVATION_MONIKER: &str =
    "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

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
/// `SEE_MASK_*` flag set and the fifth a `SW_*` show code. It builds its own
/// `SHELLEXECUTEINFOW` internally.
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

#[repr(C)]
struct TokenElevation {
    token_is_elevated: u32,
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
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// Whether this process already runs with an elevated token.
///
/// A failure reads as "not elevated": an unnecessary relaunch attempt is harmless, while
/// skipping one that was needed is not.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: *mut c_void = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TokenElevation { token_is_elevated: 0 };
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

/// Outcome of a [`relaunch_elevated`] attempt. The variant names match the failure step
/// so the wrapper log can tell them apart without decoding HRESULTs.
#[derive(Debug, Clone)]
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
}

/// Starts this executable again with the same arguments plus [`ELEVATED_FLAG`], through
/// the elevated `CMSTPLUA` object.
///
/// Returns [`RelaunchResult::Launched`] only when the elevated copy was spawned. Every
/// failure surfaces via the specific variant so the caller can log it for diagnosis
/// before continuing as a normal non-elevated launch. No UAC prompt is ever shown.
///
/// The implementation matches the published reference PoC (`CoInitialize(NULL)` = pure
/// STA, BIND_OPTS3 zero-initialised then only `cbStruct` and `dwClassContext` set,
/// `SEE_MASK_DEFAULT` + `SW_SHOW` for `ShellExec`).
pub fn relaunch_elevated(args: &[String]) -> RelaunchResult {
    diag("== relaunch_elevated start ==");
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

/// Lightweight step-trace writer, same format as the payload side. Both sides interleave
/// into the same `wrapper.log` so one run shows a single linear timeline regardless of
/// whether the portable wrapper or the payload took the elevation path.
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
