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
const COINIT_DISABLE_OLE1DDE: u32 = 0x0000_0004;
const CLSCTX_LOCAL_SERVER: u32 = 0x0000_0004;
// `ShellExec` forwards these to `ShellExecuteEx`: `NOASYNC` keeps the call synchronous on
// this STA thread, so the launched copy exists before this process exits, and `NO_UI`
// suppresses an error dialog.
const SEE_MASK_NOASYNC: u32 = 0x0000_0100;
const SEE_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
const SW_HIDE: i32 = 0;
const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;

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
/// **Note:** BIND_OPTS2 extends BIND_OPTS with `dwClassContext` **and** `locale` (LCID),
/// then BIND_OPTS3 adds `hwnd`. Omitting `locale` causes the field offsets to drift: on
/// x64 the first four DWORDs consume 20 bytes, then the `hwnd` pointer needs 8-byte
/// alignment so the compiler inserts a 4-byte padding. If `locale` is missing, that
/// padding sits where the COM runtime expects LCID and reads garbage from the stack,
/// which makes `CoGetObject` refuse the elevation moniker with `CO_E_ELEVATION_DISABLED`.
#[allow(dead_code)]
#[repr(C)]
struct BindOpts3 {
    cb_struct: u32,
    grf_flags: u32,
    grf_mode: u32,
    dw_tick_count_deadline: u32,
    dw_class_context: u32,
    locale: u32,
    hwnd: *mut c_void,
}

/// `IUnknown` (3 slots) + six unused `ICMLuaUtil` methods, then `ShellExec` at slot 9.
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
    shell_exec:
        unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, u32, i32) -> i32,
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
}

/// Starts this executable again with the same arguments plus [`ELEVATED_FLAG`], through the
/// elevated `CMSTPLUA` object.
///
/// Returns [`RelaunchResult::Launched`] only when the elevated copy was spawned. Every
/// failure (not an administrator, "Always notify" policy, COM or antivirus block) is
/// surfaced via the specific variant so the caller can record it and carry on as a
/// normal non-elevated launch. No UAC prompt is ever shown.
pub fn relaunch_elevated(args: &[String]) -> RelaunchResult {
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

    unsafe {
        let init =
            CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if init < 0 && init as u32 != RPC_E_CHANGED_MODE {
            return RelaunchResult::CoInitFailed(init);
        }
        // Defensive zeroing: `BIND_OPTS3` has 7 fields followed by pointer-size alignment
        // padding on x64; `std::mem::zeroed()` guarantees every byte we do not explicitly
        // set (including the trailing padding and the `locale` field we no longer omit)
        // starts at zero.
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
                working_dir
                    .as_ref()
                    .map_or(std::ptr::null(), |dir| dir.as_ptr()),
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

/// Appends one line to the same diagnostic file the portable wrapper writes, because the
/// application log does not exist yet at the point this decision is made.
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
        let _ = writeln!(file, "payload: {}", message);
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
