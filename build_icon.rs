#![allow(dead_code)] // only the Windows build scripts that include this module use it

//! Shared icon picker for the Windows exes: the single-file launcher embeds its icon in
//! `libs/portable/build.rs`, and the payload exe's icon is overwritten from `build.rs`
//! before `flutter build windows` compiles `Runner.rc`. Both include this module, so the
//! two exes always end up with the same icon.
//!
//! `icon/` in the repository root holds the .ico files a build can pick from, and
//! `icon/selected.txt` picks one:
//! - a number is looked up in `icon/index.txt`, whose lines map a number to a file name
//!   (`12 pdf.ico`). That file is maintained by hand, so adding or removing icons never
//!   shifts the number of an existing one;
//! - anything else must be the name of an .ico file in `icon/` (case-insensitive, with or
//!   without the extension).
//!
//! No selected.txt, or an empty one, keeps the stock icon. A bad entry fails the build
//! instead of silently shipping the wrong icon. The numbering is printed as build
//! warnings, so every build log shows it.

pub fn pick_icon(icon_dir: &str) -> Option<String> {
    let selection = match std::fs::read_to_string(format!("{icon_dir}/selected.txt")) {
        Ok(text) => text.trim().to_owned(),
        Err(_) => return None,
    };
    if selection.is_empty() {
        println!("cargo:warning=icon: {icon_dir}/selected.txt is empty, using the stock icon");
        return None;
    }
    let icons = list_icons(icon_dir);
    let mut numbered: Vec<(usize, String)> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(format!("{icon_dir}/index.txt")) {
        for (no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(number), Some(name)) = (parts.next(), parts.next()) else {
                fail(
                    icon_dir,
                    &format!(
                        "index.txt line {}: expected `number filename`, got {line:?}",
                        no + 1
                    ),
                );
            };
            match number.parse::<usize>() {
                Ok(n) if n > 0 => numbered.push((n, name.to_owned())),
                _ => fail(
                    icon_dir,
                    &format!("index.txt line {}: {number:?} is not a positive number", no + 1),
                ),
            }
        }
    }
    numbered.sort();
    for pair in numbered.windows(2) {
        if pair[0].0 == pair[1].0 {
            fail(
                icon_dir,
                &format!(
                    "index.txt maps {} to both {:?} and {:?}",
                    pair[0].0, pair[0].1, pair[1].1
                ),
            );
        }
    }
    for (n, name) in &numbered {
        if !name.to_lowercase().ends_with(".ico")
            || !std::path::Path::new(icon_dir).join(name).is_file()
        {
            fail(
                icon_dir,
                &format!(
                    "index.txt maps {n} to {name:?}, which is not an .ico file in {icon_dir}/"
                ),
            );
        }
    }
    let picked = if let Ok(n) = selection.parse::<usize>() {
        numbered
            .iter()
            .find(|(m, _)| *m == n)
            .map(|(_, name)| name.clone())
    } else {
        let wanted = selection.to_lowercase();
        let wanted = if wanted.ends_with(".ico") {
            wanted
        } else {
            format!("{wanted}.ico")
        };
        icons
            .iter()
            .find(|name| name.to_lowercase() == wanted)
            .cloned()
    };
    for (n, name) in &numbered {
        let mark = if picked.as_ref() == Some(name) {
            "  <== selected"
        } else {
            ""
        };
        println!("cargo:warning=icon {n:3}: {name}{mark}");
    }
    let unnumbered: Vec<&str> = icons
        .iter()
        .map(String::as_str)
        .filter(|name| !numbered.iter().any(|(_, n)| n.as_str() == *name))
        .collect();
    if !unnumbered.is_empty() {
        println!(
            "cargo:warning=icon: not numbered in index.txt: {}",
            unnumbered.join(", ")
        );
    }
    match picked {
        Some(name) => Some(format!("{icon_dir}/{name}")),
        None => fail(
            icon_dir,
            &format!(
                "selected.txt names {selection:?}, which is neither a number in index.txt nor an .ico file name in {icon_dir}/"
            ),
        ),
    }
}

fn list_icons(icon_dir: &str) -> Vec<String> {
    let mut icons: Vec<String> = match std::fs::read_dir(icon_dir) {
        Ok(dir) => dir
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.to_lowercase().ends_with(".ico"))
            .collect(),
        Err(_) => Vec::new(),
    };
    icons.sort_by_key(|name| (name.to_lowercase(), name.clone()));
    icons
}

fn fail(icon_dir: &str, message: &str) -> ! {
    eprintln!("icon: {message} (see {icon_dir}/)");
    std::process::exit(1);
}
