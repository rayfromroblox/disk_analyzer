use std::collections::HashSet;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTarget {
    label: String,
    path: String,
    detail: String,
}

pub fn scan_targets(startup_path: &str) -> Vec<ScanTarget> {
    let mut seen = HashSet::<PathBuf>::new();
    let mut targets = Vec::<ScanTarget>::new();
    let mut add = |path: PathBuf, label: String, detail: String| {
        if path.is_dir() && seen.insert(path.clone()) {
            targets.push(ScanTarget {
                label,
                path: path.to_string_lossy().into_owned(),
                detail,
            });
        }
    };

    if let Some(home) = home_directory() {
        add(
            home,
            "Home folder".to_owned(),
            "Your personal files".to_owned(),
        );
    }

    let startup = PathBuf::from(startup_path);
    let current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if startup != current {
        add(
            startup,
            "Selected folder".to_owned(),
            "The folder passed to the command".to_owned(),
        );
    }
    add(
        current,
        "Current folder".to_owned(),
        "Where the analyzer was started".to_owned(),
    );

    add_platform_targets(&mut add);
    targets
}

fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(target_os = "linux")]
fn add_platform_targets(add: &mut dyn FnMut(PathBuf, String, String)) {
    add(
        PathBuf::from("/"),
        "Computer".to_owned(),
        "System filesystem".to_owned(),
    );
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return;
    };
    for line in mounts.lines() {
        let Some((before_separator, after_separator)) = line.split_once(" - ") else {
            continue;
        };
        let filesystem = after_separator
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if matches!(
            filesystem,
            "proc"
                | "sysfs"
                | "tmpfs"
                | "devtmpfs"
                | "devpts"
                | "cgroup"
                | "cgroup2"
                | "overlay"
                | "squashfs"
        ) {
            continue;
        }
        let fields: Vec<_> = before_separator.split_whitespace().collect();
        let Some(mount_point) = fields.get(4) else {
            continue;
        };
        let mount_point = unescape_mount_path(mount_point);
        let path = PathBuf::from(&mount_point);
        if path == Path::new("/") || !path.is_dir() {
            continue;
        }
        let label = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| mount_point.clone());
        add(path, label, format!("Mounted {filesystem} volume"));
    }
}

#[cfg(target_os = "linux")]
fn unescape_mount_path(path: &str) -> String {
    path.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
}

#[cfg(target_os = "macos")]
fn add_platform_targets(add: &mut dyn FnMut(PathBuf, String, String)) {
    add(
        PathBuf::from("/"),
        "Macintosh HD".to_owned(),
        "System filesystem".to_owned(),
    );
    if let Ok(entries) = std::fs::read_dir("/Volumes") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                add(
                    path.clone(),
                    entry.file_name().to_string_lossy().into_owned(),
                    "Mounted volume".to_owned(),
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn add_platform_targets(add: &mut dyn FnMut(PathBuf, String, String)) {
    for letter in b'A'..=b'Z' {
        let path = PathBuf::from(format!("{}:\\", char::from(letter)));
        if path.is_dir() {
            add(
                path.clone(),
                format!("{}: drive", char::from(letter)),
                "Available volume".to_owned(),
            );
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn add_platform_targets(_add: &mut dyn FnMut(PathBuf, String, String)) {}
