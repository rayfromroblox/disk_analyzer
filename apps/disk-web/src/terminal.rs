use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use disk_core::{ScanProgress, ScanSummary, format_bytes};

static LAST_LINE_WIDTH: AtomicUsize = AtomicUsize::new(0);

pub fn progress(progress: &ScanProgress) {
    if !interactive() || progress.finished {
        return;
    }

    let line = format!(
        "  Scanning  {:>11} files  {:>11}  {:>6} errors  {:>7.1}s",
        count(progress.files),
        format_bytes(progress.allocated_bytes),
        count(progress.errors),
        progress.elapsed_ms as f64 / 1000.0
    );
    write_line(&line, false);
}

pub fn scan_started(path: &str) {
    if !interactive() {
        return;
    }

    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "\n  Scanning {path}");
    let _ = stderr.flush();
}

pub fn scan_finished(summary: &ScanSummary) {
    if !interactive() {
        return;
    }

    let state = if summary.canceled { "Partial" } else { "Done" };
    let line = format!(
        "  {state}: {} files | {} allocated | {} errors | {:.2}s",
        count(summary.files),
        format_bytes(summary.allocated_bytes),
        count(summary.errors),
        summary.elapsed_ms as f64 / 1000.0
    );
    write_line(&line, true);
}

pub fn scan_failed(error: &str) {
    if !interactive() {
        return;
    }

    write_line(&format!("  Scan failed: {error}"), true);
}

pub fn interactive() -> bool {
    io::stderr().is_terminal()
}

fn write_line(line: &str, newline: bool) {
    let previous = LAST_LINE_WIDTH.swap(line.chars().count(), Ordering::Relaxed);
    let padding = previous.saturating_sub(line.chars().count());
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "\r{line}");
    if padding > 0 {
        let _ = write!(stderr, "{}", " ".repeat(padding));
        let _ = write!(stderr, "\r{line}");
    }
    if newline {
        let _ = writeln!(stderr);
        LAST_LINE_WIDTH.store(0, Ordering::Relaxed);
    }
    let _ = stderr.flush();
}

fn count(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(digit);
    }
    formatted
}
