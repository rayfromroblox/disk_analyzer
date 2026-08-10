use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use disk_core::{
    CancellationToken, EntryKind, ScanConfig, ScanResult, SizeMetric, format_bytes, scan,
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "disk-analyzer",
    version,
    about = "Accurate cross-platform disk usage analysis"
)]
struct Args {
    /// File or directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output representation.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Size used for sorting human-readable results.
    #[arg(long, value_enum, default_value_t = Metric::Allocated)]
    size: Metric,

    /// Number of largest files and directories to print.
    #[arg(short = 'n', long, default_value_t = 20, value_parser = parse_top)]
    top: usize,

    /// Scanner workers. Zero selects a conservative automatic value.
    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,

    /// Follow symbolic links and junctions, with loop detection.
    #[arg(long)]
    follow_links: bool,

    /// Descend into mounted filesystems and other volumes.
    #[arg(long)]
    cross_filesystems: bool,

    /// Count each hard-link path as separately allocated storage.
    #[arg(long)]
    count_hard_links: bool,

    /// Suppress live progress on stderr.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Metric {
    Logical,
    Allocated,
}

fn parse_top(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "top must be an integer".to_owned())?;
    (1..=100_000)
        .contains(&parsed)
        .then_some(parsed)
        .ok_or_else(|| "top must be between 1 and 100000".to_owned())
}

impl From<Metric> for SizeMetric {
    fn from(value: Metric) -> Self {
        match value {
            Metric::Logical => Self::Logical,
            Metric::Allocated => Self::Allocated,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cancellation = CancellationToken::new();
    let signal_cancellation = cancellation.clone();
    ctrlc::set_handler(move || signal_cancellation.cancel())
        .context("failed to install Ctrl-C handler")?;

    let mut config = ScanConfig::new(&args.path);
    config.threads = args.threads;
    config.follow_symlinks = args.follow_links;
    config.stay_on_filesystem = !args.cross_filesystems;
    config.deduplicate_hard_links = !args.count_hard_links;

    let show_progress = !args.quiet && io::stderr().is_terminal();
    let result = scan(config, cancellation, |progress| {
        if show_progress {
            eprint!(
                "\rScanning: {:>10} files  {:>11}  {:>6} errors  {:>6.1}s",
                progress.files,
                format_bytes(progress.logical_bytes),
                progress.errors,
                progress.elapsed_ms as f64 / 1000.0
            );
            let _ = io::stderr().flush();
        }
    })
    .with_context(|| format!("scan failed for {}", args.path.display()))?;

    if show_progress {
        eprintln!();
    }

    match args.format {
        OutputFormat::Human => print_human(&result, args.size.into(), args.top),
        OutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout().lock(), &result)?;
            println!();
        }
        OutputFormat::Csv => print_csv(&result)?,
    }

    Ok(())
}

fn print_human(result: &ScanResult, metric: SizeMetric, top: usize) {
    let summary = &result.summary;
    let state = if summary.canceled {
        "canceled (partial results)"
    } else {
        "complete"
    };
    println!("Scan {state}: {}", summary.root);
    println!(
        "{} files, {} directories, {} symlinks, {} errors in {:.2}s",
        summary.files,
        summary.directories,
        summary.symlinks,
        summary.errors,
        summary.elapsed_ms as f64 / 1000.0
    );
    println!(
        "Logical: {}    Allocated: {}    Hard-link duplicates: {}",
        format_bytes(summary.logical_bytes),
        format_bytes(summary.allocated_bytes),
        summary.hard_link_duplicates
    );

    print_largest(
        result,
        "Largest directories",
        Some(EntryKind::Directory),
        metric,
        top,
    );
    print_largest(result, "Largest files", Some(EntryKind::File), metric, top);

    if !result.error_samples.is_empty() {
        println!(
            "\nSkipped paths (showing up to {}):",
            result.error_samples.len()
        );
        for error in &result.error_samples {
            println!("  {}: {}", error.path, error.message);
        }
    }
}

fn print_largest(
    result: &ScanResult,
    title: &str,
    kind: Option<EntryKind>,
    metric: SizeMetric,
    limit: usize,
) {
    println!("\n{title}:");
    for node in result.largest(kind, metric, limit) {
        let path = result
            .display_path(node.id)
            .unwrap_or_else(|| node.name.clone());
        println!(
            "  {:>11}  {:>11}  {}",
            format_bytes(node.logical_size),
            format_bytes(node.allocated_size),
            path
        );
    }
}

#[derive(Serialize)]
struct CsvRow<'a> {
    id: u64,
    parent_id: Option<u64>,
    kind: &'a str,
    path: String,
    logical_bytes: u64,
    allocated_bytes: u64,
    files: u64,
    directories: u64,
    modified_unix_ms: Option<u64>,
    symlink: bool,
    mount_point: bool,
    hard_link_duplicate: bool,
}

fn print_csv(result: &ScanResult) -> Result<()> {
    let mut writer = csv::Writer::from_writer(io::stdout().lock());
    for node in &result.nodes {
        writer.serialize(CsvRow {
            id: node.id,
            parent_id: node.parent_id,
            kind: node.kind.label(),
            path: result
                .display_path(node.id)
                .unwrap_or_else(|| node.name.clone()),
            logical_bytes: node.logical_size,
            allocated_bytes: node.allocated_size,
            files: node.file_count,
            directories: node.directory_count,
            modified_unix_ms: node.modified_unix_ms,
            symlink: node.is_symlink,
            mount_point: node.mount_point,
            hard_link_duplicate: node.hard_link_duplicate,
        })?;
    }
    writer.flush()?;
    Ok(())
}
