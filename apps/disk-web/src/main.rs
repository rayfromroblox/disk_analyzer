use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use disk_web::{AppState, StartScanRequest, router};
use tokio::net::TcpListener;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "web-disk-analyzer",
    version,
    about = "Analyze disk usage in your browser. Runs locally from any directory."
)]
struct Args {
    /// Directory to scan. Defaults to the current directory.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Port for the local web server. A free port is chosen if this one is busy.
    #[arg(short = 'p', long, default_value_t = 4000)]
    port: u16,

    /// Do not open the browser automatically.
    #[arg(long)]
    no_open: bool,

    /// Start the server without immediately scanning the directory.
    #[arg(long)]
    no_scan: bool,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cwd = std::env::current_dir().context("could not determine the current directory")?;
    let requested = if args.path.is_absolute() {
        args.path.clone()
    } else {
        cwd.join(&args.path)
    };
    let startup_path = std::fs::canonicalize(&requested)
        .with_context(|| format!("cannot open {}", requested.display()))?;
    if !startup_path.is_dir() {
        bail!("{} is not a directory", startup_path.display());
    }

    let (listener, fallback) = bind_listener(args.port).await?;
    let port = listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{port}");
    let state = AppState::new(
        VERSION,
        startup_path.to_string_lossy().into_owned(),
        cwd.to_string_lossy().into_owned(),
    );

    println!();
    println!("  web-disk-analyzer {VERSION}");
    println!("  Local: {url}");
    if fallback {
        println!("  Port {} was busy, so a free port was used.", args.port);
    }
    println!("  Press Ctrl+C to stop.");
    println!();

    if !args.no_scan {
        let mut request = StartScanRequest::new(startup_path.to_string_lossy().into_owned());
        request.threads = args.threads;
        request.follow_symlinks = args.follow_links;
        request.stay_on_filesystem = !args.cross_filesystems;
        request.deduplicate_hard_links = !args.count_hard_links;
        if let Err(error) = state.manager.start(request) {
            eprintln!("  Could not start the scan: {}", error.message());
        }
    }

    if !args.no_open {
        let browser_url = url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            if let Err(error) = open::that(&browser_url) {
                eprintln!("  Could not open the browser automatically: {error}");
                eprintln!("  Open {browser_url} manually.");
            }
        });
    }

    let shutdown = state.manager.clone();
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.cancel_active();
        })
        .await
        .context("web server failed")?;

    Ok(())
}

async fn bind_listener(port: u16) -> Result<(TcpListener, bool)> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => Ok((listener, false)),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .context("could not find a free local port")?;
            Ok((listener, true))
        }
        Err(error) => Err(error).with_context(|| format!("could not listen on port {port}")),
    }
}
