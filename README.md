# Disk Analyzer

A fast, accurate, cross-platform disk usage analyzer with a desktop GUI, terminal UI, and scriptable CLI. The scan engine is written in Rust and shared by every interface, so they all report the same results.

The original Python/Tkinter release remains in [`turbo_daddy.py`](turbo_daddy.py) while the Rust release is hardened.

## What changed

- Measures both logical content length and allocated filesystem blocks.
- Includes files directly inside the selected root.
- Aggregates every directory instead of retaining only a top-files heap.
- Detects sparse files, hard-link duplicates, symlinks, mount points, and scan errors.
- Uses bounded parallel directory traversal with configurable concurrency.
- Preserves partial results when canceled.
- Works on Windows, macOS, and Linux.
- Provides a paginated desktop browser, proportional space map, TUI, JSON, and CSV.

## Quick start

Rust 1.88 or newer is required.

### CLI

```bash
cargo run --release -p disk-analyzer-cli -- /path/to/scan
```

Useful examples:

```bash
# Sort by apparent content length
cargo run --release -p disk-analyzer-cli -- /home --size logical

# Machine-readable snapshot
cargo run --release -p disk-analyzer-cli -- /home --format json --quiet > scan.json

# Flat CSV containing every discovered entry
cargo run --release -p disk-analyzer-cli -- /home --format csv --quiet > scan.csv

# Cross mount points and use four scanner workers
cargo run --release -p disk-analyzer-cli -- / --cross-filesystems --threads 4
```

Run `cargo run -p disk-analyzer-cli -- --help` for all options.

### Terminal UI

```bash
cargo run --release -p disk-analyzer-tui -- /path/to/scan
```

The TUI works in Linux, macOS, Windows Terminal, and remote SSH sessions. Use arrows or `j`/`k` to move, `Enter` to descend, Backspace to go up, `/` to filter, `s` to switch size mode, and `?` for help.

### Desktop GUI

Install the [Tauri system prerequisites](https://v2.tauri.app/start/prerequisites/) for your operating system, then:

```bash
cd apps/disk-desktop
npm ci
npm run tauri dev
```

Build an installer or native bundle with:

```bash
npm run tauri build
```

On a rolling-release Linux host, build the native executable with
`npm run native:build`. Release AppImages are built on Ubuntu 22.04 in CI, as
recommended for compatibility with older Linux systems; building an AppImage
directly on Arch can outpace the older GTK tooling bundled by `linuxdeploy`.

The desktop UI keeps the complete result in Rust and requests only the current paginated directory view. A scan containing millions of files therefore does not become millions of JavaScript objects.

## Size terminology

| Metric | Meaning |
| --- | --- |
| Logical | File content length visible to applications. Hard-linked paths retain their individual logical lengths. |
| Allocated | Filesystem storage assigned to entries. Sparse files can use much less than their logical size. Hard-linked storage is counted once by default. |

Allocated totals use Unix `st_blocks × 512` and Windows `FILE_STANDARD_INFO.AllocationSize`. They include directory metadata reported by the filesystem. See [accuracy and filesystem semantics](docs/accuracy.md) for limitations involving snapshots, reflinks, reserved blocks, permissions, and files changing during a scan.

## Project structure

```text
crates/disk-core/                 Shared scanner and result model
apps/disk-cli/                    Human, JSON, and CSV interface
apps/disk-tui/                    Ratatui/Crossterm terminal interface
apps/disk-desktop/                Svelte frontend
apps/disk-desktop/src-tauri/      Native Tauri commands and scan state
```

See [architecture](docs/architecture.md) for the data flow and extension points.

## Verification

```bash
cargo fmt --all -- --check
cargo test --workspace --exclude disk-analyzer-desktop
cargo clippy --workspace --exclude disk-analyzer-desktop --all-targets -- -D warnings

cd apps/disk-desktop
npm ci
npm run check
npm run build
```

The core test suite covers root-level files, directory rollups, sparse files, hard links, symlink policy, single-file roots, and early or mid-scan cancellation. CI runs the Rust interfaces on Linux, Windows, and macOS and checks the native desktop backend on all three platforms.

## Safety

This release is read-only apart from explicitly requested exports. The interfaces can ask the operating system to open or reveal a result, but they do not delete files.
