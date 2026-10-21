# Architecture

The browser is the only primary interface. A small native server owns the scan state and serves an embedded Svelte UI over a loopback HTTP API.

```text
                         ┌──────────────────┐
filesystem metadata ───▶ │    disk-core     │
                         │ traversal        │
                         │ platform sizes   │
                         │ aggregation      │
                         └────────┬─────────┘
                                  │ ScanProgress / ScanResult
                                  ▼
                         ┌──────────────────┐
                         │    disk-web      │
                         │ scan manager     │
                         │ JSON API         │
                         │ embedded UI      │
                         └────────┬─────────┘
                                  │ http://127.0.0.1
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
              Svelte browser UI          terminal progress
```

`apps/disk-cli` and `apps/disk-tui` reuse the same scanner for terminal-only workflows. They are not part of the npm release.

## Core scanning

`jwalk` performs bounded directory-level parallelism. The root node is inspected before traversal, ensuring that immediate cancellation still produces a valid partial result. Hidden entries are explicitly included. A directory callback prunes other filesystems and reacts to cancellation before more work is queued.

The scanner streams throttled `ScanProgress` snapshots to a caller-provided observer. Nodes are collected in depth-first order and directories are rolled up in one reverse pass. Raw path components remain as `OsString`, so non-UTF-8 Unix paths can still be reconstructed for native actions; user-facing strings use a lossy display representation.

The result builds a child index after aggregation. The API can navigate a directory without sending the entire node vector to the browser.

## Web server

`disk-web` is an Axum server with a single `ScanManager`. Starting a new scan cancels the previous generation. Every API request includes a scan ID, so stale browser requests cannot read a newer result.

The manager keeps:

- the active scan ID and cancellation token;
- the latest `ScanProgress`;
- an `Arc<ScanResult>` once complete;
- the error message from a failed scan.

The browser polls status while a scan is running, then requests pages of children, top files/directories, and error samples on demand. The full result never crosses the process boundary.

The UI is built with Vite and embedded into the binary with `rust-embed`. In release builds the assets are compiled in; debug builds read `ui-dist/` from disk so the normal UI dev server can be used.

## Terminal process

The npm launcher is a thin Node.js wrapper around the native binary. The binary prints the local URL, starts the initial scan, and renders progress to stderr only when it is attached to a terminal. stdout remains free for future machine-readable modes. The browser is opened with the `open` crate and can be disabled with `--no-open`.

## Security boundary

The server binds `127.0.0.1` and validates the `Host` header. Mutating endpoints reject non-loopback `Origin` headers, which blocks cross-site browser writes while still allowing the Vite dev server on another loopback port. Native actions (`open`/`reveal`) are restricted to paths in the active scan result. Nothing outside the scanned tree can be addressed through the API.

## Platform layer

`platform.rs` is the only module that interprets operating-system metadata. It handles `st_blocks` on Unix and `FILE_STANDARD_INFO.AllocationSize` on Windows, plus device/volume and file identity for mount and hard-link handling. Future fast paths—such as optional NTFS MFT enumeration—can implement the same result contract without changing the web UI, CLI, or TUI.
