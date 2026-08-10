# Architecture

All interfaces call the same synchronous scan API from `disk-core`.

```text
                         ┌──────────────────┐
filesystem metadata ───▶ │    disk-core     │
                         │ traversal        │
                         │ platform sizes   │
                         │ aggregation      │
                         └────────┬─────────┘
                                  │ ScanProgress / ScanResult
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
          disk-analyzer    disk-analyzer-tui   Tauri commands
          human/json/csv      Ratatui UI            │
                                                    ▼
                                              Svelte desktop
```

## Core scanning

`jwalk` performs bounded directory-level parallelism. The root node is inspected before traversal, ensuring that immediate cancellation still produces a valid partial result. Hidden entries are explicitly included. A directory callback prunes other filesystems and reacts to cancellation before more work is queued.

The scanner streams throttled `ScanProgress` snapshots to a caller-provided observer. Nodes are collected in depth-first order and directories are rolled up in one reverse pass. Raw path components remain as `OsString`, so non-UTF-8 Unix paths can still be reconstructed for native actions; user-facing strings use a lossy display representation.

The result builds a child index after aggregation. Interfaces can navigate a directory without scanning the entire node vector.

## Desktop boundary

The Tauri process owns `Arc<ScanResult>` and exposes commands for status, paginated children, largest entries, errors, and native open/reveal operations. The Svelte webview never receives the full snapshot unless a future export feature explicitly requests it.

Starting a new scan cancels the previous generation. Every command includes a scan ID, preventing stale frontend requests from reading a newer result.

## Platform layer

`platform.rs` is the only module that interprets operating-system metadata. Future fast paths—such as optional NTFS MFT enumeration—can implement the same result contract without changing the GUI, TUI, or CLI.

