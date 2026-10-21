# Web Disk Analyzer

A private, local-first disk usage analyzer that runs in your browser. Start it from any terminal, in any directory:

```bash
npx -y web-disk-analyzer
```

That's it. The command starts a local server, prints a URL, opens your browser, and scans the folder you launched it from. No desktop app, installer, account, or cloud service. Your file names and sizes never leave your machine.

Requires [Node.js](https://nodejs.org) 18 or newer. The first run fetches a small prebuilt binary for your platform.

## Use a different folder

```bash
npx -y web-disk-analyzer ~/Downloads
npx -y web-disk-analyzer / --no-open
```

You can also edit the path in the UI or use the **…** button to open your system folder picker.

## Options

```
web-disk-analyzer [path] [options]

  -p, --port <port>    Port for the local server (default 4000; free port if busy)
      --no-open        Do not open the browser automatically
      --no-scan        Start the server without scanning immediately
  -j, --threads <n>    Scanner workers (0 chooses automatically)
      --follow-links   Follow symbolic links, with loop detection
      --cross-filesystems
                       Descend into mounted volumes and other filesystems
      --count-hard-links
                       Count each hard-link path as separately allocated storage
  -v, --version        Print the version
  -h, --help           Show help
```

The server listens on `127.0.0.1` only and rejects non-loopback hosts and cross-origin writes.

## What you can do

- **Browse the tree** — sizes roll up from every child, with pagination for very large directories.
- **Logical vs allocated** — switch between apparent content length and the filesystem blocks actually used. Sparse files, compression, hard links, and directory metadata are handled explicitly.
- **Space map** — a treemap of the largest children in the current directory.
- **Largest entries** — top 100 files and directories from anywhere in the scan.
- **Find errors** — every skipped or unreadable path is reported instead of hidden.
- **Native actions** — open or reveal any entry in your file manager.

## Development

Prerequisites: Rust 1.88+ and Node.js 18+.

```bash
# One-time frontend install
npm install --prefix apps/disk-web

# Build the web UI into apps/disk-web/ui-dist
npm run build --prefix apps/disk-web

# Run the server against a folder
cargo run -p disk-web -- . --no-open

# Or develop the UI with hot reload (API proxied to port 4000)
cargo run -p disk-web -- . --no-open --no-scan
npm run dev --prefix apps/disk-web
```

Useful checks:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm run check --prefix apps/disk-web
npm test --prefix npm
```

## Project layout

```text
crates/disk-core        Shared filesystem scanner and aggregation
apps/disk-web           Axum server, embedded UI assets, browser API
apps/disk-web/src       Svelte interface
apps/disk-cli           Optional human/JSON/CSV terminal output
apps/disk-tui           Optional Ratatui interface
npm                     Published npx launcher and platform packages
```

The npm package only contains the launcher. Platform binaries are published as optional dependencies, so npm downloads just the one that matches your OS and architecture.

## Publishing

Pushing a `v*` tag runs `.github/workflows/release.yml`, which:

1. builds the UI and native server for macOS (arm64/x64), Linux (x64/arm64), and Windows (x64/arm64);
2. publishes the matching platform package to npm;
3. publishes the `web-disk-analyzer` launcher;
4. attaches the raw binaries to a GitHub Release.

Add an `NPM_TOKEN` repository secret with publish access. The tag version is applied to Cargo and npm by `npm/scripts/set-version.mjs`.

## License

MIT
