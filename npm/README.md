# web-disk-analyzer

A private, local-first disk usage analyzer that runs in your browser.

```bash
npx -y web-disk-analyzer
```

The first run starts a local server, prints a URL, opens your browser, and scans the folder you launched it from. Requires [Node.js](https://nodejs.org) 18 or newer.

Pass a folder to scan it directly:

```bash
npx -y web-disk-analyzer ~/Downloads
npx -y web-disk-analyzer / --no-open
```

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

The server listens on `127.0.0.1` only. File names, sizes, and paths never leave your machine.

## What you can do

- Browse a directory tree with sizes rolled up from every child.
- Switch between **logical** size (content length) and **allocated** size (filesystem blocks actually used).
- Inspect the largest files and directories in one view.
- Sort, filter, and paginate directories without loading a giant tree into the browser.
- See skipped paths instead of silently hiding permission errors.
- Open or reveal any scanned entry in your native file manager.

## How it works

The command is a small Node.js launcher. It runs a prebuilt native binary for your platform, which serves the web UI and talks to the Rust scanning engine over a loopback-only HTTP API.
