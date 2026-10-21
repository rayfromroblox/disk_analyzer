# Distribution

The supported way to run Web Disk Analyzer is the npm package:

```bash
npx -y web-disk-analyzer
```

There is no desktop installer and no build step for users.

## Packages

| Package | Purpose |
| --- | --- |
| `web-disk-analyzer` | Node.js launcher, `web-disk-analyzer` and `webdisk` binaries |
| `web-disk-analyzer-darwin-arm64` | Native server for Apple Silicon |
| `web-disk-analyzer-darwin-x64` | Native server for Intel macOS |
| `web-disk-analyzer-linux-x64` | Native server for glibc x86-64 Linux |
| `web-disk-analyzer-linux-arm64` | Native server for glibc arm64 Linux |
| `web-disk-analyzer-win32-x64` | Native server for x64 Windows |
| `web-disk-analyzer-win32-arm64` | Native server for arm64 Windows |

The platform packages are declared as `optionalDependencies` of the launcher. npm installs only the package whose `os` and `cpu` fields match the current machine. The launcher then resolves the binary and spawns it with the user's arguments, inheriting the terminal so progress, the URL, and Ctrl+C all work normally.

No `postinstall` network download is involved. If the optional package is unavailable, the launcher prints an actionable error and accepts `WEB_DISK_ANALYZER_BIN` as an override.

## Release process

Pushing a tag such as `v1.2.0` starts `.github/workflows/release.yml`:

1. build the Svelte UI;
2. apply the tag version to Cargo, the UI manifest, and every npm manifest with `npm/scripts/set-version.mjs`;
3. build `disk-web` for each target;
4. copy each binary into its platform package and publish it;
5. publish the launcher;
6. attach the binaries to a GitHub Release.

The workflow needs an `NPM_TOKEN` repository secret. The npm account must be able to publish all package names in `npm/package.json` and `npm/platforms/*`.

The first release of a new package name must exist on npm or be published by the maintainer; npm does not support reserving names through this repository.

## Runtime and security

- The server binds `127.0.0.1`, never `0.0.0.0`.
- Requests with a non-loopback `Host` header are rejected (DNS-rebinding defense).
- Mutating requests with a foreign `Origin` header are rejected.
- The API exposes only paths that belong to the active in-memory scan.
- The UI is embedded in the native binary. There is no CDN, analytics, or remote asset loading.

## Linux compatibility

The Linux builds target glibc (Ubuntu 22.04 for x64, Ubuntu 24.04 for arm64). Alpine/musl and other libc variants are not currently packaged; use a glibc-based distribution or build from source.

## Manual installs

The launcher can run a locally built binary:

```bash
cargo build --release -p disk-web
WEB_DISK_ANALYZER_BIN="$PWD/target/release/web-disk-analyzer" node npm/bin/web-disk-analyzer.js
```

The native server can also be run directly and used without npm:

```bash
target/release/web-disk-analyzer ~/Downloads --no-open
```
