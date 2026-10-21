"use strict";

const fs = require("node:fs");
const path = require("node:path");

const PLATFORM_PACKAGES = {
  "darwin-arm64": {
    package: "web-disk-analyzer-darwin-arm64",
    executable: "web-disk-analyzer",
  },
  "darwin-x64": {
    package: "web-disk-analyzer-darwin-x64",
    executable: "web-disk-analyzer",
  },
  "linux-arm64": {
    package: "web-disk-analyzer-linux-arm64",
    executable: "web-disk-analyzer",
  },
  "linux-x64": {
    package: "web-disk-analyzer-linux-x64",
    executable: "web-disk-analyzer",
  },
  "win32-arm64": {
    package: "web-disk-analyzer-win32-arm64",
    executable: "web-disk-analyzer.exe",
  },
  "win32-x64": {
    package: "web-disk-analyzer-win32-x64",
    executable: "web-disk-analyzer.exe",
  },
};

function platformKey(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

function supportedPlatforms() {
  return Object.keys(PLATFORM_PACKAGES);
}

function resolveBinary(options = {}) {
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const env = options.env ?? process.env;
  const resolve = options.resolve ?? require.resolve;
  const exists = options.exists ?? fs.existsSync;

  if (env.WEB_DISK_ANALYZER_BIN) {
    return path.resolve(env.WEB_DISK_ANALYZER_BIN);
  }

  const key = platformKey(platform, arch);
  const entry = PLATFORM_PACKAGES[key];
  if (!entry) {
    throw new Error(
      `web-disk-analyzer does not have a prebuilt binary for ${key}. ` +
        `Supported platforms: ${supportedPlatforms().join(", ")}.`
    );
  }

  try {
    const manifest = resolve(`${entry.package}/package.json`, {
      paths: [path.join(__dirname, ".."), process.cwd()],
    });
    const binary = path.join(path.dirname(manifest), entry.executable);
    if (exists(binary)) return binary;
  } catch {
    // Fall through to the repository build output and the actionable error below.
  }

  for (const profile of ["release", "debug"]) {
    const local = path.resolve(
      __dirname,
      "..",
      "..",
      "target",
      profile,
      entry.executable
    );
    if (exists(local)) return local;
  }

  throw new Error(
    `The native binary package "${entry.package}" is missing. ` +
      `Reinstall without omitting optional dependencies, or set WEB_DISK_ANALYZER_BIN ` +
      `to a compiled web-disk-analyzer binary.`
  );
}

module.exports = { PLATFORM_PACKAGES, platformKey, resolveBinary, supportedPlatforms };
