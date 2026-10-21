"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  platformKey,
  resolveBinary,
  supportedPlatforms,
} = require("../lib/platform");

test("platformKey combines the Node platform and architecture", () => {
  assert.equal(platformKey("darwin", "arm64"), "darwin-arm64");
  assert.equal(platformKey("win32", "x64"), "win32-x64");
});

test("every supported platform has a package", () => {
  assert.deepEqual(supportedPlatforms(), [
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64",
    "linux-x64",
    "win32-arm64",
    "win32-x64",
  ]);
});

test("environment override wins", () => {
  const binary = resolveBinary({
    platform: "linux",
    arch: "x64",
    env: { WEB_DISK_ANALYZER_BIN: "/opt/tools/web-disk-analyzer" },
    resolve: () => {
      throw new Error("should not resolve a package");
    },
    exists: () => false,
  });
  assert.equal(binary, "/opt/tools/web-disk-analyzer");
});

test("resolves the platform package binary", () => {
  const manifest = "/tmp/node_modules/web-disk-analyzer-linux-x64/package.json";
  const binary = resolveBinary({
    platform: "linux",
    arch: "x64",
    env: {},
    resolve: (specifier) => {
      assert.equal(specifier, "web-disk-analyzer-linux-x64/package.json");
      return manifest;
    },
    exists: (candidate) => candidate === "/tmp/node_modules/web-disk-analyzer-linux-x64/web-disk-analyzer",
  });
  assert.equal(binary, "/tmp/node_modules/web-disk-analyzer-linux-x64/web-disk-analyzer");
});

test("rejects unsupported platforms with a useful message", () => {
  assert.throws(
    () => resolveBinary({ platform: "aix", arch: "ppc64", env: {} }),
    /does not have a prebuilt binary for aix-ppc64/
  );
});

test("explains how to recover when the optional package is missing", () => {
  assert.throws(
    () =>
      resolveBinary({
        platform: "linux",
        arch: "x64",
        env: {},
        resolve: () => {
          throw new Error("missing");
        },
        exists: () => false,
      }),
    /WEB_DISK_ANALYZER_BIN/
  );
});
