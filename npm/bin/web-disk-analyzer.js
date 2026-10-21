#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const { resolveBinary } = require("../lib/platform");

function main() {
  let binary;
  try {
    binary = resolveBinary();
  } catch (error) {
    console.error(`\n  ${error.message}\n`);
    return 1;
  }

  const child = spawn(binary, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });

  child.on("error", (error) => {
    console.error(`\n  Could not start ${binary}: ${error.message}\n`);
    process.exitCode = 1;
  });

  child.on("exit", (code) => {
    process.exitCode = code ?? 1;
  });

  return 0;
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = { main };
