import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const version = (process.argv[2] ?? "").replace(/^v/, "");
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error("Usage: node npm/scripts/set-version.mjs <version>");
  process.exit(1);
}

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const npmRoot = path.resolve(scriptDirectory, "..");
const repositoryRoot = path.resolve(npmRoot, "..");

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

const mainManifestPath = path.join(npmRoot, "package.json");
const mainManifest = JSON.parse(fs.readFileSync(mainManifestPath, "utf8"));
mainManifest.version = version;
for (const dependency of Object.keys(mainManifest.optionalDependencies ?? {})) {
  mainManifest.optionalDependencies[dependency] = version;
}
writeJson(mainManifestPath, mainManifest);

const platforms = path.join(npmRoot, "platforms");
for (const platform of fs.readdirSync(platforms)) {
  const manifestPath = path.join(platforms, platform, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  manifest.version = version;
  writeJson(manifestPath, manifest);
}

const uiManifestPath = path.join(repositoryRoot, "apps", "disk-web", "package.json");
if (fs.existsSync(uiManifestPath)) {
  const uiManifest = JSON.parse(fs.readFileSync(uiManifestPath, "utf8"));
  uiManifest.version = version;
  writeJson(uiManifestPath, uiManifest);
}

const cargoPath = path.join(repositoryRoot, "Cargo.toml");
const cargo = fs.readFileSync(cargoPath, "utf8");
const updatedCargo = cargo.replace(
  /(\[workspace\.package\][\s\S]*?\nversion\s*=\s*")[^"]+(")/,
  (_match, prefix, suffix) => `${prefix}${version}${suffix}`
);
if (!updatedCargo.includes(`[workspace.package]`) || !updatedCargo.includes(`version = "${version}"`)) {
  console.error("Could not find workspace.package.version in Cargo.toml");
  process.exit(1);
}
fs.writeFileSync(cargoPath, updatedCargo);

console.log(`Set web-disk-analyzer version to ${version}`);
