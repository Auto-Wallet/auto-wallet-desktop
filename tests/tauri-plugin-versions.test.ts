import { expect, test } from "bun:test";

const manifest = await Bun.file("package.json").json();
const cargoLock = await Bun.file("src-tauri/Cargo.lock").text();
const bunLock = await Bun.file("bun.lock").text();

// Tauri checks the resolved JS/crate major and minor before any native build.
// Check all plugin pairs so a local frontend build cannot hide a release failure.
for (const name of Object.keys(manifest.dependencies)) {
  if (!name.startsWith("@tauri-apps/plugin-")) continue;
  const crate = name.replace("@tauri-apps/plugin-", "tauri-plugin-");
  test.each(["LF", "CRLF"])(`${name} matches the Rust plugin's major and minor release (%s)`, (lineEnding) => {
    const rustLock = lineEnding === "CRLF" ? cargoLock.replace(/\r?\n/g, "\r\n") : cargoLock.replace(/\r\n/g, "\n");
    const jsLock = lineEnding === "CRLF" ? bunLock.replace(/\r?\n/g, "\r\n") : bunLock.replace(/\r\n/g, "\n");
    const rustPackage = rustLock.split("[[package]]").find((block) =>
      block.split(/\r?\n/).includes(`name = "${crate}"`),
    );
    if (!rustPackage) throw new Error(`Missing Rust plugin: ${crate}`);
    const rustVersion = rustPackage.match(/\nversion = "(\d+)\.(\d+)\.\d+"/);
    const jsEntry = jsLock.split(/\r?\n/).find((line) => line.includes(`"${name}": ["${name}@`));
    if (!jsEntry) throw new Error(`Missing locked JS plugin: ${name}`);
    const jsVersion = jsEntry.match(/@(\d+)\.(\d+)\.\d+"/);
    if (!rustVersion || !jsVersion) throw new Error(`Invalid plugin version: ${name}`);
    expect(`${jsVersion[1]}.${jsVersion[2]}`).toBe(`${rustVersion[1]}.${rustVersion[2]}`);
  });
}

// GHSA-w28w-mhc8-qvjv: tauri <= 2.11.5 let one webview fetch another's queued
// channel responses. This app runs untrusted dApp pages in webviews next to the
// trusted wallet UI, so the lock must never fall back into that range.
test("tauri crate is at or past the GHSA-w28w-mhc8-qvjv fix (2.11.6)", () => {
  const block = cargoLock
    .replace(/\r\n/g, "\n")
    .split("[[package]]")
    .find((b) => b.split("\n").includes('name = "tauri"'));
  if (!block) throw new Error("tauri missing from Cargo.lock");
  const m = block.match(/\nversion = "(\d+)\.(\d+)\.(\d+)"/);
  if (!m) throw new Error("tauri version unreadable");
  const [major, minor, patch] = m.slice(1).map(Number);
  const atLeast = major > 2 || (major === 2 && (minor > 11 || (minor === 11 && patch >= 6)));
  expect(`${major}.${minor}.${patch} patched=${atLeast}`).toBe(`${major}.${minor}.${patch} patched=true`);
});
