// Authenticode signing for the Windows release build.
//
// Tauri calls this once per file via bundle.windows.signCommand (%1 is the path).
// SSL.com eSigner's monthly plan allows 20 signings, and Tauri also asks to sign
// the NSIS plugin DLLs and the generated uninstaller. Those are skipped. A
// release signs three files:
//   1. the patched auto-desktop.exe that NSIS embeds
//   2. the NSIS setup exe (the updater artifact)
//   3. the restored auto-desktop.exe that the portable zip ships
// Each real signing waits out the previous TOTP window. eSigner rejects a reused
// one-time password, and CodeSignTool mints the password at the start of a sign.
//
// CodeSignTool v1.3.2 (the build SSLcom/esigner-codesign downloads) timestamps
// with the TSA_URL in its conf/code_sign_tool.properties (http://ts.ssl.com).
// It writes the signed bytes to a separate directory; this script copies them
// back onto the path Tauri is bundling so the updater minisign is taken of the
// already-signed installer.
//
// Secrets (all four required, otherwise the file is left unsigned):
//   ES_USERNAME, ES_PASSWORD, CREDENTIAL_ID, ES_TOTP_SECRET
// CODESIGNTOOL_DIR is the unzipped CodeSignTool-v1.3.2-windows directory.
// ESIGNER_REQUIRED=true turns a missing secret or a failed sign into a hard
// error. Without it, a missing secret exits 0 so a fork build still packages.
// ESIGNER_SIGN_LOG, when set, receives one absolute path per signing.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const CODESIGNTOOL_VERSION = "1.3.2";
export const APP_EXE = "auto-desktop.exe";
export const EXPECTED_SIGNER_CN = "Lin Mo";
export const OTP_GAP_MS = 31_000;

const SECRET_KEYS = ["ES_USERNAME", "ES_PASSWORD", "CREDENTIAL_ID", "ES_TOTP_SECRET"] as const;

type Env = Record<string, string | undefined>;

export function fileName(filePath: string): string {
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] ?? filePath;
}

// The app executable and the installers Tauri actually ships. Everything else
// Tauri hands the sign command (NSIS plugin DLLs, uninstall.exe, WebView2
// loaders) stays unsigned.
export function shouldAuthenticodeSign(filePath: string): boolean {
  const name = fileName(filePath);
  if (name.toLowerCase() === APP_EXE) return true;
  if (/-setup\.exe$/i.test(name)) return true;
  if (/\.msi$/i.test(name)) return true;
  return false;
}

export function signingSecretsPresent(env: Env): boolean {
  return SECRET_KEYS.every((key) => {
    const value = env[key];
    return typeof value === "string" && value.length > 0;
  });
}

export function signingRequired(env: Env): boolean {
  return env.ESIGNER_REQUIRED === "true";
}

export function delayBeforeNextSign(lastStartedAtMs: number | null, now: number, gapMs = OTP_GAP_MS): number {
  if (lastStartedAtMs == null || !Number.isFinite(lastStartedAtMs)) return 0;
  return Math.max(0, lastStartedAtMs + gapMs - now);
}

// A Windows release log is exactly: patched exe, NSIS setup, portable exe.
// Any other file means Tauri started asking for another signing and the
// monthly quota would be spent without a decision.
export function releaseSignLogError(lines: string[]): string | null {
  const files = lines.map((line) => line.trim()).filter((line) => line.length > 0);
  const names = files.map((file) => fileName(file).toLowerCase());
  const expected = [APP_EXE, null, APP_EXE];
  const setupOk = names.length === 3 && /-setup\.exe$/i.test(names[1] ?? "");
  const exesOk = names.length === 3 && names[0] === expected[0] && names[2] === expected[2];
  if (setupOk && exesOk) return null;
  const rendered = files.length > 0 ? files.join("\n") : "(empty)";
  return `expected signed files in order: ${APP_EXE}, <product>-setup.exe, ${APP_EXE}\ngot:\n${rendered}`;
}

export function signerSubjectError(subject: string, expectedCn = EXPECTED_SIGNER_CN): string | null {
  const escaped = expectedCn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`CN\\s*=\\s*"?${escaped}"?(?:,|$)`);
  if (pattern.test(subject)) return null;
  return `expected signer CN=${expectedCn} but certificate subject is: ${subject}`;
}

export function updaterSignatureFreshnessError(
  installerMtimeMs: number,
  sigMtimeMs: number,
  sigBytes: number,
): string | null {
  if (sigBytes <= 0) return "updater signature file is empty";
  if (installerMtimeMs > sigMtimeMs) {
    return "installer was modified after its updater signature was written";
  }
  return null;
}

function sleepSync(ms: number): void {
  if (ms <= 0) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function fail(message: string): never {
  throw new Error(message);
}

function redact(text: string, env: Env): string {
  let out = text;
  for (const key of SECRET_KEYS) {
    const secret = env[key];
    if (secret) out = out.split(secret).join("***");
  }
  return out;
}

function stampPath(env: Env): string {
  const root = env.RUNNER_TEMP || os.tmpdir();
  return path.join(root, "autodesktop-esigner-otp-started-at");
}

function reserveOtpSlot(env: Env): void {
  const stamp = stampPath(env);
  let last: number | null = null;
  if (fs.existsSync(stamp)) {
    const parsed = Number(fs.readFileSync(stamp, "utf8").trim());
    last = Number.isFinite(parsed) ? parsed : null;
  }
  const wait = delayBeforeNextSign(last, Date.now());
  if (wait > 0) {
    console.log(`eSigner: waiting ${Math.ceil(wait / 1000)}s for a fresh TOTP window`);
    sleepSync(wait);
  }
  fs.mkdirSync(path.dirname(stamp), { recursive: true });
  fs.writeFileSync(stamp, String(Date.now()));
}

function findSignedCopy(outDir: string, originalName: string): string {
  const direct = path.join(outDir, originalName);
  if (fs.existsSync(direct)) return direct;
  const stack = [outDir];
  const want = originalName.toLowerCase();
  while (stack.length > 0) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.name.toLowerCase() === want) return full;
    }
  }
  const listing = fs.readdirSync(outDir).join(", ") || "(empty)";
  throw new Error(`CodeSignTool wrote no ${originalName} in ${outDir} (${listing})`);
}

function replaceFile(from: string, to: string): void {
  let last: unknown;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      fs.copyFileSync(from, to);
      return;
    } catch (error) {
      last = error;
      sleepSync(400);
    }
  }
  throw last;
}

// PowerShell 5.1. Kept as a double-quoted JS string so `${...}` is literal
// PowerShell and not interpolated. `\\` in those strings is one backslash.
export const AUTHENTICODE_VERIFY_PS = [
  "$ErrorActionPreference = 'Stop'",
  "$path = $env:SIGN_TARGET",
  "if (-not (Test-Path -LiteralPath $path)) { Write-Error \"missing $path\"; exit 1 }",
  "$sig = Get-AuthenticodeSignature -LiteralPath $path",
  "Write-Output ('STATUS=' + [string]$sig.Status)",
  "Write-Output ('STATUS_MESSAGE=' + [string]$sig.StatusMessage)",
  "if ($sig.SignerCertificate) { Write-Output ('SUBJECT=' + $sig.SignerCertificate.Subject) } else { Write-Output 'SUBJECT=' }",
  "if ($sig.TimeStamperCertificate) {",
  "  Write-Output 'TIMESTAMP=present'",
  "  Write-Output ('TIMESTAMP_SUBJECT=' + $sig.TimeStamperCertificate.Subject)",
  "} else { Write-Output 'TIMESTAMP=missing' }",
  "if ($sig.Status -ne 'Valid') { exit 1 }",
  "if (-not $sig.TimeStamperCertificate) { exit 1 }",
  "$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\\10\\bin'",
  "$tool = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |",
  "  Where-Object { $_.FullName -match '\\\\x64\\\\signtool\\.exe$' } |",
  "  Sort-Object FullName -Descending | Select-Object -First 1",
  "if (-not $tool) { Write-Error \"signtool.exe not found under $kits\"; exit 1 }",
  "Write-Output ('SIGNTOOL=' + $tool.FullName)",
  "& $tool.FullName verify /pa /v $path",
  "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
  "exit 0",
].join("\n");

function outputField(output: string, name: string): string {
  const prefix = `${name}=`;
  const line = output.split(/\r?\n/).find((entry) => entry.startsWith(prefix));
  return line ? line.slice(prefix.length).trim() : "";
}

function verifyAuthenticode(filePath: string): void {
  const ps1 = path.join(os.tmpdir(), `autodesktop-authenticode-${process.pid}.ps1`);
  fs.writeFileSync(ps1, AUTHENTICODE_VERIFY_PS, "utf8");
  try {
    const result = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ps1],
      {
        env: { ...process.env, SIGN_TARGET: filePath },
        encoding: "utf8",
        windowsHide: true,
      },
    );
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    if (output.trim()) console.log(output.trim());
    if (result.error) fail(`could not run powershell.exe: ${result.error.message}`);
    if (result.status !== 0) fail(`Authenticode verification failed for ${filePath}`);
    if (outputField(output, "TIMESTAMP") !== "present") fail(`${filePath} has no Authenticode timestamp`);
    const subjectError = signerSubjectError(outputField(output, "SUBJECT"));
    if (subjectError) fail(subjectError);
  } finally {
    fs.rmSync(ps1, { force: true });
  }
}

function signFile(filePath: string, env: Env): void {
  const toolDir = env.CODESIGNTOOL_DIR;
  if (!toolDir) fail("CODESIGNTOOL_DIR is not set");
  const java = path.join(toolDir, "jdk-11.0.2", "bin", "java.exe");
  const jar = path.join(toolDir, "jar", `code_sign_tool-${CODESIGNTOOL_VERSION}.jar`);
  if (!fs.existsSync(java)) fail(`CodeSignTool java missing at ${java}`);
  if (!fs.existsSync(jar)) fail(`CodeSignTool jar missing at ${jar}`);
  if (!fs.existsSync(filePath)) fail(`file to sign does not exist: ${filePath}`);

  reserveOtpSlot(env);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "esigner-out-"));
  try {
    const args = [
      "-jar",
      jar,
      "sign",
      `-username=${env.ES_USERNAME}`,
      `-password=${env.ES_PASSWORD}`,
      `-credential_id=${env.CREDENTIAL_ID}`,
      `-totp_secret=${env.ES_TOTP_SECRET}`,
      `-input_file_path=${filePath}`,
      `-output_dir_path=${outDir}`,
    ];
    console.log(`eSigner: signing ${filePath}`);
    const result = spawnSync(java, args, {
      cwd: toolDir,
      encoding: "utf8",
      windowsHide: true,
    });
    const raw = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    const combined = redact(raw, env);
    if (combined.trim()) console.log(combined.trim());
    if (result.error) fail(`could not start CodeSignTool: ${result.error.message}`);
    // Match the tool's own success line before redaction. A secret that happens
    // to be a substring of that line must not hide a successful sign.
    if (result.status !== 0 || !/code signed successfully/i.test(raw)) {
      fail(`CodeSignTool failed for ${filePath} (exit ${result.status})`);
    }
    const signed = findSignedCopy(outDir, fileName(filePath));
    replaceFile(signed, filePath);
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }

  verifyAuthenticode(filePath);
  const log = env.ESIGNER_SIGN_LOG;
  if (log) {
    fs.appendFileSync(log, `${path.resolve(filePath)}\n`);
  }
  console.log(`eSigner: signed and verified ${filePath}`);
}

function readLog(logPath: string): string[] {
  if (!fs.existsSync(logPath)) return [];
  return fs.readFileSync(logPath, "utf8").split(/\r?\n/);
}

function main(): void {
  const argv = process.argv.slice(2);
  const env = process.env;

  if (argv[0] === "--check-log") {
    const logPath = argv[1];
    if (!logPath) fail("--check-log needs a path");
    const error = releaseSignLogError(readLog(logPath));
    if (error) fail(error);
    console.log(`eSigner: sign log has the three release files (${logPath})`);
    return;
  }

  if (argv[0] === "--check-updater-sig") {
    const installer = argv[1];
    if (!installer) fail("--check-updater-sig needs the installer path");
    const sigPath = `${installer}.sig`;
    if (!fs.existsSync(installer)) fail(`installer missing: ${installer}`);
    if (!fs.existsSync(sigPath)) fail(`updater signature missing: ${sigPath}`);
    const installerStat = fs.statSync(installer);
    const sigStat = fs.statSync(sigPath);
    const error = updaterSignatureFreshnessError(installerStat.mtimeMs, sigStat.mtimeMs, sigStat.size);
    if (error) fail(`${error} (${sigPath})`);
    console.log(`eSigner: updater signature ${sigPath} matches the signed installer`);
    return;
  }

  if (argv[0] === "--verify") {
    const filePath = argv[1];
    if (!filePath) fail("--verify needs a path");
    verifyAuthenticode(filePath);
    console.log(`eSigner: verified ${filePath}`);
    return;
  }

  const filePath = argv[0];
  if (!filePath || filePath.startsWith("--")) fail("usage: bun scripts/sign-windows.ts <file>");

  if (!shouldAuthenticodeSign(filePath)) {
    console.log(`eSigner: skip ${filePath} (not the app exe or an installer)`);
    return;
  }

  if (!signingSecretsPresent(env)) {
    if (signingRequired(env)) {
      fail(`refusing to leave ${filePath} unsigned: set ES_USERNAME, ES_PASSWORD, CREDENTIAL_ID, and ES_TOTP_SECRET`);
    }
    console.log(`eSigner: secrets missing, leaving unsigned: ${filePath}`);
    return;
  }

  signFile(filePath, env);
}

if (import.meta.main) {
  try {
    main();
  } catch (error) {
    console.error(`eSigner: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}
