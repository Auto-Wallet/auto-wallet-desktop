// Authenticode signing for the manual Windows release build
// (.github/workflows/release-windows.yml).
//
// Tauri calls this once per file via bundle.windows.signCommand (%1 is the path).
// SSL.com eSigner's monthly plan allows 20 signings, and Tauri also asks to sign
// the NSIS plugin DLLs, resources and the generated uninstaller. Those are
// skipped. A Windows build signs exactly two files:
//   1. the patched auto-desktop.exe that NSIS embeds
//   2. the NSIS setup exe (the updater artifact)
// Each real signing waits out the previous TOTP window. eSigner rejects a reused
// one-time password, and CodeSignTool mints the password at the start of a sign.
//
// CodeSignTool v1.3.2 timestamps with the TSA_URL in its
// conf/code_sign_tool.properties (http://ts.ssl.com). It writes the signed bytes
// to a separate directory; this script copies them back onto the path Tauri is
// bundling, so the updater minisign is taken of the already-signed installer.
//
// Signing never falls back to "unsigned". A file that should be signed fails
// the build when any of ES_USERNAME, ES_PASSWORD, CREDENTIAL_ID, ES_TOTP_SECRET
// is missing, or when it runs in GitHub Actions outside a manual
// (workflow_dispatch) run, so no automatic trigger can spend the quota.
// CODESIGNTOOL_DIR is the unzipped CodeSignTool-v1.3.2-windows directory.
// ESIGNER_SIGN_LOG, when set, receives one absolute path per signing.

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
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

// The app executable and the NSIS installer. Everything else Tauri hands the
// sign command (NSIS plugin DLLs, the uninstaller temp file, resources) stays
// unsigned.
export function shouldAuthenticodeSign(filePath: string): boolean {
  const name = fileName(filePath);
  if (name.toLowerCase() === APP_EXE) return true;
  return /-setup\.exe$/i.test(name);
}

export function missingSigningSecrets(env: Env): string[] {
  return SECRET_KEYS.filter((key) => {
    const value = env[key];
    return typeof value !== "string" || value.length === 0;
  });
}

// Windows signing is manual-only. In GitHub Actions, anything other than a
// workflow_dispatch run (push, pull_request, schedule, tag) is refused before
// CodeSignTool is touched.
export function signingContextError(env: Env): string | null {
  if (env.GITHUB_ACTIONS !== "true") return null;
  if (env.GITHUB_EVENT_NAME === "workflow_dispatch") return null;
  return `Windows signing runs only from a manual workflow_dispatch run, not from "${env.GITHUB_EVENT_NAME}"`;
}

export function delayBeforeNextSign(lastStartedAtMs: number | null, now: number, gapMs = OTP_GAP_MS): number {
  if (lastStartedAtMs === null) return 0;
  return Math.max(0, lastStartedAtMs + gapMs - now);
}

// A Windows build log is exactly: patched app exe, then the NSIS setup.
// Any other file means Tauri started asking for another signing and the
// monthly quota was spent without a decision.
export function releaseSignLogError(lines: string[]): string | null {
  const files = lines.map((line) => line.trim()).filter((line) => line.length > 0);
  const names = files.map((file) => fileName(file).toLowerCase());
  if (names.length === 2 && names[0] === APP_EXE && /-setup\.exe$/.test(names[1]!)) return null;
  const rendered = files.length > 0 ? files.join("\n") : "(empty)";
  return `expected signed files in order: ${APP_EXE}, <product>-setup.exe\ngot:\n${rendered}`;
}

export function signerSubjectError(subject: string, expectedCn = EXPECTED_SIGNER_CN): string | null {
  const escaped = expectedCn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`(?:^|,\\s*)CN\\s*=\\s*"?${escaped}"?\\s*(?:,|$)`);
  if (pattern.test(subject)) return null;
  return `expected signer CN=${expectedCn} but certificate subject is: ${subject}`;
}

// --- Tauri updater (minisign) signature check --------------------------------
// Tauri stores both the public key (tauri.conf.json plugins.updater.pubkey) and
// each `<file>.sig` as base64 of a minisign text file. The signature is Ed25519
// over BLAKE2b-512(file) ("ED", prehashed) or over the file itself ("Ed"), plus
// a global Ed25519 signature over (signature || trusted comment).

function decodeTauriText(base64: string): string[] {
  return Buffer.from(base64.trim(), "base64").toString("utf8").split(/\r?\n/);
}

function decodeLine(line: string | undefined, what: string): Buffer {
  if (!line) throw new Error(`${what}: missing line`);
  return Buffer.from(line.trim(), "base64");
}

function ed25519Key(raw: Buffer): crypto.KeyObject {
  return crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

export function updaterSignatureError(file: Buffer, sigBase64: string, pubkeyBase64: string): string | null {
  const keyBytes = decodeLine(decodeTauriText(pubkeyBase64)[1], "public key");
  if (keyBytes.length !== 42 || keyBytes.subarray(0, 2).toString("latin1") !== "Ed") {
    return "public key is not a minisign Ed25519 key";
  }
  const keyId = keyBytes.subarray(2, 10);
  const publicKey = ed25519Key(keyBytes.subarray(10));

  const sigLines = decodeTauriText(sigBase64);
  const sigBytes = decodeLine(sigLines[1], "signature");
  if (sigBytes.length !== 74) return "signature has the wrong length";
  const algorithm = sigBytes.subarray(0, 2).toString("latin1");
  if (!sigBytes.subarray(2, 10).equals(keyId)) {
    return "signature was made by a different key than the updater pubkey";
  }
  const signature = sigBytes.subarray(10);

  let message: Buffer;
  if (algorithm === "ED") message = crypto.createHash("blake2b512").update(file).digest();
  else if (algorithm === "Ed") message = file;
  else return `unknown signature algorithm ${JSON.stringify(algorithm)}`;
  if (!crypto.verify(null, message, publicKey, signature)) {
    return "signature does not match the file (was it changed after signing?)";
  }

  const trustedPrefix = "trusted comment: ";
  const trustedLine = sigLines[2];
  if (!trustedLine?.startsWith(trustedPrefix)) return "signature has no trusted comment";
  const trustedComment = Buffer.from(trustedLine.slice(trustedPrefix.length), "utf8");
  const globalSignature = decodeLine(sigLines[3], "global signature");
  if (!crypto.verify(null, Buffer.concat([signature, trustedComment]), publicKey, globalSignature)) {
    return "trusted comment signature is invalid";
  }
  return null;
}

// --- Authenticode -------------------------------------------------------------

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
    if (!Number.isFinite(parsed)) fail(`corrupt TOTP stamp file ${stamp}`);
    last = parsed;
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

// Retries only a transient lock (antivirus or the bundler still holding the
// file); the last error is rethrown.
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

function codeSignTool(env: Env): { toolDir: string; java: string; jar: string } {
  const toolDir = env.CODESIGNTOOL_DIR;
  if (!toolDir) fail("CODESIGNTOOL_DIR is not set");
  const java = path.join(toolDir, "jdk-11.0.2", "bin", "java.exe");
  const jar = path.join(toolDir, "jar", `code_sign_tool-${CODESIGNTOOL_VERSION}.jar`);
  if (!fs.existsSync(java)) fail(`CodeSignTool java missing at ${java}`);
  if (!fs.existsSync(jar)) fail(`CodeSignTool jar missing at ${jar}`);
  return { toolDir, java, jar };
}

// `credential_info` returns the certificate behind CREDENTIAL_ID. It takes no
// one-time password and signs nothing, so it costs no quota: a wrong account,
// password, credential or certificate fails here, before tauri build signs.
export function subjectFromCredentialInfo(output: string): string {
  const match = output.match(/^[\s-]*Subject DN:[ \t]*(.+?)[ \t]*$/m);
  if (!match) throw new Error("credential_info output has no Subject DN");
  return match[1]!;
}

// Decides whether credential_info proved the account and certificate are right.
// CodeSignTool prints the certificate lines on stdout but writes its "executed
// successfully" line only to its log4j file, and it exits 0 even after printing
// "Error: ...". So the proof is a Subject DN on stdout whose CN is ours.
export function credentialInfoError(status: number | null, output: string): string | null {
  if (status !== 0) return `CodeSignTool credential_info failed (exit ${status})`;
  return signerSubjectError(subjectFromCredentialInfo(output));
}

function checkCredential(env: Env): void {
  const missing = missingSigningSecrets(env);
  if (missing.length > 0) fail(`cannot check the eSigner credential: missing ${missing.join(", ")}`);
  const { toolDir, java, jar } = codeSignTool(env);
  const result = spawnSync(
    java,
    [
      "-jar",
      jar,
      "credential_info",
      `-username=${env.ES_USERNAME}`,
      `-password=${env.ES_PASSWORD}`,
      `-credential_id=${env.CREDENTIAL_ID}`,
    ],
    { cwd: toolDir, encoding: "utf8", windowsHide: true },
  );
  const raw = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const shown = redact(raw, env);
  if (shown.trim()) console.log(shown.trim());
  if (result.error) fail(`could not start CodeSignTool: ${result.error.message}`);
  const error = credentialInfoError(result.status, raw);
  if (error) fail(error);
  console.log(`eSigner: credential OK, certificate is CN=${EXPECTED_SIGNER_CN}`);
}

// Tauri starts signCommand.cmd with CreateProcess: no shell, so it must be a
// real executable. npm's bun shims (bun.ps1, bun.cmd, a bash script) are not;
// the bun running this script is.
function writeTauriSignConfig(outPath: string): void {
  const bun = fs.realpathSync(process.execPath);
  if (process.platform === "win32" && !bun.toLowerCase().endsWith(".exe")) {
    fail(`bun is not running from an .exe (${bun}); Tauri could not start it`);
  }
  const script = fs.realpathSync(import.meta.path);
  const config = { bundle: { windows: { signCommand: { cmd: bun, args: [script, "%1"] } } } };
  fs.writeFileSync(outPath, JSON.stringify(config, null, 2));
  console.log(`signCommand: ${bun} ${script} %1 -> ${outPath}`);
}

function signFile(filePath: string, env: Env): void {
  const { toolDir, java, jar } = codeSignTool(env);
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
    // CodeSignTool exits 0 even after printing "Error: ...", so the exit code
    // proves nothing. SignCommand prints "Code signed successfully: <path>" to
    // stdout (System.out) right after sign() returns (checked in the v1.3.2
    // bytecode). Match it before redaction: a secret that happens to be a
    // substring of that line must not hide a successful sign.
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

  if (argv[0] === "--write-tauri-config") {
    const outPath = argv[1];
    if (!outPath) fail("--write-tauri-config needs an output path");
    writeTauriSignConfig(outPath);
    return;
  }

  if (argv[0] === "--check-credential") {
    checkCredential(env);
    return;
  }

  if (argv[0] === "--check-log") {
    const logPath = argv[1];
    if (!logPath) fail("--check-log needs a path");
    const error = releaseSignLogError(readLog(logPath));
    if (error) fail(error);
    console.log(`eSigner: sign log has exactly the two expected files (${logPath})`);
    return;
  }

  if (argv[0] === "--verify-updater-sig") {
    const [file, confPath] = argv.slice(1);
    if (!file || !confPath) fail("usage: --verify-updater-sig <file> <tauri.conf.json>");
    const sigPath = `${file}.sig`;
    if (!fs.existsSync(sigPath)) fail(`updater signature missing: ${sigPath}`);
    const conf = JSON.parse(fs.readFileSync(confPath, "utf8"));
    const pubkey = conf.plugins.updater.pubkey;
    if (typeof pubkey !== "string" || pubkey.length === 0) fail(`no plugins.updater.pubkey in ${confPath}`);
    const error = updaterSignatureError(fs.readFileSync(file), fs.readFileSync(sigPath, "utf8"), pubkey);
    if (error) fail(`${sigPath}: ${error}`);
    console.log(`updater: ${sigPath} is a valid signature of ${file} by the app's updater key`);
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
    console.log(`eSigner: skip ${filePath} (not the app exe or the installer)`);
    return;
  }

  const contextError = signingContextError(env);
  if (contextError) fail(contextError);

  const missing = missingSigningSecrets(env);
  if (missing.length > 0) {
    fail(`refusing to leave ${filePath} unsigned: missing ${missing.join(", ")}`);
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
