import { spawnSync } from "node:child_process";
import { expect, test } from "bun:test";
import {
  APP_EXE,
  AUTHENTICODE_VERIFY_PS,
  CODESIGNTOOL_VERSION,
  OTP_GAP_MS,
  delayBeforeNextSign,
  fileName,
  releaseSignLogError,
  shouldAuthenticodeSign,
  signerSubjectError,
  signingRequired,
  signingSecretsPresent,
  updaterSignatureFreshnessError,
} from "../scripts/sign-windows.ts";

test("signs the app exe, the NSIS setup, and an MSI, and skips everything else Tauri asks about", () => {
  expect(shouldAuthenticodeSign("D:\\a\\repo\\src-tauri\\target\\release\\auto-desktop.exe")).toBe(true);
  expect(shouldAuthenticodeSign("/src-tauri/target/release/auto-desktop.exe")).toBe(true);
  expect(shouldAuthenticodeSign("C:\\out\\AutoDesktop_0.2.86_x64-setup.exe")).toBe(true);
  expect(shouldAuthenticodeSign("C:\\out\\AutoDesktop_0.2.86_x64_en-US.msi")).toBe(true);

  expect(shouldAuthenticodeSign("C:\\nsis\\NSISdl.dll")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\nsis\\additional\\nsis_tauri_utils.dll")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\out\\uninstall.exe")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\temp\\MicrosoftEdgeWebview2Setup.exe")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\out\\WebView2Loader.dll")).toBe(false);
});

test("file names keep the last path segment on either separator", () => {
  expect(fileName("a/b\\c/auto-desktop.exe")).toBe("auto-desktop.exe");
  expect(fileName(APP_EXE)).toBe(APP_EXE);
});

test("signing is configured only when all four secrets are non-empty", () => {
  const full = {
    ES_USERNAME: "lin",
    ES_PASSWORD: "p",
    CREDENTIAL_ID: "cred",
    ES_TOTP_SECRET: "totp",
  };
  expect(signingSecretsPresent(full)).toBe(true);
  expect(signingSecretsPresent({ ...full, ES_PASSWORD: "" })).toBe(false);
  expect(signingSecretsPresent({ ...full, CREDENTIAL_ID: undefined })).toBe(false);
  expect(signingSecretsPresent({})).toBe(false);
  expect(signingRequired({ ESIGNER_REQUIRED: "true" })).toBe(true);
  expect(signingRequired({ ESIGNER_REQUIRED: "false" })).toBe(false);
  expect(signingRequired({})).toBe(false);
});

test("the next sign waits out the TOTP window that the previous sign consumed", () => {
  expect(delayBeforeNextSign(null, 1_000)).toBe(0);
  expect(delayBeforeNextSign(Number.NaN, 1_000)).toBe(0);
  expect(delayBeforeNextSign(0, 10_000)).toBe(OTP_GAP_MS - 10_000);
  expect(delayBeforeNextSign(0, OTP_GAP_MS)).toBe(0);
  expect(delayBeforeNextSign(0, OTP_GAP_MS + 5)).toBe(0);
});

test("a release sign log is the patched exe, the NSIS setup, then the portable exe", () => {
  const ok = [
    "D:\\a\\src-tauri\\target\\release\\auto-desktop.exe",
    "D:\\a\\src-tauri\\target\\release\\bundle\\nsis\\AutoDesktop_0.2.86_x64-setup.exe",
    "D:\\a\\src-tauri\\target\\release\\auto-desktop.exe",
    "",
  ];
  expect(releaseSignLogError(ok)).toBeNull();

  expect(releaseSignLogError(ok.slice(0, 2))).not.toBeNull();
  expect(
    releaseSignLogError([
      ...ok.slice(0, 3),
      "D:\\a\\src-tauri\\target\\release\\nsis\\x64\\Plugins\\NSISdl.dll",
    ]),
  ).not.toBeNull();
  expect(
    releaseSignLogError([
      ok[1]!,
      ok[0]!,
      ok[2]!,
    ]),
  ).not.toBeNull();
});

test("the signer subject must be the Personal ID CN", () => {
  expect(signerSubjectError("CN=Lin Mo, O=Lin Mo, C=US")).toBeNull();
  expect(signerSubjectError('CN="Lin Mo", O=Lin Mo, C=US')).toBeNull();
  expect(signerSubjectError("CN = Lin Mo")).toBeNull();
  expect(signerSubjectError("CN=Someone Else, O=Someone Else, C=US")).not.toBeNull();
  expect(signerSubjectError("CN=Lin Mo Extra, O=Lin Mo, C=US")).not.toBeNull();
});

test("the updater signature must be non-empty and not older than the signed installer", () => {
  expect(updaterSignatureFreshnessError(100, 100, 20)).toBeNull();
  expect(updaterSignatureFreshnessError(100, 150, 20)).toBeNull();
  expect(updaterSignatureFreshnessError(200, 150, 20)).not.toBeNull();
  expect(updaterSignatureFreshnessError(100, 150, 0)).not.toBeNull();
});

function runSigner(args: string[], env: Record<string, string | undefined>) {
  return spawnSync("bun", ["scripts/sign-windows.ts", ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

test("a missing secret skips signing unless the release asked for it", () => {
  const skipped = runSigner(["C:\\nsis\\NSISdl.dll"], { ESIGNER_REQUIRED: "true" });
  expect(skipped.status).toBe(0);
  expect(skipped.stdout).toContain("skip");

  const unsigned = runSigner(["target\\release\\auto-desktop.exe"], {
    ES_USERNAME: "",
    ES_PASSWORD: "",
    CREDENTIAL_ID: "",
    ES_TOTP_SECRET: "",
    ESIGNER_REQUIRED: "",
  });
  expect(unsigned.status).toBe(0);
  expect(unsigned.stdout).toContain("secrets missing");

  const required = runSigner(["target\\release\\auto-desktop.exe"], {
    ES_USERNAME: "",
    ES_PASSWORD: "",
    CREDENTIAL_ID: "",
    ES_TOTP_SECRET: "",
    ESIGNER_REQUIRED: "true",
  });
  expect(required.status).toBe(1);
  expect(required.stderr).toContain("ES_USERNAME");
});

test("verification script checks Authenticode status, a timestamp, and signtool /pa", () => {
  expect(AUTHENTICODE_VERIFY_PS).toContain("Get-AuthenticodeSignature");
  expect(AUTHENTICODE_VERIFY_PS).toContain("verify /pa /v");
  expect(AUTHENTICODE_VERIFY_PS).toContain("${env:ProgramFiles(x86)}");
  expect(AUTHENTICODE_VERIFY_PS).toContain("TIMESTAMP=present");
  expect(CODESIGNTOOL_VERSION).toBe("1.3.2");
});
