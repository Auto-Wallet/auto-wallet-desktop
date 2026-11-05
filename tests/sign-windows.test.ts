import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "bun:test";
import {
  APP_EXE,
  CODESIGNTOOL_VERSION,
  OTP_GAP_MS,
  delayBeforeNextSign,
  fileName,
  missingSigningSecrets,
  releaseSignLogError,
  shouldAuthenticodeSign,
  signerSubjectError,
  signingContextError,
  updaterSignatureError,
} from "../scripts/sign-windows.ts";

const ROOT = path.resolve(import.meta.dir, "..");
const WORKFLOWS = path.join(ROOT, ".github", "workflows");
const FIXTURE = path.join(ROOT, "tests", "fixtures", "updater-sig");
const FULL_SECRETS = {
  ES_USERNAME: "lin",
  ES_PASSWORD: "p4ss",
  CREDENTIAL_ID: "cred-1",
  ES_TOTP_SECRET: "totp-secret",
};

function readWorkflow(name: string): { text: string; parsed: any } {
  const text = fs.readFileSync(path.join(WORKFLOWS, name), "utf8");
  return { text, parsed: Bun.YAML.parse(text) };
}

// --- which files spend a signing ---------------------------------------------

test("signs only the app exe and the NSIS setup; skips everything else Tauri asks about", () => {
  expect(shouldAuthenticodeSign("D:\\a\\repo\\src-tauri\\target\\release\\auto-desktop.exe")).toBe(true);
  expect(shouldAuthenticodeSign("/src-tauri/target/release/AUTO-DESKTOP.EXE")).toBe(true);
  expect(shouldAuthenticodeSign("C:\\out\\AutoDesktop_0.2.86_x64-setup.exe")).toBe(true);

  expect(shouldAuthenticodeSign("C:\\out\\AutoDesktop_0.2.86_x64_en-US.msi")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\nsis\\NSISdl.dll")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\nsis\\additional\\nsis_tauri_utils.dll")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\Users\\r\\AppData\\Local\\Temp\\nsa1B2C.tmp")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\out\\uninstall.exe")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\temp\\MicrosoftEdgeWebview2Setup.exe")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\out\\WebView2Loader.dll")).toBe(false);
  expect(shouldAuthenticodeSign("C:\\out\\not-auto-desktop.exe")).toBe(false);
});

test("file names keep the last path segment on either separator", () => {
  expect(fileName("a/b\\c/auto-desktop.exe")).toBe("auto-desktop.exe");
  expect(fileName(APP_EXE)).toBe(APP_EXE);
});

test("missing secrets are named, empty counts as missing", () => {
  expect(missingSigningSecrets(FULL_SECRETS)).toEqual([]);
  expect(missingSigningSecrets({ ...FULL_SECRETS, ES_PASSWORD: "" })).toEqual(["ES_PASSWORD"]);
  expect(missingSigningSecrets({ ...FULL_SECRETS, CREDENTIAL_ID: undefined, ES_TOTP_SECRET: "" })).toEqual([
    "CREDENTIAL_ID",
    "ES_TOTP_SECRET",
  ]);
  expect(missingSigningSecrets({})).toEqual(["ES_USERNAME", "ES_PASSWORD", "CREDENTIAL_ID", "ES_TOTP_SECRET"]);
});

test("in GitHub Actions only a manual workflow_dispatch run may sign", () => {
  expect(signingContextError({})).toBeNull();
  expect(signingContextError({ GITHUB_ACTIONS: "true", GITHUB_EVENT_NAME: "workflow_dispatch" })).toBeNull();
  for (const event of ["push", "pull_request", "schedule", "workflow_run", "release"]) {
    const error = signingContextError({ GITHUB_ACTIONS: "true", GITHUB_EVENT_NAME: event });
    expect(error).toContain(`"${event}"`);
    expect(error).toContain("workflow_dispatch");
  }
});

test("the next sign waits out the TOTP window that the previous sign consumed", () => {
  expect(delayBeforeNextSign(null, 1_000)).toBe(0);
  for (let i = 0; i < 20; i++) {
    const last = Math.floor(Math.random() * 1e12);
    const elapsed = Math.floor(Math.random() * OTP_GAP_MS * 2);
    expect(delayBeforeNextSign(last, last + elapsed)).toBe(Math.max(0, OTP_GAP_MS - elapsed));
  }
  expect(delayBeforeNextSign(5_000, 5_000 + OTP_GAP_MS)).toBe(0);
  expect(delayBeforeNextSign(5_000, 5_000 + OTP_GAP_MS - 1)).toBe(1);
});

test("a build's sign log is exactly the patched exe, then the NSIS setup", () => {
  const exe = "D:\\a\\src-tauri\\target\\release\\auto-desktop.exe";
  const setup = "D:\\a\\src-tauri\\target\\release\\bundle\\nsis\\AutoDesktop_0.2.86_x64-setup.exe";
  expect(releaseSignLogError([exe, setup, ""])).toBeNull();

  // The old portable-zip flow signed a third file; that is quota we no longer spend.
  expect(releaseSignLogError([exe, setup, exe])).toContain("got:");
  expect(releaseSignLogError([exe])).toContain(exe);
  expect(releaseSignLogError([setup, exe])).toContain("in order");
  expect(releaseSignLogError([exe, setup, "D:\\a\\nsis\\Plugins\\NSISdl.dll"])).toContain("NSISdl.dll");
  expect(releaseSignLogError([])).toContain("(empty)");
});

test("the signer subject must carry CN=Lin Mo as its own RDN", () => {
  expect(signerSubjectError("CN=Lin Mo, O=Lin Mo, C=US")).toBeNull();
  expect(signerSubjectError('CN="Lin Mo", O=Lin Mo, C=US')).toBeNull();
  expect(signerSubjectError("O=Lin Mo, CN=Lin Mo")).toBeNull();
  expect(signerSubjectError("CN = Lin Mo")).toBeNull();
  expect(signerSubjectError("CN=Someone Else, O=Someone Else, C=US")).toContain("Someone Else");
  expect(signerSubjectError("CN=Lin Mo Extra, O=Lin Mo, C=US")).toContain("Lin Mo Extra");
  expect(signerSubjectError("CN=Evil, OU=xCN=Lin Mo")).toContain("CN=Evil");
  expect(signerSubjectError("")).toContain("certificate subject is: ");
});

// --- updater (minisign) signature --------------------------------------------
// The fixture was produced by `tauri signer generate` + `tauri signer sign`
// with a throwaway key whose private half was discarded.

const fixturePayload = () => fs.readFileSync(path.join(FIXTURE, "payload.bin"));
const fixtureSig = () => fs.readFileSync(path.join(FIXTURE, "payload.bin.sig"), "utf8");
const fixturePubkey = () => fs.readFileSync(path.join(FIXTURE, "test.key.pub"), "utf8").trim();
const appPubkey = () =>
  JSON.parse(fs.readFileSync(path.join(ROOT, "src-tauri", "tauri.conf.json"), "utf8")).plugins.updater.pubkey;

test("a real Tauri updater signature verifies against its key", () => {
  expect(updaterSignatureError(fixturePayload(), fixtureSig(), fixturePubkey())).toBeNull();
});

test("an updater signature fails if any byte of the file changed", () => {
  const original = fixturePayload();
  for (let i = 0; i < 5; i++) {
    const tampered = Buffer.from(original);
    const at = crypto.randomInt(tampered.length);
    tampered[at] = tampered[at]! ^ (1 + crypto.randomInt(255));
    expect(updaterSignatureError(tampered, fixtureSig(), fixturePubkey())).toContain("does not match the file");
  }
  expect(updaterSignatureError(Buffer.concat([original, Buffer.from([0])]), fixtureSig(), fixturePubkey())).toContain(
    "does not match the file",
  );
});

test("an updater signature from another key is rejected (the app's real pubkey)", () => {
  expect(updaterSignatureError(fixturePayload(), fixtureSig(), appPubkey())).toContain("different key");
});

test("a forged trusted comment is rejected", () => {
  const lines = Buffer.from(fixtureSig(), "base64").toString("utf8").split("\n");
  lines[2] = lines[2]!.replace("file:payload.bin", "file:other.bin");
  const forged = Buffer.from(lines.join("\n"), "utf8").toString("base64");
  expect(updaterSignatureError(fixturePayload(), forged, fixturePubkey())).toContain("trusted comment");
});

// --- workflow policy: Windows packaging and signing are manual only ----------

test("release-windows.yml runs only on workflow_dispatch and keeps secrets behind the environment", () => {
  const { parsed } = readWorkflow("release-windows.yml");
  expect(Object.keys(parsed.on)).toEqual(["workflow_dispatch"]);
  expect(parsed.concurrency["cancel-in-progress"]).toBe(false);
  expect(parsed.jobs.build.environment).toBe("windows-signing");
  expect(parsed.jobs.build.needs).toBe("preflight");
  // Only the publish job, which holds no signing secrets, may write the release.
  expect(parsed.permissions).toEqual({ contents: "read" });
  expect(parsed.jobs.publish.permissions).toEqual({ contents: "write" });
  expect(JSON.stringify(parsed.jobs.publish)).not.toContain("ES_");
  expect(JSON.stringify(parsed.jobs.build)).toContain("--bundles nsis");
});

test("CodeSignTool version and pinned hash in the workflow match the script", () => {
  const { parsed } = readWorkflow("release-windows.yml");
  expect(parsed.env.CODESIGNTOOL_VERSION).toBe(CODESIGNTOOL_VERSION);
  expect(parsed.env.CODESIGNTOOL_SHA256).toMatch(/^[0-9a-f]{64}$/);
});

test("no other workflow packages Windows or touches the signing secrets", () => {
  const forbidden = ["ES_USERNAME", "ES_PASSWORD", "CREDENTIAL_ID", "ES_TOTP_SECRET", "signCommand", "CodeSignTool", "scripts/sign-windows"];
  const others = fs.readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f) && f !== "release-windows.yml");
  expect(others).toContain("ci.yml");
  expect(others).toContain("release.yml");
  for (const name of others) {
    const { text, parsed } = readWorkflow(name);
    for (const word of forbidden) {
      if (text.includes(word)) throw new Error(`${name} mentions ${word}; Windows signing belongs to release-windows.yml only`);
    }
    for (const [jobName, job] of Object.entries<any>(parsed.jobs)) {
      const runsOn = JSON.stringify(job["runs-on"] ?? "") + JSON.stringify(job.strategy ?? "");
      if (!/windows/i.test(runsOn)) continue;
      for (const step of job.steps as any[]) {
        const run: string = step.run ?? "";
        if (/tauri build/.test(run) && !/--no-bundle/.test(run)) {
          throw new Error(`${name} job ${jobName} bundles on Windows: ${run}`);
        }
      }
    }
  }
});

// --- the CLI, end to end ------------------------------------------------------

function runSigner(args: string[], env: Record<string, string | undefined>) {
  return spawnSync("bun", [path.join(ROOT, "scripts", "sign-windows.ts"), ...args], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_ACTIONS: "", GITHUB_EVENT_NAME: "", CODESIGNTOOL_DIR: "", ...env },
  });
}

test("files that are not ours are skipped even with no secrets", () => {
  const skipped = runSigner(["C:\\nsis\\NSISdl.dll"], {});
  expect(skipped.status).toBe(0);
  expect(skipped.stdout).toContain("skip");
});

test("a CI run that is not workflow_dispatch refuses to sign before reaching CodeSignTool", () => {
  for (const event of ["push", "pull_request"]) {
    const result = runSigner(["target\\release\\auto-desktop.exe"], {
      ...FULL_SECRETS,
      GITHUB_ACTIONS: "true",
      GITHUB_EVENT_NAME: event,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`not from "${event}"`);
    expect(result.stdout).not.toContain("signing");
  }
});

test("missing secrets fail the build instead of leaving the file unsigned", () => {
  const result = runSigner(["target\\release\\auto-desktop.exe"], {
    ...FULL_SECRETS,
    ES_PASSWORD: "",
    ES_TOTP_SECRET: "",
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("refusing to leave");
  expect(result.stderr).toContain("missing ES_PASSWORD, ES_TOTP_SECRET");
});

test("--verify-updater-sig checks the signature against the key in a tauri.conf.json", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "updater-sig-"));
  fs.copyFileSync(path.join(FIXTURE, "payload.bin"), path.join(dir, "payload.bin"));
  fs.copyFileSync(path.join(FIXTURE, "payload.bin.sig"), path.join(dir, "payload.bin.sig"));
  const conf = path.join(dir, "tauri.conf.json");
  fs.writeFileSync(conf, JSON.stringify({ plugins: { updater: { pubkey: fixturePubkey() } } }));

  const ok = runSigner(["--verify-updater-sig", path.join(dir, "payload.bin"), conf], {});
  expect(ok.status).toBe(0);

  const wrongKey = runSigner(
    ["--verify-updater-sig", path.join(dir, "payload.bin"), path.join(ROOT, "src-tauri", "tauri.conf.json")],
    {},
  );
  expect(wrongKey.status).toBe(1);
  expect(wrongKey.stderr).toContain("different key");

  fs.appendFileSync(path.join(dir, "payload.bin"), "x");
  const changed = runSigner(["--verify-updater-sig", path.join(dir, "payload.bin"), conf], {});
  expect(changed.status).toBe(1);
  expect(changed.stderr).toContain("does not match the file");
  fs.rmSync(dir, { recursive: true, force: true });
});

test.skipIf(process.platform !== "win32")("--verify rejects an unsigned exe", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authenticode-"));
  const exe = path.join(dir, "auto-desktop.exe");
  fs.writeFileSync(exe, crypto.randomBytes(4096));
  const result = runSigner(["--verify", exe], {});
  expect(result.status).toBe(1);
  expect(result.stdout).toMatch(/STATUS=(NotSigned|UnknownError)/);
  expect(result.stderr).toContain("Authenticode verification failed");
  fs.rmSync(dir, { recursive: true, force: true });
});
