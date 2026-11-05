# Releasing

Builds are produced by **`.github/workflows/release.yml`**, triggered when a `v*`
tag is pushed. Each release publishes standalone clients with OS/arch in the name:

| OS      | Asset                                          | Notes                                              |
| ------- | ---------------------------------------------- | -------------------------------------------------- |
| macOS   | `AutoDesktop_<ver>_macos_aarch64.dmg`          | Apple Silicon, signed + notarized                  |
| macOS   | `AutoDesktop_<ver>_macos_x64.dmg`              | Intel, signed + notarized                          |
| Windows | `AutoDesktop_<ver>_windows_x86_64_setup.exe`   | NSIS installer, Authenticode-signed when secrets are set; also the updater payload |
| Windows | `AutoDesktop_<ver>_windows_x64.zip`            | Standalone `.exe` (WebView2 from system), same signature |

## Cut a release

1. **Bump the version** in `package.json`, `src-tauri/Cargo.toml`, and
   `src-tauri/tauri.conf.json` (keep all three in sync).
2. Commit, then tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. The workflow builds all three OSes in parallel and creates the GitHub Release
   with auto-generated notes.

## Test Windows signing without a release

Actions → **Release** → **Run workflow**, with **Fail the run if the eSigner secrets are missing** left on. That builds Windows only, signs when the four secrets below are set, verifies the signatures, and uploads the `windows-x64` artifact. It does not publish a GitHub Release.

## Required GitHub secrets (Windows Authenticode)

SSL.com eSigner, Personal ID certificate (CN=Lin Mo). The release job signs with CodeSignTool through Tauri's `bundle.windows.signCommand`. Each Windows release uses three signings (app exe inside the installer, NSIS setup exe, portable exe). See [Windows Authenticode](README.md#windows-authenticode-sslcom-esigner) in the README.

`ES_USERNAME`, `ES_PASSWORD`, `CREDENTIAL_ID`, `ES_TOTP_SECRET`.

A `v*` tag push that lacks any of them still publishes unsigned Windows builds. The manual run above fails closed so a test is not silently unsigned.

The updater minisign key is separate: `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

## Required GitHub secrets (macOS signing/notarization)

`APPLE_CERTIFICATE` (base64 of the Developer ID Application `.p12`),
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD` (app-specific
password), `APPLE_TEAM_ID`. The signing identity is derived from the imported
certificate at build time, so no `APPLE_SIGNING_IDENTITY` secret is needed.
