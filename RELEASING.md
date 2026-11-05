# Releasing

macOS builds come from **`.github/workflows/release.yml`**, triggered when a `v*`
tag is pushed. Windows builds come from **`.github/workflows/release-windows.yml`**,
which runs **only by hand**: nothing packages or signs Windows automatically.

| OS      | Asset                                          | Built by                                    |
| ------- | ---------------------------------------------- | ------------------------------------------- |
| macOS   | `AutoDesktop_<ver>_macos_aarch64.dmg`          | tag push; Apple Silicon, signed + notarized |
| macOS   | `AutoDesktop_<ver>_macos_x64.dmg`              | tag push; Intel, signed + notarized         |
| Windows | `AutoDesktop_<ver>_windows_x86_64_setup.exe`   | manual run; NSIS installer, Authenticode-signed; also the updater payload |

There is no Windows portable `.zip`.

## Cut a release

1. **Bump the version** in `package.json`, `src-tauri/Cargo.toml`, and
   `src-tauri/tauri.conf.json` (keep all three in sync).
2. Commit, then tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. `release.yml` builds macOS and publishes the GitHub Release with
   auto-generated notes and a `latest.json` that lists only the macOS platforms.
4. **Windows (optional, manual).** Once that release exists, run:
   ```bash
   gh workflow run release-windows.yml --ref v0.1.0
   ```
   (or Actions -> **Release Windows** -> Run workflow, with the tag picked under
   "Use workflow from"). A reviewer approves the `windows-signing` environment,
   then the run builds the NSIS installer, signs it, checks the signatures,
   attaches the installer and its `.sig` to the release, and adds
   `windows-x86_64` to that release's `latest.json`.

Until step 4 runs for a release, Windows users get no update to it: the
updater finds no `windows-x86_64` entry in `latest.json`.

## Windows signing (SSL.com eSigner)

Personal ID certificate (CN=Lin Mo). Tauri's `bundle.windows.signCommand` calls
`scripts/sign-windows.ts`, which runs CodeSignTool 1.3.2 (its download is
pinned by SHA-256 in the workflow). Each run spends **two** of the 20 monthly
signings: the app exe packed inside the installer, and the NSIS setup exe. The
NSIS plugin DLLs and the uninstaller stay unsigned. A cancelled or failed run
may already have spent one or both, so the workflow never cancels itself.

The run fails, and nothing is published, when:
- it is not on a `v*` tag, the tag differs from `tauri.conf.json`'s version, or
  the release has no `latest.json` yet (all checked before any signing);
- any eSigner secret is missing (there is no unsigned fallback);
- the script runs in Actions from anything but `workflow_dispatch`;
- the sign log is not exactly app exe + setup exe, the Authenticode signature is
  not valid, timestamped and issued to CN=Lin Mo, or the updater `.sig` does not
  verify against `plugins.updater.pubkey`.

`ci.yml` runs `tests/sign-windows.test.ts`. It never signs, and it also fails if
any workflow other than `release-windows.yml` bundles Windows or uses the
signing secrets.

### Secrets: the `windows-signing` environment

`ES_USERNAME`, `ES_PASSWORD`, `CREDENTIAL_ID`, `ES_TOTP_SECRET` belong in the
`windows-signing` environment (Settings -> Environments), **not** in repository
secrets: repository secrets reach every workflow on every branch, and these four
let anyone sign any file as CN=Lin Mo. The environment only accepts `v*` tags and
needs a required reviewer's approval before a run sees the secrets.

The updater minisign key is separate: `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (repository secrets).

## Required GitHub secrets (macOS signing/notarization)

`APPLE_CERTIFICATE` (base64 of the Developer ID Application `.p12`),
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD` (app-specific
password), `APPLE_TEAM_ID`. The signing identity is derived from the imported
certificate at build time, so no `APPLE_SIGNING_IDENTITY` secret is needed.
