# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Product goal & the 6 core features live in [VISION.md](VISION.md).** Read it before planning features — without the north star, work drifts backend-deep and the visible product (Wallet / dApps / Settings pages) stalls. This file is *how* to work in the repo; VISION.md is *what* we're building and *why*.

## What this is

**AutoDesktop** — a lightweight, RabbyDesktop-style desktop wallet & dApp browser built on **Tauri 2 + React + TypeScript**. It embeds remote dApp web pages and injects an EIP-1193 wallet provider (`window.ethereum`) into them, like a browser-extension wallet but native.

The desktop app now owns its wallet core directly:

- `src/wallet-core` — EIP-1193/6963 provider, platform adapter interfaces, and portable wallet-facing TypeScript.
- `../auto-wallet` — the existing Chrome MV3 browser-extension wallet. It is maintained separately and does not consume this core.
- `src-tauri` plus `src` — Tauri backend, native/window/webview concerns, and trusted React UI.

Use **bun** (not npm) for everything.

## Commands

```bash
bun install                 # install deps
bun run tauri dev           # run the app (beforeDevCommand runs build:injected + vite, then cargo builds)
bun run tauri build         # production bundle (.app/.dmg)

bun run build:injected      # rebuild the injected provider IIFE (see "Injection pipeline" — REQUIRED after editing src/injected/* or src/wallet-core/*)
bunx tsc --noEmit           # typecheck the frontend (incl. the injection entry + wallet-core imports)

cd src-tauri && cargo test  # Rust unit tests + offline E2E (deterministic, no network)
cd src-tauri && cargo test -- --ignored   # LIVE E2E: forwards to real public RPC nodes (network)
cd src-tauri && cargo check # fast Rust typecheck

```

When the dev server is killed, a stray `vite` may keep port 1420 held; free it with `lsof -ti tcp:1420 | xargs kill -9` before re-running.

### Testing strategy (E2E)
`tauri-driver` / WebdriverIO (the official UI-E2E path) **does not work on macOS** — Apple ships no
WKWebView WebDriver. So the wallet bridge is E2E-tested in-process with **`tauri::test`'s mock runtime**
(see `mod e2e` in `lib.rs`), which drives the *real* `invoke('wallet_request') → command → handle_rpc`
pipeline — including the **`dapp.json` ACL grant** (the mock webview is built as the `dapp` webview on a
remote URL) and the trustworthy-origin derivation — without a GUI. Notes:
- The `test` feature is enabled via `[dev-dependencies] tauri = { features = ["test"] }`.
- Commands taking a webview must be **generic over the runtime** (`webview: tauri::Webview<R>`), or
  `generate_handler!` can't build them for `MockRuntime`.
- `generate_context!` defines a one-per-crate `_EMBED_INFO_PLIST` static — expand it at exactly one call
  site. Both `run()` and the tests share the single generic `build_context::<R>()`.
- `e2e_pipeline_offline` runs by default; the live-network forward test is `#[ignore]`d (run with `--ignored`).
- For full UI-level E2E later, the macOS route is a community plugin (`tauri-plugin-webdriver` / CrabNebula
  `tauri-plugin-automation`) embedded in the app — not adopted yet.

### Windows coverage in CI (dev machine is macOS — Windows bugs must surface in CI)
`.github/workflows/ci.yml` runs on every PR/push-to-main:
- **`test`** (windows-latest + macos-latest): `cargo test`, `tsc --noEmit` (including `src/wallet-core`), injected-bundle build.
- **`smoke-windows`** — boots the **real app on WebView2**: `src-tauri/src/smoke.rs` (active only when
  `AUTODESKTOP_SMOKE_DIR` is set) serves a dApp page from a loopback HTTP server, drives the SHELL webview
  to `invoke('open_dapp', …)` over its real IPC (the exact user-click path — required to catch the Windows
  sync-command deadlock below) so the page opens in a `dapp-*` child webview, and the page must answer
  `eth_chainId` through the injected provider → `wallet_request` pipeline. `scripts/smoke-ci.ts` launches the binary, asserts the result, and
  uploads **desktop screenshots** as the `windows-smoke` artifact — check those screenshots to see actual
  Windows rendering without a VM. Run locally: `bun run tauri build --debug --no-bundle && bun run smoke src-tauri/target/debug/auto-desktop`.
- **`lint-assets`** — `bun run check:icons` asserts every entry in `src-tauri/icons/icon.ico` has rounded
  corners baked in (Windows renders the .ico verbatim; nothing rounds it at runtime). Regenerate with
  `bun run icon:windows` (ImageMagick) after changing the icon. Also greps for hardcoded local-webview
  origins: the local origin is `tauri://localhost` on macOS but `http://tauri.localhost` on Windows — always
  derive origins (e.g. `webview.url()`), never match them literally.
- **`e2e-windows-experimental`** — tauri-driver/WebdriverIO scaffold in `e2e/wdio/` (Windows is the one
  platform where the official WebDriver path works). Manual workflow_dispatch, non-blocking; see its README.
- **Windows packaging + Authenticode signing are manual only** — `release-windows.yml`
  (`workflow_dispatch` on a `v*` tag, `windows-signing` environment). The SSL.com eSigner plan allows
  20 signings a month and each build spends 2, so no push/tag/PR trigger may bundle Windows or sign.
  CI Windows jobs build with `--no-bundle` only; `tests/sign-windows.test.ts` fails if another workflow
  bundles on Windows or touches the eSigner secrets, and the sign script refuses non-dispatch runs.
  See RELEASING.md.

Windows-specific gotchas already fixed once:
- **Any command that creates a webview/window (or may) MUST be `async`** (`open_dapp`,
  `sync_toast_overlay`, `sync_menu_overlay`). Synchronous commands run on the main thread inside a
  WebView2 event handler, where webview creation **deadlocks** (tauri builder docs / wry#583): the dApp
  never appears, the shell stops scrolling, and the close button dies — the app-wide Windows freeze of
  v0.2.14–0.2.17. All earlier "blank child webview steals input" reports were this deadlock, misdiagnosed;
  the v0.2.16 separate-dapp-window rewrite treated that symptom and was reverted. The smoke test drives
  `open_dapp` through the shell's real IPC precisely so this regression stays caught (calling the Rust fn
  from `setup()` bypassed the deadlocking context and hid it).
- `WindowBuilder::inner_size` is the CLIENT size: sizing it from the monitor work area makes the OUTER
  frame (client + title bar/borders) overflow below the taskbar and clip the sidebar bottom. Startup goes
  through `fit_startup_window`, which measures outer−inner post-build, shrinks the client to fit the work
  area, centers within the work area (not the monitor), and returns the ACTUAL client size for the shell
  child webview (also right when the window starts maximized).
- `content_to_frame` title-bar compensation is a macOS-only artifact — on Windows/Linux child-webview
  bounds are already client-area relative, so it must pass through.
- `cargo test` exes on Windows die at startup with `0xc0000139 STATUS_ENTRYPOINT_NOT_FOUND`: they carry no
  app manifest, so the pre-v6 comctl32.dll (no TaskDialogIndirect) gets loaded (known tauri::test issue,
  tauri-apps discussion #11179). Fix lives in `build.rs::embed_test_manifest` + `test-manifest.xml`, gated
  behind `AUTODESKTOP_TEST_MANIFEST=1`; CI sets it and runs `cargo test --lib` (all tests are lib unit
  tests — `rustc-link-arg-tests` does NOT cover those and errors without `tests/` targets; the plain
  link-arg must not reach the real bin, which gets its manifest from tauri-build).

## Architecture

### Multi-webview dApp browser (the core model)
There is **no window defined in `tauri.conf.json`** (`app.windows: []`). `src-tauri/src/lib.rs` `run()` builds everything in `setup()`:

- a container **`Window`** (`tauri::window::WindowBuilder`), then
- a **`shell`** child webview (local, trusted) loading the React UI, full window, underneath, and
- a **`dapp`** child webview (remote, untrusted) loading the dApp URL, positioned in the content rect — native child webviews render **on top of** the shell in their rectangle (this is why the sidebar/topbar stay visible and why approval UI must be a separate window, not an in-shell modal).

Multi-webview (`Window::add_child`) requires the Cargo feature `tauri = { features = ["unstable"] }`.

### Wallet bridge & security boundary (read before touching capabilities)
dApp page → injected `window.ethereum` → `invoke('wallet_request', {method, params})` → Rust `wallet_request` command → `handle_rpc()` (the single backend entry). `handle_rpc` routes each method one of three ways (`route_method`): **Wallet** (answered from local state — accounts, selected chain), **Signing** (needs the key + user approval), **Forward** (read-only, proxied to the selected chain's public RPC node).

The security model is enforced by Tauri's ACL across three capability files:
- `src-tauri/capabilities/default.json` — scoped to `webviews: ["shell"]` only. Grants `core:default` etc. to the trusted UI. **Do not scope it to `windows:["main"]`** — that would cover the dapp webview too.
- `src-tauri/capabilities/dapp.json` — scoped to `webviews: ["dapp"]` + `remote.urls`. Grants **only** `allow-wallet-request` and nothing else. That one command is the entire attack surface exposed to untrusted dApps. **Never add `core:*` / `fs:*` / `shell:*` here.**
- `src-tauri/capabilities/approval.json` — scoped to `webviews: ["approval"]` (local). Grants the approve/reject/list commands to the **dedicated approval window only**. The dapp webview is deliberately NOT granted these, so a page can never self-approve its own signing request. **Never grant these to `dapp`.**

Non-obvious ACL facts (verified): app commands work from local webviews with no permission, but a **remote** webview calling a bare app command fails with `"... not allowed. Plugin not found"`. The fix is a permission `.toml` (e.g. `permissions/wallet-request.toml`, `permissions/approval.toml`) defining the bare `allow-*` id — tauri-build does **not** auto-generate app-command permissions — and listing it in the capability. (Local capabilities also require the caller's IPC URL to be `local`; remote ones match against `remote.urls`.)

**Trustworthy origin (done):** `wallet_request` takes `webview: tauri::Webview<R>` and derives the caller origin from `webview.url()` (engine-set), never from a JS param. Commands taking a webview must be **generic over the runtime** or `generate_handler!` can't build them for the test `MockRuntime`.

**Signing/approval flow:** a Signing method suspends in `request_approval` (a per-request `tokio::oneshot` + a 300s timeout) and opens a **separate top-level approval window** (`index.html?view=approval` → `ApprovalView.tsx`) — separate because the dapp webview renders on top of the shell, so an in-shell modal can't cover it. The window's `approve_request`/`reject_request` resolve the channel; approve → the backend signs (Rust-side key, never in any webview), reject → EIP-1193 `4001`. ⚠️ The active key is currently the **publicly-known Anvil #0 dev key** (`DEV_PRIVKEY_HEX`, labeled in `lib.rs`) — the encrypted password-unlocked vault is the next slice. Only `personal_sign` is wired so far; other signing methods reject up-front.

**Nothing on the signing path may wait without a bound** (fixed once, after a Send
sat on "confirm in window" forever with no window and no error, leaving no trace):
- `WebviewWindowBuilder::build()` **only posts a `CreateWindow` message to the event
  loop and returns Ok** (`tauri-runtime-wry`, `Context::create_window`) — its `Ok` is
  *not* proof a window exists. `request_approval` therefore waits for the approval
  UI itself to call in (`APPROVAL_UI_BEAT`, bumped by the three commands only that
  window may call) and fails inside `APPROVAL_WINDOW_TIMEOUT`. The `DECISION_TIMEOUT`
  starts only after that, so it can never again hide a window that never appeared.
- A freshly built approval window must be **positioned and focused explicitly**
  (`place_over_shell` + `set_focus`). Left to macOS, a 420x640 prompt lands wherever
  the OS likes — on a multi-monitor desk, a display the user isn't looking at.
  `always_on_top` does not move a window onto the screen you are using.
- `http()` carries `connect_timeout`/`timeout`/`pool_idle_timeout`/`tcp_keepalive`.
  A bare `reqwest::Client::new()` has none, so a keep-alive socket the peer had
  quietly dropped swallowed a request and never answered.
- Broadcasting distinguishes `RpcFailure::Rejected` (node said no — nothing in
  flight) from `Unreachable` (no answer — the signed tx *may* be in flight, so it is
  recorded under its locally computed hash and left to the receipt poller).
- The send path logs to `autodesktop.log` via `log_diagnostic`. `println!` goes to
  stdout, which macOS discards for a double-clicked `.app` — that is why the original
  failure left nothing to read.

### Injection pipeline (how the provider gets into dApp pages)
`src/injected/inpage.tauri.ts` (defines the Tauri `invoke`-based `ProviderTransport`, calls `src/wallet-core`'s `installProvider`) → bundled to a self-contained IIFE by `scripts/build-injected.ts` (`Bun.build`, `format: iife`) → written to `src-tauri/injected/inpage.js` → embedded in Rust via `include_str!` → set as the dapp webview's `initialization_script`.

**`include_str!` is compile-time**, so editing `src/injected/*` or `src/wallet-core/*` requires `bun run build:injected` **and** a Rust rebuild. `bun run tauri dev` does this automatically on startup (beforeDevCommand), but Tauri's file watcher will **not** rebuild the bundle mid-session.

### Wallet core relationship
`src/wallet-core` is first-party AutoDesktop source. It is consumed by the injected IIFE through `bun build`, and its adapter boundaries (`ProviderTransport`, `StorageAdapter`, `ConfirmAdapter`, `HidTransport`) keep browser-page provider logic separate from Tauri-specific glue.

### DeFi position sources (why the provider mix looks odd)
`get_defi_positions` prefers **Zerion** because it is free, and reaches for **DeBank** only where Zerion can't answer. DeBank bills in units, and the endpoints differ by two orders of magnitude — measured against the live API: `all_complex_protocol_list` ~300, `/v1/user/protocol` 4, `/v1/chain/list` and `/v1/protocol/list` 1 each.

- **Zerion fails, or returns nothing for a wallet that holds assets** → fall back to the full DeBank sweep. Expensive, but it is the only thing that answers "what does this wallet hold everywhere".
- **Zerion answers** → it stays primary, and DeBank is charged only for **Uniswap v4**, which Zerion does not report at all. Zerion's free portfolio call (`filter[positions]=no_filter`) names the chains the wallet is active on; `/v1/protocol/list` says which of those run v4; only that intersection gets a `/v1/user/protocol` probe. Typically ~10 chains ≈ 40 units instead of ~300.

Three things keep that cheap, and breaking any one turns a one-off lookup back into a per-refresh bill: the id lookups persist to `debank-registry.json` in the app data dir for 30 days (including "this chain has no v4", which is an answer worth caching); probe results are held in memory for 3 minutes, bypassed only by the UI's manual refresh (`force`); and `UNISWAP_V4_MAX_PROBES` caps the chains one address can cost. The supplement also runs under its own `UNISWAP_V4_TIMEOUT`, well inside the frontend's 30s — a supplement that overruns must lose itself, never the portfolio.

Verify against the real APIs with `cargo test --lib uniswap_v4_live -- --ignored` (spends units; needs `ZERION_API_KEY` + `DEBANK_APIKEY` in `.env.local`).

### Touch ID unlock (keychain entitlement + provisioning profile)
The vault password for Touch ID lives in the **data-protection keychain** behind a
`BiometryCurrentSet` + `WhenPasscodeSetThisDeviceOnly` access control (`touch_id.rs`),
so macOS itself demands the fingerprint — an in-app `LAContext` check alone would
leave a plain login-keychain item any same-user process could ask for. That keychain
needs the restricted `keychain-access-groups` entitlement, which macOS honors only
with a matching embedded provisioning profile:
- Release builds sign with `src-tauri/Entitlements.keychain.plist` and embed the
  Developer ID profile (`*.provisionprofile` is git-ignored):
  - `bun run build:macos:local` reads the profile path from `APPLE_PROVISIONING_PROFILE`
    in `.env.local`.
  - `release.yml` decodes the `APPLE_PROVISIONING_PROFILE` secret (base64 of the
    file). `scripts/prepare-keychain-signing.ts` checks it and prints the
    `tauri build --config` that embeds it. Both signing passes — `tauri build`
    (the updater `.app.tar.gz`) and the DMG re-sign — must use the keychain
    entitlements; the verify step checks both apps.
  - Both paths check the profile (team, app id, keychain group, expiry) before
    building.
- Everything else (`ci.yml`, `tauri dev`, `cargo test`) uses `Entitlements.plist`.
  Never add the keychain entitlements there without a profile: macOS kills an app
  that claims restricted entitlements without one.
- Unsigned builds get `-34018` when enabling Touch ID. That is intended — there is
  deliberately no fallback to the unprotected login keychain.

## Platform constraints (macOS / WKWebView)
- **No WebHID/WebUSB** in WKWebView → Ledger/hardware support must go through a Rust `hidapi` transport behind `HidTransport`, not `@ledgerhq/hw-transport-webhid`.
- **Custom URI schemes are one-way from remote pages**: a remote https page can hit a registered scheme via subresource load (`new Image().src=...`) but `fetch()` to it is blocked by WebKit. The wallet bridge therefore uses `invoke`, not the `adipc://` scheme (which remains only as a diagnostic beacon endpoint in `lib.rs`).
