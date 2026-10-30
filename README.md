# AutoDesktop

A super-lightweight, **RabbyDesktop-style native desktop wallet + dApp browser**, built on **Tauri 2 + React + TypeScript**. It embeds remote dApp pages in native child webviews and injects an EIP-1193 wallet provider (`window.ethereum`) into them — like a browser-extension wallet, but a native app with a small installer.

AutoDesktop is the desktop counterpart to the **Auto Wallet** browser extension.

> **Product north star & the 6 core features:** [VISION.md](VISION.md)
> **How to work in this repo (architecture, security boundary, conventions):** [CLAUDE.md](CLAUDE.md)
> **Code signing policy** (team roles, privacy policy, Windows uninstall): [Code signing policy](#code-signing-policy)

## Related Code

AutoDesktop owns its wallet core in this repo:

| Path | Role |
| --- | --- |
| `src/wallet-core` | EIP-1193/6963 provider, platform adapter interfaces, and portable wallet-facing TypeScript. |
| `src` | Trusted React shell UI plus the dApp injection entry. |
| `src-tauri` | Tauri backend, native/window/webview concerns, key custody, signing, and RPC forwarding. |

The existing Chrome MV3 browser-extension wallet (`../auto-wallet`) is maintained separately and does not consume this core.

## Quick start

Use **bun** (not npm) for everything.

```bash
bun install                 # install deps
bun run tauri dev           # run the app (builds the injected provider + vite + cargo)
bun run tauri build         # production bundle (.app / .dmg)

bun run build:injected      # rebuild the injected provider IIFE (required after editing src/injected/* or src/wallet-core/*)
bunx tsc --noEmit           # typecheck the frontend

cd src-tauri && cargo test           # Rust unit tests + offline in-process E2E (deterministic, no network)
cd src-tauri && cargo test -- --ignored   # LIVE E2E: forwards to real public RPC nodes (network)
cd src-tauri && cargo check          # fast Rust typecheck
```

If the dev server is killed, a stray `vite` may hold port 1420 — free it with `lsof -ti tcp:1420 | xargs kill -9`.

Relay swaps need `RELAY_API_KEY` in the root `.env.local` (see `.env.example`).
Rust sends the key in the `x-api-key` header; the frontend uses shell-only IPC
commands for quotes, chain metadata, and status. Key lookup uses the process
environment, then `.env.local`, then the key compiled into the release build.
The macOS and Windows release jobs receive the `RELAY_API_KEY` GitHub Actions
secret. Rebuild and restart the app after updating a release key.

## What's built

- **Encrypted HD key vault** — BIP-39 mnemonic + manual BIP-32/BIP-44 derivation on pure-Rust k256; sealed at rest with Argon2id (64 MiB) + AES-256-GCM. Private keys live only in Rust, only while unlocked, and never cross into any webview.
- **Onboarding** — first-run chooser: create a new HD wallet, import (recovery phrase **or** a single raw private key), or connect a Ledger (placeholder — see below). Unlock screen with a checkbox-gated "forgot password → reset wallet" escape hatch.
- **Signing + approval flow** — `personal_sign`, `eth_sendTransaction` (EIP-1559 type-2), and `eth_signTypedData_v4` (EIP-712). Each signing request suspends and opens a **separate top-level approval window**; the backend signs only after the user approves there. dApps can never self-approve.
- **Multi-webview dApp browser** — a container window with a trusted local `shell` webview (the React UI) and per-tab remote `dapp-*` webviews rendered on top, with an injected provider.
- **Read-only RPC forwarding** — non-signing JSON-RPC is proxied to the selected chain's public node.
- **Network management** — built-in chains (Ethereum, Base, OP, Arbitrum, Polygon) plus user-added custom chains and editable RPC/params, persisted to disk.
- **i18n** — English / 中文.

### Pending

- **Ledger** (hardware wallet) — v1 requirement. WKWebView has no WebHID, so this needs a Rust `hidapi` transport behind `HidTransport`. Presented in onboarding as an honest placeholder until wired.
- **Multi-wallet** — currently a single vault; importing a private key is the *first* wallet, not multiple independent secrets coexisting.
- Custom ERC-20 tokens on the Wallet page, collapsible sidebar / editable URL bar.

See the project memory roadmap for live per-slice progress.

## Architecture

### Multi-webview model

There is **no window defined in `tauri.conf.json`** — `src-tauri/src/lib.rs` `run()`/`setup()` builds a container `Window`, a local **`shell`** child webview (the React UI, full window, underneath), and remote **`dapp-*`** child webviews positioned in the content rect. Native child webviews render *on top of* the shell in their rectangle — which is why the sidebar/topbar stay visible and why approval UI must be a separate window, not an in-shell modal. Multi-webview requires the Cargo `unstable` feature.

### Wallet bridge & security boundary

```
dApp page → injected window.ethereum → invoke('wallet_request', {method, params})
          → Rust wallet_request command → handle_rpc() (single backend entry)
          → route: Wallet (local state) | Signing (key + user approval) | Forward (read-only RPC)
```

The boundary is enforced by Tauri's ACL across three capability files:

- `capabilities/default.json` — scoped to the **`shell`** webview only; grants the trusted UI its commands (incl. the vault commands).
- `capabilities/dapp.json` — scoped to **`dapp-*`** webviews + `remote.urls`; grants **only** `allow-wallet-request`. That one command is the entire attack surface exposed to untrusted dApps. Never add `core:*`/`fs:*`/`shell:*` here.
- `capabilities/approval.json` — scoped to the dedicated **`approval`** window; grants the approve/reject/list commands so a page can never self-approve.

The caller origin is derived from the engine-set `webview.url()`, never from a JS param.

### Injection pipeline

`src/injected/inpage.tauri.ts` (a Tauri `invoke`-based `ProviderTransport` calling `src/wallet-core`'s `installProvider`) → bundled to a self-contained IIFE by `scripts/build-injected.ts` → written to `src-tauri/injected/inpage.js` → embedded in Rust via `include_str!` → set as each dapp webview's `initialization_script`. Because `include_str!` is compile-time, editing `src/injected/*` or `src/wallet-core/*` requires `bun run build:injected` **and** a Rust rebuild (`tauri dev` does this on startup, but not on mid-session file changes).

## Project layout

```
src/                    React shell (trusted UI)
  pages/                WalletPage, DappsPage, BrowserView, SettingsPage, LockScreen, ApprovalView
  lib/                  vault, chains, accounts, activeChain, useBalances, rpc, i18n, dapps, platform…
  injected/             inpage.tauri.ts — the provider transport bundled into dApp pages
  wallet-core/          EIP-1193/6963 provider and wallet adapter interfaces
src-tauri/src/          Rust backend
  lib.rs                window/webview setup, wallet bridge, vault + chain commands, in-process E2E
  vault.rs              BIP-39/32/44 derivation + Argon2id/AES-GCM keystore (pure crypto core)
  eth_tx.rs             EIP-1559 transaction RLP encoding + signing
  eip712.rs             EIP-712 typed-data hashing + signing
src-tauri/capabilities/ ACL capability files (default / dapp / approval)
src-tauri/permissions/  app-command permission definitions
scripts/                build-injected + CDP/native verification harnesses
```

## Testing

`tauri-driver`/WebdriverIO (the official UI-E2E path) **does not work on macOS** — Apple ships no WKWebView WebDriver. So the wallet bridge is E2E-tested **in-process** with `tauri::test`'s mock runtime (`mod e2e` in `lib.rs`), which drives the real `invoke('wallet_request') → command → handle_rpc` pipeline — including the `dapp.json` ACL grant and trustworthy-origin derivation — without a GUI. Offline tests run by default; the live network-forward test is `#[ignore]`d (run with `cargo test -- --ignored`).

The frontend onboarding/Settings flows are verified visually via a Chrome CDP harness against the vite dev server (`scripts/*-test.ts`), and natively via macOS `screencapture` (`scripts/native-shot.sh`).

## Code signing policy

Free code signing provided by SignPath.io, certificate by SignPath Foundation.

Windows releases are built from this repository by [`.github/workflows/release.yml`](.github/workflows/release.yml) on a `v*` tag. The current published installer is `AutoDesktop_<version>_windows_x86_64_setup.exe` on the [GitHub Releases](https://github.com/Auto-Wallet/auto-wallet-desktop/releases) page (`auto-desktop` in older links is this same repository).

### Team roles

- Committers and reviewers: [Members team](https://github.com/orgs/Auto-Wallet/teams/members)
- Approvers: [Owners](https://github.com/orgs/Auto-Wallet/people?query=role%3Aowner)

Committers may change this repository without an extra review. Every change from someone who is not a committer is reviewed by a team member before it lands. A team member trusted by the whole team (an Approver) approves each request to code-sign a release.

### Privacy policy

AutoDesktop is a desktop Ethereum wallet and dApp browser. It has no analytics or crash-reporting SDK. The diagnostic log (`autodesktop.log`), the encrypted vault, settings, and the price cache stay on this computer. Private keys are used only in the app process, after you unlock the vault and approve a signature.

The app does contact other systems while it runs. Any HTTPS request reveals your IP address to that server. Several of those servers are chosen by the app, and some requests include your wallet address or a transaction you are about to sign. The Windows installer does not yet offer a switch to turn those calls off. What follows is the complete set of networked behavior in the current source.

**While the app is open**

- **Updates.** On startup, and about once an hour after that, the app asks GitHub whether a newer release exists (`api.github.com` and the release files for [Auto-Wallet/auto-wallet-desktop](https://github.com/Auto-Wallet/auto-wallet-desktop/releases)) and may download the installer. Installing it waits for you. The fallback update request uses the User-Agent `AutoDesktop`. No wallet data is included. [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement) applies.

**On the Wallet page**

- **Chain RPC.** Balances, token reads, gas, and receipts are JSON-RPC calls to the endpoint configured for each chain. Built-in chains default to public nodes (PublicNode hosts such as `ethereum-rpc.publicnode.com`, plus chain operators including BNB Chain, zkSync, Sonic, Alchemy's public World Chain endpoint, Wanchain, and others listed in the app). A release build appends this project's PublicNode API key to `*.publicnode.com` URLs. Calls such as `eth_getBalance` include the account address. A signed transaction is broadcast with `eth_sendRawTransaction`. You can replace any chain's RPC in Settings; that server then receives the same kinds of calls. A dApp you have open can also ask the wallet to forward standard Ethereum read calls, and a transaction that page already signed, to the selected chain's RPC.
- **USD prices.** When the wallet asks for prices, and the on-disk cache is older than about 30 minutes, the app calls CoinGecko (`api.coingecko.com/api/v3/simple/price`) with coin ids and a browser-style User-Agent ending in `AutoDesktop/<version>`. The wallet address is not included. [CoinGecko's privacy policy](https://www.coingecko.com/en/privacy) applies.

**When you turn a feature on or confirm an action**

- **DeFi positions.** The Wallet page queries Zerion (`api.zerion.io`) with the account address when you enable DeFi for that account. If Zerion fails for a wallet that holds assets, the same address is sent to DeBank (`pro-openapi.debank.com`). When Zerion answers, DeBank is still asked about Uniswap v4 on chains where that wallet is active. Both calls use API keys built into the release. The same refresh reads xStake farming positions with Wanchain RPC calls. [DeBank's privacy policy](https://debank.com/privacy) applies; Zerion's own policy applies to the Zerion calls.
- **Transaction preview.** Before you approve a signature, the approval window can POST the sender, recipient, calldata, value, gas, and chain id to WanScan's simulator at `https://balance-change-simulate-api.wanscan.org/simulate`.
- **Swaps.** A quote or built transaction is sent to the service for the route you pick: XFlows (`xflows.wanchain.org`), Relay (`api.relay.link`, with this project's API key), and/or OKX DEX (`web3.okx.com`, signed with this project's OKX API credentials). Those requests include wallet addresses, token addresses, and amounts. An OKX status check sends the transaction hash.
- **Logos.** DeFi positions and the swap token lists show the protocol, chain, and token logos that Zerion, DeBank, Relay, and XFlows return. Each logo loads straight from the image host named in that response (usually the service's own CDN). That host sees your IP address; the request carries no wallet address.
- **Safe accounts.** Importing a Safe talks to Safe's Transaction Service. The default host is `api.safe.global` (this project's API key is attached only to that host). A service URL you enter is used instead, and does not receive that key. Requests include the Safe address and transaction fields. Confirming a Safe transaction also submits the signature.
- **Your OKX account.** The OKX page uses an API key you create and store in the operating system credential store (`com.autodesktop.wallet.okx`). Those calls go to the OKX host for the region you select (`www.okx.com`, `us.okx.com`, `eea.okx.com`, or `tr.okx.com`) and read balances and Dual Investment orders. This is separate from the project's OKX DEX credentials above.
- **dApps and explorers.** A site you open loads in a child webview (Microsoft Edge WebView2 on Windows). That site is a third party: it sees your IP address, and after you connect it can read the selected address through the injected Ethereum provider. Favicons are requested from the site's own origin. Explorer links (Etherscan and the other explorers configured in the app) open only when you follow them. WebView2 is Microsoft's component; [Microsoft's privacy statement](https://privacy.microsoft.com/en-us/privacystatement) applies to it.

**Installer**

The NSIS setup (`AutoDesktop_<version>_windows_x86_64_setup.exe`) can download the Microsoft Edge WebView2 runtime from Microsoft when Windows does not already have it.

### Uninstall on Windows

The Windows download is the NSIS installer `AutoDesktop_<version>_windows_x86_64_setup.exe` from [GitHub Releases](https://github.com/Auto-Wallet/auto-wallet-desktop/releases). It installs for the current user, registers **AutoDesktop** with Windows, and puts the program in `%LOCALAPPDATA%\AutoDesktop`.

1. Open **Settings → Apps → Installed apps**.
2. Select **AutoDesktop**, then **Uninstall**, and confirm.
3. The program files, Start menu entry, and desktop shortcut are removed. On the confirmation page, **Delete app data** is unchecked. Leave it unchecked to keep the encrypted vault. Check it to also delete `%APPDATA%\com.autowallet.desktop` and `%LOCALAPPDATA%\com.autowallet.desktop`. That removes the vault from this PC. The recovery phrase is the backup; the app cannot recreate a deleted vault.
4. If you connected an OKX API key, disconnect it in the app first. The uninstaller does not remove the Windows Credential Manager entry for `com.autodesktop.wallet.okx`.

An in-app update runs the installer in passive mode and does not show the delete-app-data checkbox, so an update leaves the vault in place.

The portable zip `AutoDesktop_<version>_windows_x64.zip` is not registered with Windows. Close the app and delete the extracted folder. Wallet data in the folders above is left behind until you delete it yourself.

## Platform constraints (macOS / WKWebView)

- **No WebHID/WebUSB** → Ledger/hardware support must go through a Rust `hidapi` transport behind `HidTransport`.
- **Custom URI schemes are one-way from remote pages** — WebKit blocks `fetch()` to a registered scheme, so the wallet bridge uses `invoke`, not a custom scheme.
