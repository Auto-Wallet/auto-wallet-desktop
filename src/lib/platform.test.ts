import { afterEach, expect, test } from "bun:test";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { goBackDapp, navigateDapp } from "./platform";

Object.defineProperty(globalThis, "window", {
  value: globalThis,
  configurable: true,
});

afterEach(() => clearMocks());

test("the browser back control navigates inside the active dApp webview", async () => {
  const calls: Array<{ command: string; args: unknown }> = [];
  mockIPC((command, args) => {
    calls.push({ command, args });
  });

  await goBackDapp("dapp-uniswap");

  expect(calls).toEqual([
    { command: "go_back_dapp", args: { label: "dapp-uniswap" } },
  ]);
});

test("the address bar navigates the existing dApp tab to the full URL", async () => {
  const calls: Array<{ command: string; args: unknown }> = [];
  mockIPC((command, args) => { calls.push({ command, args }); });
  await navigateDapp("dapp-uniswap", "https://app.aave.com/?market=base#supply");
  expect(calls).toEqual([{
    command: "navigate_dapp",
    args: { label: "dapp-uniswap", url: "https://app.aave.com/?market=base#supply" },
  }]);
});
