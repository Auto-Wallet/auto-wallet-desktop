import { afterEach, expect, test } from "bun:test";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { closeDappTabs } from "./dappTabs";
import { hasDappLoaded, markDappLoaded } from "./dappLoadState";

Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
afterEach(() => clearMocks());

test("closes every native tab and clears its loaded state", async () => {
  const labels: string[] = [];
  mockIPC((command, args) => {
    expect(command).toBe("close_dapp");
    labels.push((args as { label: string }).label);
  });
  markDappLoaded("dapp-relay");
  markDappLoaded("dapp-uniswap");
  markDappLoaded("dapp-other");

  expect(await closeDappTabs(["relay", "uniswap"])).toEqual({ closed: ["relay", "uniswap"], failed: [] });
  expect(labels).toEqual(["dapp-relay", "dapp-uniswap"]);
  expect(hasDappLoaded("dapp-relay")).toBe(false);
  expect(hasDappLoaded("dapp-uniswap")).toBe(false);
  expect(hasDappLoaded("dapp-other")).toBe(true);
});

test("continues closing other tabs and reports any failure for retry", async () => {
  const labels: string[] = [];
  const error = "webview close failed";
  mockIPC((_command, args) => {
    const { label } = args as { label: string };
    labels.push(label);
    if (label === "dapp-relay") throw error;
  });
  markDappLoaded("dapp-relay");
  markDappLoaded("dapp-uniswap");

  expect(await closeDappTabs(["relay", "uniswap"])).toEqual({
    closed: ["uniswap"], failed: [{ id: "relay", error }],
  });
  expect(labels).toEqual(["dapp-relay", "dapp-uniswap"]);
  expect(hasDappLoaded("dapp-relay")).toBe(true);
  expect(hasDappLoaded("dapp-uniswap")).toBe(false);
});

test("closing an empty list does not call native commands", async () => {
  const calls: string[] = [];
  mockIPC((command) => { calls.push(command); });
  expect(await closeDappTabs([])).toEqual({ closed: [], failed: [] });
  expect(calls).toEqual([]);
});

test("browser preview clears tabs without requiring native IPC", async () => {
  const nativeWindow = window;
  Object.defineProperty(globalThis, "window", { value: {}, configurable: true });
  markDappLoaded("dapp-preview");
  try {
    expect(await closeDappTabs(["preview"])).toEqual({ closed: ["preview"], failed: [] });
    expect(hasDappLoaded("dapp-preview")).toBe(false);
  } finally {
    Object.defineProperty(globalThis, "window", { value: nativeWindow, configurable: true });
  }
});
