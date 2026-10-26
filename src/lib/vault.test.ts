import { afterEach, describe, expect, test } from "bun:test";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { enableTouchId, getTouchIdStatus, importPrivateKey, unlockVaultWithTouchId } from "./vault";

Object.defineProperty(globalThis, "window", {
  value: globalThis,
  configurable: true,
});

afterEach(() => clearMocks());

describe("Private key import", () => {
  test("imports the key and trimmed wallet name in one command", async () => {
    const calls: Array<{ command: string; args: unknown }> = [];
    mockIPC((command, args) => {
      calls.push({ command, args });
      if (command === "import_private_key") return { id: "imported", address: "0x1234" };
      if (command === "vault_status") return {
        exists: true, unlocked: true, has_password: true,
        wallets: [{ id: "imported", label: "Trading", kind: "privkey", accounts: ["0x1234"] }],
        active: "0x1234",
      };
      throw new Error(`Unexpected command: ${command}`);
    });

    expect(await importPrivateKey(undefined, "  test-key  ", "  Trading  ")).toEqual({
      id: "imported", address: "0x1234",
    });
    expect(calls).toEqual([
      { command: "import_private_key", args: { password: undefined, privateKey: "test-key", label: "Trading" } },
      { command: "vault_status", args: {} },
    ]);
  });

  test("rejects a blank name before importing a wallet", async () => {
    const calls: string[] = [];
    mockIPC((command) => { calls.push(command); });

    await expect(importPrivateKey(undefined, "test-key", " \t ")).rejects.toThrow("wallet name cannot be empty");
    expect(calls).toEqual([]);
  });
});

describe("Touch ID vault bridge", () => {
  test("reads Touch ID state from the native vault command", async () => {
    const calls: Array<{ command: string; args: unknown }> = [];
    mockIPC((command, args) => {
      calls.push({ command, args });
      return { available: true, enabled: true };
    });

    expect(await getTouchIdStatus()).toEqual({ available: true, enabled: true });
    expect(calls).toEqual([{ command: "touch_id_status", args: {} }]);
  });

  test("passes localized reasons to native Touch ID prompts", async () => {
    const calls: Array<{ command: string; args: unknown }> = [];
    mockIPC((command, args) => {
      calls.push({ command, args });
      return "0x1234";
    });

    await enableTouchId("enable wallet unlock");
    await unlockVaultWithTouchId("unlock wallet");

    expect(calls).toEqual([
      { command: "enable_touch_id", args: { reason: "enable wallet unlock" } },
      { command: "unlock_vault_with_touch_id", args: { reason: "unlock wallet" } },
      { command: "vault_status", args: {} },
    ]);
  });
});
