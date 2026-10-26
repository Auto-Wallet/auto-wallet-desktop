import { afterEach, describe, expect, test } from "bun:test";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { changePassword, connectLedger, enableTouchId, getTouchIdStatus, importPrivateKey, importVault, unlockVaultWithTouchId } from "./vault";

Object.defineProperty(globalThis, "window", {
  value: globalThis,
  configurable: true,
});

afterEach(() => clearMocks());

test("changes the password through the shell command and returns its Touch ID outcome", async () => {
  const calls: Array<{ command: string; args: unknown }> = [];
  mockIPC((command, args) => {
    calls.push({ command, args });
    return { touchIdEnabled: true, warning: null };
  });
  expect(await changePassword("current-password", "new-password")).toEqual({ touchIdEnabled: true, warning: null });
  expect(calls).toEqual([{
    command: "change_password",
    args: { currentPassword: "current-password", newPassword: "new-password" },
  }]);
});

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

});

describe("Optional names for every vault import", () => {
  const imports = [
    { command: "import_private_key", run: (name?: string) => importPrivateKey(undefined, "test-key", name) },
    { command: "import_vault", run: (name?: string) => importVault(undefined, "test phrase", name) },
    { command: "connect_ledger", run: (name?: string) => connectLedger("m/44'/60'/0'/0/0", name) },
  ];
  for (const entry of imports) {
    test(`${entry.command} accepts a custom, blank, or omitted name`, async () => {
      const labels: unknown[] = [];
      mockIPC((command, args) => {
        if (command === "vault_status") return {
          exists: true, unlocked: true, has_password: true, wallets: [], active: "0x1234",
        };
        expect(command).toBe(entry.command);
        labels.push((args as { label: string }).label);
        return { id: "imported", address: "0x1234" };
      });
      for (const name of ["  Savings  ", " \t ", undefined]) {
        expect(await entry.run(name)).toEqual({ id: "imported", address: "0x1234" });
      }
      expect(labels).toEqual(["Savings", "", ""]);
    });
  }
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
