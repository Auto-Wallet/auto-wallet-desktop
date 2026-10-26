import { afterEach, expect, test } from "bun:test";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { prepareUnlock } from "./preferredUnlock";
import { unlockVaultWithTouchId } from "./vault";

Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
afterEach(() => clearMocks());

test("opening unlock starts Touch ID after reading the enabled preference", async () => {
  const calls: string[] = [];
  mockIPC((command) => {
    calls.push(command);
    if (command === "touch_id_status") return { available: true, enabled: true };
    if (command === "unlock_vault_with_touch_id") return "0x1234";
    if (command === "vault_status") return {
      exists: true, unlocked: true, has_password: true, wallets: [], active: "0x1234",
    };
    throw new Error(`Unexpected command: ${command}`);
  });
  const modes: string[] = [];
  await prepareUnlock({
    isActive: () => true,
    onStatus: (status) => { modes.push(status.enabled ? "touchId" : "password"); },
    onTouchId: () => unlockVaultWithTouchId("unlock your wallet"),
  });
  expect(modes).toEqual(["touchId"]);
  expect(calls).toEqual(["touch_id_status", "unlock_vault_with_touch_id", "vault_status"]);
});

test("disabled or unavailable Touch ID leaves authentication to the password form", async () => {
  for (const status of [
    { available: true, enabled: false },
    { available: false, enabled: true },
    { available: false, enabled: false },
  ]) {
    mockIPC(() => status);
    let prompts = 0;
    const statuses: unknown[] = [];
    await prepareUnlock({
      isActive: () => true,
      onStatus: (value) => { statuses.push(value); },
      onTouchId: async () => { prompts++; },
    });
    expect(statuses).toEqual([status]);
    expect(prompts).toBe(0);
  }
});

test("a cancelled authentication reports the error without automatically retrying", async () => {
  const calls: string[] = [];
  mockIPC((command) => {
    calls.push(command);
    if (command === "touch_id_status") return { available: true, enabled: true };
    if (command === "unlock_vault_with_touch_id") throw "User cancelled";
    throw new Error(`Unexpected command: ${command}`);
  });
  await expect(prepareUnlock({
    isActive: () => true,
    onStatus: () => {},
    onTouchId: () => unlockVaultWithTouchId("unlock your wallet"),
  })).rejects.toBe("User cancelled");
  expect(calls).toEqual(["touch_id_status", "unlock_vault_with_touch_id"]);
});

test("a disposed effect cannot start a second prompt during Strict Mode setup", async () => {
  const completions: Array<(status: { available: boolean; enabled: boolean }) => void> = [];
  mockIPC(() => new Promise((resolve) => { completions.push(resolve); }));
  let active = true;
  let statuses = 0;
  let prompts = 0;
  const callbacks = {
    onStatus: () => { statuses++; },
    onTouchId: async () => { prompts++; },
  };
  const stale = prepareUnlock({ ...callbacks, isActive: () => active });
  active = false;
  const current = prepareUnlock({ ...callbacks, isActive: () => true });
  for (const complete of completions) complete({ available: true, enabled: true });
  await Promise.all([stale, current]);
  expect(statuses).toBe(1);
  expect(prompts).toBe(1);
});
