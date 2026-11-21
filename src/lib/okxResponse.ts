import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "./platform";

type JsonRecord = Record<string, unknown>;

export function record(value: unknown, label: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonRecord;
}

export function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

export function string(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}

export function optionalString(value: unknown, label: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  return string(value, label);
}

export function timestamp(value: unknown, label: string): number {
  const raw = string(value, label);
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`${label} is invalid`);
  return parsed;
}

export function parseEnvelope(value: unknown, label: string): unknown[] {
  const envelope = record(value, label);
  const code = string(envelope.code, `${label}.code`);
  if (code !== "0") {
    const message = string(envelope.msg, `${label}.msg`);
    throw new Error(`OKX API ${code}: ${message}`);
  }
  return array(envelope.data, `${label}.data`);
}

export async function okxInvoke<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!isTauri()) throw new Error("OKX account access is available in the desktop app.");
  return invoke<T>(command, args);
}
