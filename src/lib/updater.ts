import { invoke } from "@tauri-apps/api/core";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";
import { isTauri } from "./platform";

function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

export type UpdateInfo = {
  currentVersion: string;
  latestVersion: string;
  available: boolean;
  installed?: boolean;
  manual?: boolean;
  autoError?: string;
  releaseUrl: string;
  downloadUrl?: string | null;
};

export type UpdateProgress = {
  phase: "downloading" | "installing";
  downloaded: number;
  total?: number;
};

export async function checkForUpdate(): Promise<UpdateInfo> {
  if (!isTauri()) {
    return {
      currentVersion: __APP_VERSION__,
      latestVersion: __APP_VERSION__,
      available: false,
      releaseUrl: "https://github.com/Auto-Wallet/auto-wallet-desktop/releases",
      downloadUrl: null,
    };
  }
  try {
    const update = await check();
    if (!update) {
      return {
        currentVersion: __APP_VERSION__,
        latestVersion: __APP_VERSION__,
        available: false,
        releaseUrl: "https://github.com/Auto-Wallet/auto-wallet-desktop/releases",
        downloadUrl: null,
      };
    }
    return {
      currentVersion: __APP_VERSION__,
      latestVersion: update.version,
      available: true,
      releaseUrl: "https://github.com/Auto-Wallet/auto-wallet-desktop/releases/latest",
      downloadUrl: null,
    };
  } catch (e) {
    const fallback = await invoke<UpdateInfo>("check_for_update");
    return fallback.available
      ? { ...fallback, manual: true, autoError: errText(e) }
      : fallback;
  }
}

export async function installUpdate(
  info?: UpdateInfo | null,
  onProgress?: (progress: UpdateProgress) => void,
): Promise<UpdateInfo> {
  if (!isTauri()) {
    return (
      info ?? {
        currentVersion: __APP_VERSION__,
        latestVersion: __APP_VERSION__,
        available: false,
        releaseUrl: "https://github.com/Auto-Wallet/auto-wallet-desktop/releases",
        downloadUrl: null,
      }
    );
  }

  if (info?.manual) {
    return info;
  }

  try {
    const update = await check();
    if (!update) {
      return {
        currentVersion: __APP_VERSION__,
        latestVersion: __APP_VERSION__,
        available: false,
        releaseUrl: "https://github.com/Auto-Wallet/auto-wallet-desktop/releases",
        downloadUrl: null,
      };
    }
    let downloaded = 0;
    let total: number | undefined;
    await update.downloadAndInstall((event) => {
      if (event.event === "Started") {
        downloaded = 0;
        total = event.data.contentLength;
        onProgress?.({ phase: "downloading", downloaded, total });
        return;
      }
      if (event.event === "Progress") {
        downloaded += event.data.chunkLength;
        onProgress?.({ phase: "downloading", downloaded, total });
        return;
      }
      onProgress?.({ phase: "installing", downloaded, total });
    });
    await relaunch();
    return {
      currentVersion: __APP_VERSION__,
      latestVersion: update.version,
      available: true,
      installed: true,
      releaseUrl: "https://github.com/Auto-Wallet/auto-wallet-desktop/releases/latest",
      downloadUrl: null,
    };
  } catch (e) {
    const fallback = await invoke<UpdateInfo>("check_for_update");
    return fallback.available
      ? { ...fallback, manual: true, autoError: errText(e) }
      : fallback;
  }
}
