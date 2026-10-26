import { getTouchIdStatus, type TouchIdStatus } from "./vault";

/** Resolve the preference before showing a method or starting authentication. */
export async function prepareUnlock({ isActive, onStatus, onTouchId }: {
  isActive: () => boolean;
  onStatus: (status: TouchIdStatus) => void;
  onTouchId: () => Promise<void>;
}): Promise<void> {
  const status = await getTouchIdStatus();
  if (!isActive()) return;
  onStatus(status);
  if (status.available && status.enabled) await onTouchId();
}
