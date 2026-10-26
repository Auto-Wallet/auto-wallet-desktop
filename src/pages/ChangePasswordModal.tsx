import { useEffect, useId, useRef, useState } from "react";
import { changePassword, type ChangePasswordResult } from "../lib/vault";
import { useT } from "../lib/i18n";
import { Icon } from "../lib/icons";

export function validatePasswordChange(current: string, next: string, confirm: string): string | null {
  if (!current) return "settings.currentPasswordRequired";
  if ([...next].length < 8) return "lock.errShort";
  if (next !== confirm) return "lock.errMatch";
  if (current === next) return "settings.passwordUnchanged";
  return null;
}

export function ChangePasswordModal({ onClose, onChanged }: {
  onClose: () => void;
  onChanged: (result: ChangePasswordResult) => void;
}) {
  const { t } = useT();
  const id = useId();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const saving = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !saving.current) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit() {
    if (saving.current) return;
    const validation = validatePasswordChange(current, next, confirm);
    if (validation) return setError(t(validation));
    saving.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      onChanged(result);
      onClose();
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(message === "incorrect password" ? t("settings.currentPasswordIncorrect") : message);
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }

  const fields = [
    { key: "current", label: t("settings.currentPassword"), value: current, update: setCurrent, autoComplete: "current-password" },
    { key: "new", label: t("lock.newPassword"), value: next, update: setNext, autoComplete: "new-password" },
    { key: "confirm", label: t("lock.confirm"), value: confirm, update: setConfirm, autoComplete: "new-password" },
  ];

  return (
    <div className="scrim" onClick={() => { if (!saving.current) onClose(); }}>
      <form
        className="modal change-password-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${id}-title`}
        onClick={(event) => event.stopPropagation()}
        onSubmit={(event) => { event.preventDefault(); void submit(); }}
      >
        <div className="modal-head">
          <div className="modal-title" id={`${id}-title`}>{t("settings.changePassword")}</div>
          <button type="button" className="icon-btn bare" disabled={busy} onClick={onClose} aria-label={t("common.close")}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          <p className="change-password-note">{t("settings.passwordChangeScope")}</p>
          {fields.map((field) => (
            <div className="field" key={field.key}>
              <label className="field-label" htmlFor={`${id}-${field.key}`}>{field.label}</label>
              <input
                id={`${id}-${field.key}`}
                className="input"
                type="password"
                autoComplete={field.autoComplete}
                autoFocus={field.key === "current"}
                disabled={busy}
                required
                value={field.value}
                onChange={(event) => { field.update(event.target.value); setError(null); }}
              />
            </div>
          ))}
          {error && <div className="form-error" role="alert">{error}</div>}
          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" disabled={busy} onClick={onClose}>{t("wallet.cancel")}</button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? t("settings.passwordChanging") : t("settings.changePassword")}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
