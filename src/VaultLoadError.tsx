import type { TFn } from "./lib/i18n";

export function VaultLoadError({ t, error, busy, onRetry }: {
  t: TFn;
  error: string;
  busy: boolean;
  onRetry: () => void;
}) {
  return (
    <div className="boot">
      <div className="boot-error" role="alert">
        <h1>{t("wallet.loadFailed")}</h1>
        <p>{t("wallet.loadFailedHint")}</p>
        <pre>{error}</pre>
        <button className="btn btn-primary" disabled={busy} onClick={onRetry}>{t("wallet.retry")}</button>
      </div>
    </div>
  );
}
