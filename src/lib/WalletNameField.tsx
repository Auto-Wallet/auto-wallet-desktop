import { useId } from "react";
import { useT } from "./i18n";

/** Every import flow uses the same optional name field. */
export function WalletNameField({ value, onChange, disabled = false, placeholder }: {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
}) {
  const { t } = useT();
  const id = useId();
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>{t("wallet.nameOptional")}</label>
      <input
        id={id}
        name="walletName"
        className="input"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder ?? t("wallet.walletName")}
        autoComplete="off"
        disabled={disabled}
      />
    </div>
  );
}
