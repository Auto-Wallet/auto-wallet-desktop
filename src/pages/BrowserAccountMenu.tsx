import { shortAddress } from "../lib/format";
import { useT } from "../lib/i18n";
import { Icon } from "../lib/icons";
import { Avatar, CopyButton } from "../lib/ui";

// Shared by the native menu overlay and the browser preview.
export function BrowserAccountMenu({
  accounts,
  activeAddress,
  query,
  onQueryChange,
  onSelect,
  onDismiss,
  copyTitle,
  onCopied,
  onCopyFailed,
}: {
  accounts: readonly { address: string; label: string }[];
  activeAddress: string;
  query: string;
  onQueryChange: (query: string) => void;
  onSelect: (address: string) => void;
  onDismiss: () => void;
  copyTitle: string;
  onCopied: () => void;
  onCopyFailed?: () => void;
}) {
  const { t } = useT();
  const search = query.trim().toLowerCase();
  const matches = accounts.filter((account) =>
    account.label.toLowerCase().includes(search) || account.address.toLowerCase().includes(search),
  );

  return (
    <>
      <label className="chain-search">
        <Icon name="search" size={15} />
        <input
          value={query}
          autoFocus
          aria-label={t("wallet.searchAccounts")}
          placeholder={t("wallet.searchAccounts")}
          onChange={(event) => onQueryChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key !== "Escape") return;
            event.stopPropagation();
            onDismiss();
          }}
        />
      </label>
      <div className="acct-list scroll">
        {matches.map((account) => {
          const active = account.address.toLowerCase() === activeAddress.toLowerCase();
          return (
            <div
              key={account.address}
              role="button"
              tabIndex={0}
              className={`acct-opt${active ? " on" : ""}`}
              onClick={() => onSelect(account.address)}
              onKeyDown={(event) => {
                if (event.key !== "Enter" && event.key !== " ") return;
                event.preventDefault();
                onSelect(account.address);
              }}
            >
              <Avatar address={account.address} size={28} />
              <span className="meta">
                <span className="l">{account.label}</span>
                <span className="a">{shortAddress(account.address, 8, 6)}</span>
              </span>
              <CopyButton
                className="acct-copy"
                title={copyTitle}
                size={14}
                value={account.address}
                onCopied={onCopied}
                onCopyFailed={onCopyFailed}
              />
              {active && <span className="check"><Icon name="check" size={15} /></span>}
            </div>
          );
        })}
        {matches.length === 0 && <div className="chain-empty">{t("wallet.noAccountMatches")}</div>}
      </div>
    </>
  );
}
