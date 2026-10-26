// Shared Ledger address picker — used by both the onboarding flow (LockScreen)
// and the add-wallet flow (WalletPage). Loads a PAGE of 20 addresses, fetched in
// small chunks so each row appears as the device derives it (dynamic load), with
// prev/next pagination so the user can scan far down the derivation path.

import { useCallback, useState } from "react";
import { connectLedger, listLedgerAddresses, type LedgerAccount, type WalletRef } from "./vault";
import { shortAddress } from "./format";
import { useT } from "./i18n";
import { Icon } from "./icons";

export const LEDGER_PAGE_SIZE = 20;
const CHUNK = 4; // addresses fetched per device round-trip (then rendered)

function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

export function useLedgerScan(onConnected: (ref: WalletRef) => void, name = "") {
  const [accounts, setAccounts] = useState<LedgerAccount[]>([]);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false); // scanning a page
  const [connecting, setConnecting] = useState(false);
  const [started, setStarted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadPage = useCallback(async (p: number) => {
    setStarted(true);
    setLoading(true);
    setError(null);
    setAccounts([]);
    try {
      const base = p * LEDGER_PAGE_SIZE;
      for (let off = 0; off < LEDGER_PAGE_SIZE; off += CHUNK) {
        const want = Math.min(CHUNK, LEDGER_PAGE_SIZE - off);
        const chunk = await listLedgerAddresses(base + off, want);
        if (chunk.length === 0) break;
        setAccounts((prev) => [...prev, ...chunk]); // show as they stream in
        if (chunk.length < want) break;
      }
    } catch (e) {
      setError(errText(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const scan = useCallback(() => {
    setPage(0);
    void loadPage(0);
  }, [loadPage]);
  const nextPage = useCallback(() => {
    const p = page + 1;
    setPage(p);
    void loadPage(p);
  }, [page, loadPage]);
  const prevPage = useCallback(() => {
    if (page <= 0) return;
    const p = page - 1;
    setPage(p);
    void loadPage(p);
  }, [page, loadPage]);

  const pick = useCallback(
    async (acct: LedgerAccount) => {
      setConnecting(true);
      setError(null);
      try {
        const ref = await connectLedger(acct.path, name);
        onConnected(ref);
      } catch (e) {
        setError(errText(e));
        setConnecting(false);
      }
    },
    [onConnected, name],
  );

  return { accounts, page, loading, connecting, started, error, scan, nextPage, prevPage, pick };
}

/** The paginated, streaming address list + pager (presentational). */
export function LedgerList({
  accounts,
  page,
  loading,
  connecting,
  onPick,
  onPrev,
  onNext,
}: {
  accounts: LedgerAccount[];
  page: number;
  loading: boolean;
  connecting: boolean;
  onPick: (a: LedgerAccount) => void;
  onPrev: () => void;
  onNext: () => void;
}) {
  const { t } = useT();
  const base = page * LEDGER_PAGE_SIZE;
  const busy = loading || connecting;
  return (
    <div className="ledger-pick">
      <ul className="ledger-list">
        {accounts.map((a) => (
          <li key={a.path}>
            <button className="ledger-acct" disabled={connecting} onClick={() => onPick(a)}>
              <span className="ledger-idx">#{a.index}</span>
              <span className="ledger-addr">{shortAddress(a.address, 10, 8)}</span>
              <Icon name="chevronR" size={16} />
            </button>
          </li>
        ))}
        {loading &&
          Array.from({ length: LEDGER_PAGE_SIZE - accounts.length }).map((_, i) => (
            <li key={`skel-${i}`}>
              <div className="ledger-acct ledger-skel">
                <span className="skeleton" style={{ width: 40, height: 13 }} />
                <span className="skeleton" style={{ width: 150, height: 13 }} />
              </div>
            </li>
          ))}
      </ul>
      <div className="ledger-pager">
        <button className="btn btn-ghost btn-sm" disabled={page === 0 || busy} onClick={onPrev}>
          <Icon name="chevronL" size={14} /> {t("lock.ledgerPrev")}
        </button>
        <span className="ledger-range">
          #{base}–#{base + LEDGER_PAGE_SIZE - 1}
        </span>
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={onNext}>
          {t("lock.ledgerNext")} <Icon name="chevronR" size={14} />
        </button>
      </div>
    </div>
  );
}
