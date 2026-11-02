import { Component, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./ApprovalView.css";
import { Icon, type IconName } from "./lib/icons";
import { Avatar } from "./lib/ui";
import { useT, type TFn } from "./lib/i18n";
import { formatUnits, fmtUnitsDisplay, parseUnits, shortAddress, toHexQuantity } from "./lib/format";
import { isTauri } from "./lib/platform";
import { useSegPill } from "./lib/transitions";
import { rpc } from "./lib/rpc";
import { simulateTx, type SimulationPreview } from "./lib/simulation";
import { createActivityReporter } from "./lib/autoLock";
import {
  detectPermit,
  isSafeDelegateCall,
  encodeErc20Approve,
  MAX_UINT256,
  parseApprovalDetails,
  parseHexQuantity,
  parseTransferDetails,
  type ApprovalDetails,
  type PermitGrant,
  type TransferDetails,
  type TypedDataPayload,
} from "./lib/decode";

// Mirrors the Rust `PreparedTx` (snake_case from serde).
interface TxDisplay {
  chain_id: string;
  chain_name: string;
  symbol: string;
  from: string;
  to: string;
  value: string;
  data: string;
  gas: string;
  nonce: string;
  max_priority_fee_per_gas: string;
  max_fee_per_gas: string;
}

// Mirrors the Rust `PendingRequest` (src-tauri/src/lib.rs).
interface PendingRequest {
  id: string;
  method: string;
  origin: string;
  signer_address?: string;
  signer_kind?: "local" | "ledger";
  summary: string;
  tx?: TxDisplay;
  typed_data?: TypedDataPayload;
}
type ApprovalTokenInfo = {
  symbol: string;
  decimals: number;
  balanceRaw: string;
  balance: string;
};
// Mirrors the Rust vault status (read once so the window can show WHO signs).
interface VaultStatusDto {
  address: string | null;
  kind: "hd" | "privkey" | "ledger" | null;
}

function kindMeta(method: string, t: TFn): { title: string; icon: IconName; coral: boolean } {
  switch (method) {
    case "personal_sign":
      return { title: t("approval.signMessage"), icon: "edit", coral: false };
    case "eth_sign":
      return { title: t("approval.signData"), icon: "edit", coral: false };
    case "eth_signTypedData_v4":
      return { title: t("approval.signTyped"), icon: "edit", coral: false };
    case "eth_sendTransaction":
      return { title: t("approval.sendTx"), icon: "send", coral: true };
    case "wallet_addEthereumChain":
      return { title: t("approval.addNetwork"), icon: "globe", coral: false };
    case "eth_requestAccounts":
      return { title: t("approval.connect"), icon: "globe", coral: false };
    case "safe_confirmTransaction":
      return { title: t("approval.confirmSafe"), icon: "shield", coral: false };
    default:
      return { title: method, icon: "shield", coral: false };
  }
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

/**
 * The approval window UI (loaded via index.html?view=approval in a dedicated
 * native window). It polls the backend for pending signing requests and lets the
 * user approve or reject. The approve/reject commands are granted ONLY to this
 * "approval" webview — the dapp webview can never reach them.
 */
function ApprovalView() {
  const { t } = useT();
  const [requests, setRequests] = useState<PendingRequest[]>([]);
  const [signer, setSigner] = useState<VaultStatusDto | null>(null);
  const [busy, setBusy] = useState(false);
  // Editable EIP-1559 fees (Gwei) for an eth_sendTransaction request: the max fee
  // cap and the priority fee (tip). Both are sent back as wei-hex overrides.
  const [maxFeeGwei, setMaxFeeGwei] = useState("");
  const [maxPrioGwei, setMaxPrioGwei] = useState("");
  const [feeError, setFeeError] = useState(false);
  const [prioError, setPrioError] = useState(false);
  // Which tx view: the structured basics, raw JSON, or the calldata hex.
  const [txView, setTxView] = useState<"basic" | "json" | "hex">("basic");
  // Pre-sign balance-change simulation for the active eth_sendTransaction request.
  const [sim, setSim] = useState<SimulationPreview | null>(null);
  const [simPending, setSimPending] = useState(false);
  const [approvalInfo, setApprovalInfo] = useState<ApprovalTokenInfo | null>(null);
  const [approvalAmount, setApprovalAmount] = useState("");
  const [approvalError, setApprovalError] = useState("");

  const refresh = useCallback(async () => {
    if (!isTauri()) return;
    const list = await invoke<PendingRequest[]>("get_pending_requests");
    setRequests(list);
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    void refresh();
    void invoke<VaultStatusDto>("vault_status")
      .then((s) => setSigner(s))
      .catch(() => setSigner(null));
    const timer = setInterval(() => void refresh(), 500);
    return () => clearInterval(timer);
  }, [refresh]);

  // A user reading a request here is present: report their input so the idle
  // auto-lock waits. An open request on its own no longer holds the lock off.
  useEffect(() => {
    if (!isTauri()) return;
    const report = createActivityReporter(30_000, Date.now, () => {
      invoke("note_user_activity").catch((e) =>
        console.error("[approval] note_user_activity failed", e),
      );
    });
    const events = ["pointerdown", "pointermove", "keydown", "wheel"] as const;
    for (const ev of events) window.addEventListener(ev, report, { passive: true });
    return () => {
      for (const ev of events) window.removeEventListener(ev, report);
    };
  }, []);

  const current = requests[0];
  const approvalDetails = useMemo(
    () => (current?.tx ? parseApprovalDetails(current.tx) : null),
    [current?.id, current?.tx?.to, current?.tx?.data],
  );
  const transferDetails = useMemo(
    () => (current?.tx ? parseTransferDetails(current.tx) : null),
    [current?.id, current?.tx?.to, current?.tx?.data],
  );

  // Seed the editable fee field from the resolved tx whenever the active request
  // changes (so the user starts from the suggested max fee, in Gwei).
  useEffect(() => {
    if (current?.tx) {
      setMaxFeeGwei(formatUnits(current.tx.max_fee_per_gas, 9, 9));
      setMaxPrioGwei(formatUnits(current.tx.max_priority_fee_per_gas, 9, 9));
      setFeeError(false);
      setPrioError(false);
    }
  }, [current?.id, current?.tx?.max_fee_per_gas, current?.tx?.max_priority_fee_per_gas]);

  // Simulate the active tx to preview the signer's balance changes before signing.
  useEffect(() => {
    const tx = current?.tx;
    if (!tx) {
      setSim(null);
      setSimPending(false);
      return;
    }
    let cancelled = false;
    setSim(null);
    setSimPending(true);
    void simulateTx({
      chainId: parseInt(tx.chain_id, 16),
      from: tx.from,
      to: tx.to || null,
      data: tx.data,
      value: BigInt(tx.value || "0x0"),
      gas: BigInt(tx.gas || "0x0"),
      nativeSymbol: tx.symbol,
    })
      .then((preview) => {
        if (!cancelled) setSim(preview);
      })
      .finally(() => {
        if (!cancelled) setSimPending(false);
      });
    return () => {
      cancelled = true;
    };
  }, [current?.id, current?.tx?.chain_id, current?.tx?.to, current?.tx?.data, current?.tx?.value]);

  useEffect(() => {
    let cancelled = false;
    setApprovalInfo(null);
    setApprovalError("");
    setApprovalAmount("");
    if (!current?.tx || !approvalDetails) return;

    const chainName = current.tx.chain_name;
    void loadApprovalTokenInfo(current.tx.chain_id, approvalDetails.tokenAddress, current.tx.from)
      .then((info) => {
        if (cancelled) return;
        setApprovalInfo(info);
        setApprovalAmount(formatTokenAmountForInput(approvalDetails.amountRaw, info.decimals));
      })
      .catch((e) => {
        if (!cancelled) {
          setApprovalError(
            isTokenEmptyResult(e)
              ? t("approval.tokenNotOnChain", { chain: chainName })
              : errText(e) || t("approval.approveTokenLoadFailed"),
          );
        }
      });
    return () => {
      cancelled = true;
    };
    // `t` is deliberately NOT a dep: useT returns a fresh closure every render
    // while this view re-renders on a 500ms poll — depending on it would cancel
    // and restart the token fetch forever (observed as a stuck "Loading token…").
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [approvalDetails, current?.id, current?.tx?.chain_id, current?.tx?.from]);

  const decide = useCallback(
    async (req: PendingRequest, approve: boolean) => {
      let args: Record<string, unknown> = { id: req.id };
      if (approve && req.tx) {
        // Hand back the (possibly edited) EIP-1559 fees as wei-hex overrides. Parse
        // each separately so the offending field is the one flagged. (The backend
        // re-clamps priority ≤ max fee, so we don't have to.)
        let maxFeePerGas: string;
        let maxPriorityFeePerGas: string;
        try {
          maxFeePerGas = toHexQuantity(parseUnits(maxFeeGwei, 9));
        } catch {
          setFeeError(true);
          return;
        }
        try {
          maxPriorityFeePerGas = toHexQuantity(parseUnits(maxPrioGwei, 9));
        } catch {
          setPrioError(true);
          return;
        }
        const balanceChanges =
          sim?.status === "success" && sim.changes.length > 0
            ? sim.changes.map((c) => ({
                symbol: c.symbol,
                formattedDelta: c.formattedDelta,
                direction: c.direction,
              }))
            : undefined;
        let txData: string | undefined;
        if (approvalDetails) {
          if (approvalInfo) {
            try {
              txData = encodeErc20Approve(
                approvalDetails.spender,
                parseUnits(approvalAmount.trim(), approvalInfo.decimals),
              );
            } catch {
              setApprovalError(t("approval.approveAmountInvalid"));
              return;
            }
          } else if (!approvalError) {
            // Token metadata still loading — re-encoding needs real decimals.
            setApprovalError(t("approval.approveTokenLoading"));
            return;
          }
          // Metadata load FAILED (approvalError shown): the editable-amount
          // feature is unavailable, so the dApp's original calldata is sent
          // untouched — never re-encode with guessed decimals.
        }
        args = {
          id: req.id,
          maxFeePerGas,
          maxPriorityFeePerGas,
          txData,
          balanceChanges,
        };
      }
      setBusy(true);
      try {
        await invoke(approve ? "approve_request" : "reject_request", args);
        await refresh();
      } finally {
        setBusy(false);
      }
    },
    [refresh, maxFeeGwei, maxPrioGwei, sim, approvalDetails, approvalInfo, approvalAmount, t],
  );

  if (!current) {
    return (
      <div className="approval idle">
        <div>
          <div className="idle-mark">
            <Icon name="shieldCheck" size={26} />
          </div>
          <p>{t("approval.idle")}</p>
        </div>
      </div>
    );
  }

  const meta = kindMeta(current.method, t);
  const requestSignerAddress = current.signer_address ?? signer?.address;
  const isLedger =
    current.signer_kind === "ledger" ||
    (current.signer_kind === undefined && signer?.kind === "ledger");
  // Title says what the tx actually DOES when the calldata is decoded; the raw
  // method name is demoted to a corner tag.
  const title = approvalDetails
    ? `${t("approval.approveTitle")}${approvalInfo ? ` · ${approvalInfo.symbol}` : ""}`
    : transferDetails
      ? t("approval.transferTitle")
      : meta.title;

  return (
    <div className="approval">
      <header className="approval-head">
        <Icon name="shield" size={14} /> {t("approval.title")}
        {requests.length > 1 && (
          <span className="approval-queue">{t("approval.queue", { i: 1, n: requests.length })}</span>
        )}
      </header>

      <div className="approval-body scroll">
        {/* Dense identity strip: action + origin/network/method as corner tags. */}
        <div className="apv-top">
          <span className={`apv-top-ic${meta.coral ? " coral" : ""}`}>
            <Icon name={meta.icon} size={18} />
          </span>
          <div className="apv-top-main">
            <h2>{title}</h2>
            <div className="apv-chips">
              <span className="apv-chip strong" title={current.origin}>
                <Icon name="globe" size={11} /> {hostOf(current.origin)}
              </span>
              {current.tx && <span className="apv-chip">{current.tx.chain_name}</span>}
              <span className="apv-chip mono dim">{current.method}</span>
            </div>
          </div>
        </div>

        {current.tx ? (
          <>
            {txView === "basic" ? (
              <>
                {approvalDetails ? (
                  <ApproveEditor
                    tx={current.tx}
                    details={approvalDetails}
                    info={approvalInfo}
                    amount={approvalAmount}
                    onAmount={(v) => {
                      setApprovalAmount(v);
                      setApprovalError("");
                    }}
                    error={approvalError}
                    t={t}
                  />
                ) : transferDetails ? (
                  <TransferSection tx={current.tx} details={transferDetails} t={t} />
                ) : (
                  <PlainTxCard tx={current.tx} t={t} />
                )}
                <SimPreview sim={sim} pending={simPending} t={t} />
                <FeeSection
                  tx={current.tx}
                  maxFeeGwei={maxFeeGwei}
                  onMaxFee={(v) => {
                    setMaxFeeGwei(v);
                    setFeeError(false);
                  }}
                  feeError={feeError}
                  maxPrioGwei={maxPrioGwei}
                  onMaxPrio={(v) => {
                    setMaxPrioGwei(v);
                    setPrioError(false);
                  }}
                  prioError={prioError}
                  t={t}
                />
              </>
            ) : (
              <pre className="apv-msg">
                {txView === "json"
                  ? txAsJson(current.tx)
                  : current.tx.data && current.tx.data !== "0x"
                    ? current.tx.data
                    : "0x"}
              </pre>
            )}
            <MetaRow tx={current.tx} view={txView} onView={setTxView} t={t} />
          </>
        ) : current.typed_data ? (
          <TypedDataDetails data={current.typed_data} t={t} />
        ) : current.method === "eth_requestAccounts" ? null : (
          <div>
            <div className="field-label" style={{ padding: "0 2px 7px" }}>
              {t("approval.message")}
            </div>
            <pre className="apv-msg">{current.summary}</pre>
          </div>
        )}

        {requestSignerAddress && (
          <div className="apv-signer">
            <Avatar address={requestSignerAddress} size={20} />
            <span className="sl">
              {current.method === "eth_requestAccounts"
                ? t("approval.connectAccount")
                : t("approval.signingWith")}
            </span>
            <span className="sn">{shortAddress(requestSignerAddress, 8, 6)}</span>
            {isLedger && (
              <span className="badge ledger">
                <Icon name="ledger" size={11} /> Ledger
              </span>
            )}
          </div>
        )}

        <div className="apv-warn">
          <Icon name="alert" size={16} />
          {current.method === "wallet_addEthereumChain"
            ? t("approval.addNetworkWarn")
            : current.method === "eth_requestAccounts"
              ? t("approval.connectWarn")
              : t("approval.warn")}
        </div>

        {isLedger && busy && (
          <div className="ledger-confirm">
            <Icon name="ledger" size={17} /> {t("approval.ledgerConfirm")}
          </div>
        )}
      </div>

      <footer className="approval-foot">
        <button className="btn btn-ghost btn-lg" disabled={busy} onClick={() => void decide(current, false)}>
          {t("approval.reject")}
        </button>
        <button
          className="btn btn-aurora btn-lg grow"
          disabled={busy}
          onClick={() => void decide(current, true)}
        >
          {busy ? t("approval.waiting") : t("approval.approve")}
        </button>
      </footer>
    </div>
  );
}

// The undecoded-transaction primary card: recipient (or contract) + amount. The
// network lives in the header chips; gas/nonce/data live in the meta tag row.
function PlainTxCard({ tx, t }: { tx: TxDisplay; t: TFn }) {
  const hasData = !!tx.data && tx.data !== "0x" && tx.data.length > 2;
  return (
    <div className="apv-tx">
      <Row
        label={hasData ? t("approval.interactWith") : t("approval.to")}
        mono
        value={tx.to ? shortAddress(tx.to, 10, 8) : t("approval.newContract")}
      />
      <Row label={t("approval.amount")} value={`${fmtUnitsDisplay(tx.value, 18)} ${tx.symbol}`} />
    </div>
  );
}

// A decoded approve/transfer card describes the token call, but the same tx can
// also carry native coin to the contract. Say so inside the card the user is
// reading — the JSON tab alone is not a place anyone looks (review addendum #1).
function NativeValueNotice({ tx, t }: { tx: TxDisplay; t: TFn }) {
  const wei = parseHexQuantity(tx.value);
  if (wei === 0n) return null;
  const amount =
    wei === null ? `${tx.value} (raw)` : `${fmtUnitsDisplay(tx.value, 18)} ${tx.symbol}`;
  return (
    <div className="apv-approve-error apv-native-sent">
      <Icon name="alert" size={14} /> {t("approval.nativeAlsoSent", { amount })}
    </div>
  );
}

// The editable ERC-20 approve card — the single thing the user is deciding on,
// so it renders first and standalone.
export function ApproveEditor({
  tx,
  details,
  info,
  amount,
  onAmount,
  error,
  t,
}: {
  tx: TxDisplay;
  details: ApprovalDetails;
  info: ApprovalTokenInfo | null;
  amount: string;
  onAmount: (v: string) => void;
  error: string;
  t: TFn;
}) {
  return (
    <div className="apv-approve-editor">
      <div className="apv-approve-head">
        <span>{t("approval.approveTitle")}</span>
        <span className="apv-approve-pill">{t("approval.editable")}</span>
      </div>
      <Row
        label={t("approval.token")}
        value={info?.symbol ?? shortAddress(details.tokenAddress, 10, 8)}
        mono={!info}
      />
      <Row label={t("approval.spender")} value={shortAddress(details.spender, 10, 8)} mono />
      {error && !info ? (
        // Metadata never loaded: an editable amount is impossible, and approving
        // sends the dApp's calldata untouched — so the allowance in that calldata
        // must be on screen (review addendum #2), raw if it can't be scaled.
        <>
          <Row
            label={t("approval.allowance")}
            value={
              details.amountRaw === MAX_UINT256
                ? t("approval.permitAmountUnlimited")
                : t("approval.rawAmount", { n: details.amountRaw.toString() })
            }
            danger={details.amountRaw === MAX_UINT256}
          />
          <div className="apv-approve-error">{error}</div>
        </>
      ) : (
        <div className="apv-approve-field">
          <label className="field-label">{t("approval.approveAmount")}</label>
          <input
            className={`input mono${error ? " err" : ""}`}
            value={amount}
            inputMode="decimal"
            placeholder={info ? `${t("approval.amount")} (${info.symbol})` : t("approval.approveTokenLoading")}
            disabled={!info}
            onChange={(e) => onAmount(e.target.value)}
          />
          <div className="apv-approve-meta">
            <span>
              {t("approval.balance")}:{" "}
              {info ? `${info.balance} ${info.symbol}` : t("approval.approveTokenLoading")}
            </span>
            {info && (
              <button type="button" onClick={() => onAmount(info.balance)}>
                {t("approval.useBalance")}
              </button>
            )}
          </div>
          {error && <div className="apv-approve-error">{error}</div>}
        </div>
      )}
      <NativeValueNotice tx={tx} t={t} />
    </div>
  );
}

// Secondary facts as corner tags + the Basics/JSON/HEX switch, one thin row.
function MetaRow({
  tx,
  view,
  onView,
  t,
}: {
  tx: TxDisplay;
  view: "basic" | "json" | "hex";
  onView: (v: "basic" | "json" | "hex") => void;
  t: TFn;
}) {
  const hasData = !!tx.data && tx.data !== "0x" && tx.data.length > 2;
  const dataBytes = hasData ? tx.data.replace(/^0x/, "").length / 2 : 0;
  const segRef = useSegPill<HTMLDivElement>(view, ".apv-seg-btn.on");
  return (
    <div className="apv-meta">
      <span className="apv-tag mono">Gas {toBigintSafe(tx.gas)}</span>
      <span className="apv-tag mono">Nonce {toBigintSafe(tx.nonce)}</span>
      {hasData && <span className="apv-tag mono">{t("approval.dataBytes", { n: dataBytes })}</span>}
      <span className="apv-meta-spacer" />
      <div className="apv-seg" ref={segRef}>
        <span className="t-tabs-pill" aria-hidden="true" />
        {(["basic", "json", "hex"] as const).map((v) => (
          <button
            key={v}
            className={`apv-seg-btn${view === v ? " on" : ""}`}
            onClick={() => onView(v)}
          >
            {v === "basic" ? t("approval.tabBasic") : v === "json" ? "JSON" : "HEX"}
          </button>
        ))}
      </div>
    </div>
  );
}

// Network fee, collapsed to one line ("up to X ETH · Y Gwei") with the two
// EIP-1559 editors behind an Edit toggle. A parse error force-opens the editors
// so the flagged field is visible.
function FeeSection({
  tx,
  maxFeeGwei,
  onMaxFee,
  feeError,
  maxPrioGwei,
  onMaxPrio,
  prioError,
  t,
}: {
  tx: TxDisplay;
  maxFeeGwei: string;
  onMaxFee: (v: string) => void;
  feeError: boolean;
  maxPrioGwei: string;
  onMaxPrio: (v: string) => void;
  prioError: boolean;
  t: TFn;
}) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (feeError || prioError) setOpen(true);
  }, [feeError, prioError]);

  // Worst-case fee from the (possibly edited) max fee; falls back to the
  // prepared tx values while the edited text isn't parseable.
  let feeSummary = "";
  try {
    const gas = BigInt(tx.gas || "0x0");
    const maxFeeWei = parseUnits(maxFeeGwei, 9);
    const amount = fmtUnitsDisplay(toHexQuantity(gas * maxFeeWei), 18);
    // Dust totals (cheap L2s) round to "0" — the Gwei figure alone says more.
    feeSummary = amount === "0" ? "" : t("approval.feeUpTo", { amount, symbol: tx.symbol });
  } catch {
    feeSummary = "";
  }

  return (
    <div className="apv-feebox">
      <div className="apv-fee-row">
        <span className="apv-fee-label">{t("approval.feeLabel")}</span>
        <span className="apv-fee-sum mono">
          {feeSummary ? `${feeSummary} · ` : ""}{maxFeeGwei || "—"} Gwei
        </span>
        <button type="button" className="apv-fee-toggle" onClick={() => setOpen((o) => !o)}>
          {open ? t("approval.feeDone") : t("approval.feeEdit")}
        </button>
      </div>
      {open && (
        <>
          <FeeInput label={t("approval.maxPriority")} value={maxPrioGwei} onChange={onMaxPrio} err={prioError} hint={t("approval.maxPriorityHint")} />
          <FeeInput label={t("approval.maxFee")} value={maxFeeGwei} onChange={onMaxFee} err={feeError} hint={t("approval.maxFeeHint")} />
        </>
      )}
    </div>
  );
}

// Pre-sign balance-change preview from the simulation API.
function SimPreview({ sim, pending, t }: { sim: SimulationPreview | null; pending: boolean; t: TFn }) {
  // The empty result ("no changes") carries one bit of information — collapse
  // it to a single line instead of a full card.
  if (!pending && sim && sim.status === "success" && sim.changes.length === 0) {
    return (
      <div className="apv-sim slim">
        <div className="apv-sim-head">
          <Icon name="activity" size={14} /> {t("approval.simTitle")}
        </div>
        <span className="apv-sim-note">{t("approval.simNoChange")}</span>
      </div>
    );
  }
  return (
    <div className="apv-sim">
      <div className="apv-sim-head">
        <Icon name="activity" size={14} /> {t("approval.simTitle")}
        {pending && <span className="apv-sim-tag">{t("approval.simulating")}</span>}
      </div>
      {pending ? (
        <div className="apv-sim-skel">
          <span className="skeleton" style={{ width: "60%", height: 14 }} />
          <span className="skeleton" style={{ width: "40%", height: 14 }} />
        </div>
      ) : sim && sim.status === "failed" ? (
        <div className="apv-sim-bad">
          <Icon name="alert" size={15} /> {sim.error || t("approval.simRevert")}
        </div>
      ) : sim && sim.status === "unavailable" ? (
        <div className="apv-sim-note">{t("approval.simUnavailable")}</div>
      ) : sim && sim.changes.length > 0 ? (
        <div className="apv-sim-list">
          {sim.changes.map((c) => (
            <div key={c.key} className={`apv-sim-row ${c.direction}`}>
              <span className="sym">{c.symbol}</span>
              <span className="delta mono">{c.formattedDelta}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="apv-sim-note">{t("approval.simNoChange")}</div>
      )}
    </div>
  );
}

// The tx as the EIP-1193 params a dApp sent, pretty-printed (raw hex values).
function txAsJson(tx: TxDisplay): string {
  return JSON.stringify(
    {
      from: tx.from,
      to: tx.to,
      value: tx.value,
      data: tx.data,
      gas: tx.gas,
      nonce: tx.nonce,
      maxFeePerGas: tx.max_fee_per_gas,
      maxPriorityFeePerGas: tx.max_priority_fee_per_gas,
      chainId: tx.chain_id,
    },
    null,
    2,
  );
}

function toBigintSafe(hex: string): string {
  try {
    return BigInt(hex).toString();
  } catch {
    return hex;
  }
}

// One editable EIP-1559 fee field (in Gwei).
function FeeInput({
  label,
  value,
  onChange,
  err,
  hint,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  err: boolean;
  hint: string;
}) {
  return (
    <div className="apv-fee">
      <label className="field-label">{label}</label>
      <div className={`apv-fee-input${err ? " err" : ""}`}>
        <input className="input mono" value={value} inputMode="decimal" onChange={(e) => onChange(e.target.value)} />
        <span className="apv-fee-unit">Gwei</span>
      </div>
      <div className="apv-fee-hint">{hint}</div>
    </div>
  );
}

function Row({
  label,
  value,
  mono,
  danger,
}: {
  label: string;
  value: string;
  mono?: boolean;
  danger?: boolean;
}) {
  return (
    <div className="apv-row">
      <span className="apv-row-l">{label}</span>
      <span className={`apv-row-v${mono ? " mono" : ""}${danger ? " danger" : ""}`}>{value}</span>
    </div>
  );
}

function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

function formatDeadline(deadline: bigint | null, t: TFn): string {
  if (deadline === null) return "—";
  if (deadline >= 253402300800n) return t("approval.permitNeverExpires"); // ≥ year 10000
  return new Date(Number(deadline) * 1000).toLocaleString();
}

// One allowance inside a permit: token, amount, and its own expiration (Permit2).
function PermitGrantRows({
  grant,
  chainHex,
  heading,
  t,
}: {
  grant: PermitGrant;
  chainHex: string | null;
  heading: string | null;
  t: TFn;
}) {
  const [tokenMeta, setTokenMeta] = useState<{ symbol: string; decimals: number } | null>(null);

  useEffect(() => {
    setTokenMeta(null);
    if (!grant.token || !chainHex || grant.amountRaw === null || grant.unlimited) return;
    let cancelled = false;
    // Display-only enrichment: if metadata can't load, the raw amount (the
    // ground truth) stays on screen — nothing is hidden or defaulted.
    void Promise.all([readErc20Symbol(chainHex, grant.token), readErc20Decimals(chainHex, grant.token)])
      .then(([symbol, decimals]) => {
        if (!cancelled) setTokenMeta({ symbol, decimals });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [grant.token, chainHex, grant.amountRaw, grant.unlimited]);

  const allowanceLabel = grant.unlimited
    ? t("approval.permitAmountUnlimited")
    : grant.amountRaw === null
      ? "—"
      : tokenMeta
        ? `${formatTokenAmountForInput(grant.amountRaw, tokenMeta.decimals)} ${tokenMeta.symbol}`
        : t("approval.rawAmount", { n: grant.amountRaw.toString() });

  return (
    <>
      {heading && <div className="field-label apv-permit-entry">{heading}</div>}
      <Row
        label={t("approval.token")}
        value={
          grant.token === null
            ? "—"
            : tokenMeta
              ? `${tokenMeta.symbol} (${shortAddress(grant.token, 8, 6)})`
              : shortAddress(grant.token, 10, 8)
        }
        mono={!tokenMeta}
        danger={grant.token === null}
      />
      <Row label={t("approval.allowance")} value={allowanceLabel} danger={grant.unlimited || grant.amountRaw === null} />
      {grant.expiration !== null && (
        <Row
          label={t("approval.permitExpiration")}
          value={formatDeadline(grant.expiration, t)}
          danger={grant.expiration >= 253402300800n}
        />
      )}
    </>
  );
}

// Full EIP-712 payload display: permit warning (spender/allowance/deadline) when
// the signature grants token spending, then domain + primaryType + the complete
// message. A summary line alone would be blind signing.
export function TypedDataDetails({ data, t }: { data: TypedDataPayload; t: TFn }) {
  const permit = useMemo(() => detectPermit(data), [data]);
  const delegateCall = useMemo(() => isSafeDelegateCall(data), [data]);
  const domain = (data.domain ?? {}) as Record<string, unknown>;

  return (
    <div className="apv-typed">
      {delegateCall && (
        <div className="apv-permit">
          <div className="apv-permit-title">
            <Icon name="alert" size={15} /> {t("approval.safeDelegateTitle")}
          </div>
          <div className="apv-permit-body">{t("approval.safeDelegateBody")}</div>
        </div>
      )}
      {permit && (
        <div className="apv-permit">
          <div className="apv-permit-title">
            <Icon name="alert" size={15} /> {t("approval.permitWarnTitle")}
          </div>
          <div className="apv-permit-body">{t("approval.permitWarnBody")}</div>
          {permit.incomplete && (
            <div className="apv-permit-body danger">{t("approval.permitIncomplete")}</div>
          )}
          {permit.spender && (
            <Row label={t("approval.spender")} value={shortAddress(permit.spender, 10, 8)} mono />
          )}
          {/* Every grant, never just the first: a batch can hide an unlimited
              allowance behind a harmless first entry (review #2). */}
          {permit.grants.map((grant, i) => (
            <PermitGrantRows
              key={i}
              grant={grant}
              chainHex={permit.chainHex}
              heading={
                permit.grants.length > 1
                  ? t("approval.permitEntry", { n: i + 1, total: permit.grants.length })
                  : null
              }
              t={t}
            />
          ))}
          <Row
            label={t("approval.deadline")}
            value={formatDeadline(permit.deadline, t)}
            danger={permit.deadline !== null && permit.deadline >= 253402300800n}
          />
        </div>
      )}
      <div className="apv-tx">
        {typeof domain.name === "string" && (
          <Row label={t("approval.typedDomain")} value={domain.name} />
        )}
        {typeof domain.version === "string" && (
          <Row label={t("approval.typedVersion")} value={domain.version} />
        )}
        {domain.chainId != null && (
          <Row label={t("approval.typedChainId")} value={String(domain.chainId)} mono />
        )}
        {typeof domain.verifyingContract === "string" && (
          <Row
            label={t("approval.typedContract")}
            value={shortAddress(domain.verifyingContract, 10, 8)}
            mono
          />
        )}
        {typeof data.primaryType === "string" && (
          <Row label={t("approval.typedType")} value={data.primaryType} mono />
        )}
      </div>
      <div>
        <div className="field-label" style={{ padding: "0 2px 7px" }}>
          {t("approval.message")}
        </div>
        <pre className="apv-msg">{JSON.stringify(data.message, null, 2)}</pre>
      </div>
    </div>
  );
}

// Decoded ERC-20 transfer details (read-only) for a dApp transaction.
export function TransferSection({
  tx,
  details,
  t,
}: {
  tx: TxDisplay;
  details: TransferDetails;
  t: TFn;
}) {
  const [meta, setMeta] = useState<{ symbol: string; decimals: number } | null>(null);
  const [metaFailed, setMetaFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setMeta(null);
    setMetaFailed(false);
    // Display-only enrichment: on failure the raw amount + token address stay
    // visible and a note says why — never a silently-guessed 18 decimals.
    void Promise.all([
      readErc20Symbol(tx.chain_id, details.tokenAddress),
      readErc20Decimals(tx.chain_id, details.tokenAddress),
    ])
      .then(([symbol, decimals]) => {
        if (!cancelled) setMeta({ symbol, decimals });
      })
      .catch(() => {
        if (!cancelled) setMetaFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [tx.chain_id, details.tokenAddress]);

  return (
    <div className="apv-approve-editor">
      <div className="apv-approve-head">
        <span>{t("approval.transferTitle")}</span>
        <span className="apv-approve-pill">{t("approval.decoded")}</span>
      </div>
      <Row
        label={t("approval.token")}
        value={
          meta
            ? `${meta.symbol} (${shortAddress(details.tokenAddress, 8, 6)})`
            : shortAddress(details.tokenAddress, 10, 8)
        }
        mono={!meta}
      />
      {details.owner && (
        <Row label={t("approval.transferOwner")} value={shortAddress(details.owner, 10, 8)} mono />
      )}
      <Row
        label={t("approval.transferRecipient")}
        value={shortAddress(details.recipient, 10, 8)}
        mono
      />
      <Row
        label={t("approval.amount")}
        value={
          meta
            ? `${formatTokenAmountForInput(details.amountRaw, meta.decimals)} ${meta.symbol}`
            : t("approval.rawAmount", { n: details.amountRaw.toString() })
        }
      />
      {metaFailed && <div className="apv-approve-error">{t("approval.tokenMetaFailed")}</div>}
      <NativeValueNotice tx={tx} t={t} />
    </div>
  );
}

/// Sentinel for an `eth_call` that returned no data (`0x`): the address has no
/// contract code on the queried chain — in practice, the wallet is on a
/// different network than the dApp expects. Mapped to a human explanation at
/// the display site (a raw BigInt SyntaxError here confused users).
const TOKEN_EMPTY_RESULT = "token-call-returned-empty";

function isTokenEmptyResult(e: unknown): boolean {
  return e instanceof Error && e.message === TOKEN_EMPTY_RESULT;
}

function readHexWord(raw: string): bigint {
  const hex = (raw ?? "").trim();
  if (hex === "" || hex === "0x") throw new Error(TOKEN_EMPTY_RESULT);
  return BigInt(hex);
}

async function loadApprovalTokenInfo(
  chainId: string,
  tokenAddress: string,
  owner: string,
): Promise<ApprovalTokenInfo> {
  const [symbol, decimals, balanceRaw] = await Promise.all([
    readErc20Symbol(chainId, tokenAddress),
    readErc20Decimals(chainId, tokenAddress),
    rpc<string>(chainId, "eth_call", [
      { to: tokenAddress, data: `0x70a08231${owner.replace(/^0x/, "").padStart(64, "0")}` },
      "latest",
    ]),
  ]);
  return {
    symbol,
    decimals,
    balanceRaw,
    balance: formatTokenAmountForInput(readHexWord(balanceRaw), decimals),
  };
}

async function readErc20Symbol(chainId: string, tokenAddress: string): Promise<string> {
  try {
    const raw = await rpc<string>(chainId, "eth_call", [
      { to: tokenAddress, data: "0x95d89b41" },
      "latest",
    ]);
    return decodeAbiString(raw) || "TOKEN";
  } catch {
    return "TOKEN";
  }
}

async function readErc20Decimals(chainId: string, tokenAddress: string): Promise<number> {
  // NO fallback on failure: a guessed default (18) would re-encode an edited
  // approve at the wrong scale (e.g. USDC is 6) — a funds-loss bug. Fail loudly;
  // callers decide whether to block (approve editor) or degrade to raw display.
  const raw = await rpc<string>(chainId, "eth_call", [
    { to: tokenAddress, data: "0x313ce567" },
    "latest",
  ]);
  const value = Number(readHexWord(raw));
  if (!Number.isFinite(value) || value < 0 || value > 255) {
    throw new Error(`unexpected ERC-20 decimals() result: ${raw}`);
  }
  return value;
}

function decodeAbiString(raw: string): string {
  const hex = raw.replace(/^0x/, "");
  if (hex.length === 64) return decodeBytes(hex);
  if (hex.length >= 128) {
    const len = Number(BigInt(`0x${hex.slice(64, 128)}`));
    if (Number.isFinite(len) && len >= 0) {
      return decodeBytes(hex.slice(128, 128 + len * 2));
    }
  }
  return "";
}

function decodeBytes(hex: string): string {
  const bytes = hex.match(/.{1,2}/g)?.map((b) => Number.parseInt(b, 16)) ?? [];
  const trimmed = bytes.filter((b) => b !== 0);
  return new TextDecoder().decode(new Uint8Array(trimmed)).trim();
}

function formatTokenAmountForInput(value: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const frac = value % base;
  if (frac === 0n) return whole.toString();
  return `${whole}.${frac.toString().padStart(decimals, "0").replace(/0+$/, "")}`;
}

// Last line of defence for anything the decoders above still miss: a render
// error must not leave a blank window with the request stuck at the head of the
// queue. The fallback cannot approve — it only rejects, then retries the view.
class ApprovalErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null; busy: boolean }
> {
  state = { error: null as Error | null, busy: false };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("[approval] render failed", error);
  }

  private rejectCurrent = async () => {
    this.setState({ busy: true });
    try {
      const list = await invoke<PendingRequest[]>("get_pending_requests");
      if (list[0]) await invoke("reject_request", { id: list[0].id });
    } finally {
      this.setState({ error: null, busy: false });
    }
  };

  render() {
    if (!this.state.error) return this.props.children;
    return <ApprovalRenderFailed busy={this.state.busy} onReject={this.rejectCurrent} error={this.state.error} />;
  }
}

function ApprovalRenderFailed({
  busy,
  onReject,
  error,
}: {
  busy: boolean;
  onReject: () => void;
  error: Error;
}) {
  const { t } = useT();
  return (
    <div className="approval idle">
      <div>
        <div className="idle-mark">
          <Icon name="alert" size={26} />
        </div>
        <p>{t("approval.renderFailed")}</p>
        <pre className="apv-msg">{error.message}</pre>
        <button className="btn btn-ghost btn-lg" disabled={busy} onClick={onReject}>
          {t("approval.reject")}
        </button>
      </div>
    </div>
  );
}

export default function ApprovalWindow() {
  return (
    <ApprovalErrorBoundary>
      <ApprovalView />
    </ApprovalErrorBoundary>
  );
}
