import { useT } from "../lib/i18n";
import type { OkxTradingBalance } from "../lib/okxAccount";
import { getOkxLoanRisk, type OkxAppliedRates, type OkxFlexibleLoan, type OkxFlexibleLoans, type OkxLoanRates, type OkxSavings } from "../lib/okxFinance";
import { Coin, EmptyState, InlineError, TableSkeleton, formatDate, formatMoney } from "./OkxDisplay";

const numberFormatter = new Intl.NumberFormat(undefined, { maximumSignificantDigits: 12 });
const percentFormatter = new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 4 });

function amount(value: string | null): string {
  return value === null ? "—" : numberFormatter.format(Number(value));
}

function percent(value: string | number): string {
  return percentFormatter.format(Number(value));
}

export function TradingBalanceTable({ balances }: { balances: OkxTradingBalance[] | null }) {
  const { t } = useT();
  if (balances === null) return <TableSkeleton rows={3} />;
  if (balances.length === 0) return <EmptyState title={t("okx.noAssets")} />;
  const hasDebt = balances.some(({ liability, interest }) => Number(liability) > 0 || Number(interest) > 0);
  return (
    <div className="okx-table-wrap">
      <table className="okx-table okx-finance-table">
        <thead><tr>
          <th>{t("okx.asset")}</th>
          <th>{t("okx.spotBalance")}</th>
          <th>{t("okx.cashBalance")}</th>
          <th>{t("okx.available")}</th>
          <th>{t("okx.frozen")}</th>
          {hasDebt && <th>{t("okx.tradingLiability")}</th>}
          {hasDebt && <th>{t("okx.interest")}</th>}
        </tr></thead>
        <tbody>{balances.map((row) => (
          <tr key={row.currency}>
            <td><Coin currency={row.currency} /><strong>{row.currency}</strong></td>
            <td className="tnum"><strong>{amount(row.spotBalance)}</strong></td>
            <td className="tnum">{amount(row.cashBalance)}</td>
            <td className="tnum">{amount(row.available)}</td>
            <td className="tnum">{amount(row.frozen)}</td>
            {hasDebt && <td className="tnum">{amount(row.liability)}</td>}
            {hasDebt && <td className="tnum">{amount(row.interest)}</td>}
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function SavingsTable({ savings, error }: { savings: OkxSavings | null; error: string | null }) {
  const { t } = useT();
  if (error !== null) return <InlineError message={error} />;
  if (savings === null) return <TableSkeleton rows={2} />;
  if (savings.balances.length === 0) return <EmptyState title={t("okx.noSavings")} />;
  return (
    <>
      {savings.rates.error !== null && (
        <InlineError message={t("okx.savingsRateError", { detail: savings.rates.error })} />
      )}
      <div className="okx-table-wrap">
        <table className="okx-table okx-finance-table">
          <thead><tr>
            <th>{t("okx.asset")}</th>
            <th>{t("okx.balance")}</th>
            <th>{t("okx.lent")}</th>
            <th>{t("okx.pendingLending")}</th>
            <th>{t("okx.minimumApr")}</th>
            <th>{t("okx.lendingApr")}</th>
            <th>{t("okx.savingsEarnings")}</th>
          </tr></thead>
          <tbody>{savings.balances.map((row) => {
            const rate = savings.rates.data === null ? undefined : savings.rates.data.get(row.currency);
            return (
              <tr key={row.currency}>
                <td><Coin currency={row.currency} /><strong>{row.currency}</strong></td>
                <td className="tnum"><strong>{amount(row.balance)}</strong></td>
                <td className="tnum">{amount(row.lent)}</td>
                <td className="tnum">{amount(row.pending)}</td>
                <td className="tnum">{percent(row.minimumApr)}</td>
                <td className="tnum">
                  {rate === undefined ? "—" : (
                    <><strong>{percent(rate.annualRate)}</strong><small>{formatDate(rate.appliedAt)}</small></>
                  )}
                </td>
                <td className="tnum">{amount(row.earnings)}</td>
              </tr>
            );
          })}</tbody>
        </table>
      </div>
    </>
  );
}

export function FlexibleLoanSection({ loans, loanRates, rateError, error }: {
  loans: OkxFlexibleLoans | null;
  loanRates: OkxLoanRates | null;
  rateError: string | null;
  error: string | null;
}) {
  const { t } = useT();

  return (
    <section className="okx-section okx-loans-section">
      <div className="okx-section-head">
        <div>
          <h2>{t("okx.flexibleLoan")}</h2>
          <p>{t("okx.flexibleLoanHint")}</p>
        </div>
        {loans !== null && error === null && (
          <time className="okx-finance-updated" dateTime={new Date(loans.updatedAt).toISOString()}>
            {t("okx.updatedAt", { time: formatDate(loans.updatedAt) })}
          </time>
        )}
      </div>
      {rateError !== null && <InlineError message={t("okx.loanRateError", { detail: rateError })} />}
      {error !== null ? <InlineError message={error} />
        : loans === null ? <TableSkeleton rows={2} />
        : loans.orders.length === 0 ? <EmptyState title={t("okx.noLoans")} />
        : <div className="okx-loan-list">{loans.orders.map((loan) => (
          <LoanCard key={loan.orderId} loan={loan} rates={loanRates === null ? undefined : loanRates.get(loan.orderId)} />
        ))}</div>}
    </section>
  );
}

function LoanCard({ loan, rates }: { loan: OkxFlexibleLoan; rates: OkxAppliedRates | undefined }) {
  const { t } = useT();
  const risk = getOkxLoanRisk(loan);
  const scale = Math.max(1, loan.liquidationLtv, loan.currentLtv);
  const marginCallPosition = loan.marginCallLtv / scale * 100;
  const liquidationPosition = loan.liquidationLtv / scale * 100;
  const currentPosition = loan.currentLtv / scale * 100;
  const quote = loan.liquidation === null ? null : loan.liquidation.instrumentId.split("-").pop();

  return (
    <article className="okx-loan-card" data-risk={risk.state}>
      <div className="okx-loan-head">
        <h3>{t("okx.orderId")} <span>#{loan.orderId}</span></h3>
        <span className="okx-loan-state">{t(`okx.loanState.${risk.state}`)}</span>
      </div>
      <div className="okx-loan-body">
        <div className="okx-loan-risk">
          <dl className="okx-loan-metrics">
            <div>
              <dt>{t("okx.healthFactor")}</dt>
              <dd className="okx-health-value tnum">{risk.healthFactor === null ? "—" : risk.healthFactor.toFixed(2)}</dd>
            </div>
            <div>
              <dt>{t("okx.liquidationPrice")}</dt>
              <dd>
                {loan.liquidation === null ? <span>—</span> : (
                  <><strong className="tnum">{amount(loan.liquidation.price)} {quote}</strong><small>{loan.liquidation.instrumentId}</small></>
                )}
              </dd>
            </div>
          </dl>
          <div className="okx-ltv-chart" aria-hidden="true">
            <div className="okx-ltv-track" style={{ gridTemplateColumns: `${marginCallPosition}fr ${liquidationPosition - marginCallPosition}fr ${100 - liquidationPosition}fr` }}>
              <i /><i /><i />
            </div>
            <span className="okx-ltv-marker" style={{ left: `${currentPosition}%` }} />
          </div>
          <dl className="okx-ltv-legend">
            <div><dt>{t("okx.currentLtv")}</dt><dd className="tnum">{percent(loan.currentLtv)}</dd></div>
            <div><dt>{t("okx.marginCallLtv")}</dt><dd className="tnum">{percent(loan.marginCallLtv)}</dd></div>
            <div><dt>{t("okx.liquidationLtv")}</dt><dd className="tnum">{percent(loan.liquidationLtv)}</dd></div>
          </dl>
          <p className="okx-loan-caption">
            {t("okx.liquidationHeadroom", {
              value: new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(risk.liquidationHeadroom * 100),
            })}
            {loan.liquidation === null && (
              <> · {t(loan.collateral.length > 1 || loan.debts.length > 1 ? "okx.multiCurrencyLiquidation" : "okx.liquidationUnavailable")}</>
            )}
          </p>
        </div>
        <div className="okx-loan-assets">
          <div className="okx-loan-assets-group">
            <h4>{t("okx.adjustedCollateral")} <strong className="tnum">${formatMoney(loan.adjustedCollateralUsd)}</strong></h4>
            <ul>{loan.collateral.map((row) => (
              <li key={row.currency}><span>{row.currency}</span><strong className="tnum">{amount(row.amount)}</strong></li>
            ))}</ul>
          </div>
          <div className="okx-loan-assets-group">
            <h4>{t("okx.outstandingDebt")} <strong className="tnum">${formatMoney(loan.debtUsd)}</strong></h4>
            {rates !== undefined && rates.error !== null && (
              <InlineError message={t("okx.loanRateError", { detail: rates.error })} />
            )}
            <ul>{loan.debts.map((row) => {
              const rate = rates === undefined || rates.data === null ? undefined : rates.data.get(row.currency);
              return (
                <li key={row.currency}>
                  <div>
                    <span>{row.currency}</span>
                    <small title={rate === undefined ? undefined : formatDate(rate.appliedAt)}>
                      {t("okx.latestBorrowApy")} {rate === undefined ? "—" : percent(rate.annualRate)}
                    </small>
                  </div>
                  <div>
                    <strong className="tnum">{amount(row.amount)}</strong>
                    {rate !== undefined && (
                      <small>{t("okx.latestBorrowInterest", { amount: amount(rate.interest) })}</small>
                    )}
                  </div>
                </li>
              );
            })}</ul>
          </div>
        </div>
      </div>
    </article>
  );
}
