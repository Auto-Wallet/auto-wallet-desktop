import { Icon } from "../lib/icons";
import { isUsdStablecoin } from "../lib/okxAccount";

export function formatMoney(value: string): string {
  const number = Number(value);
  if (!Number.isFinite(number)) return value;
  return new Intl.NumberFormat(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(number);
}

export function formatCurrencyAmount(value: string, currency: string): string {
  const number = Number(value);
  if (!Number.isFinite(number)) return value;
  const fractionDigits = isUsdStablecoin(currency) ? 2 : 6;
  return new Intl.NumberFormat(undefined, {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  }).format(number);
}

export function formatDate(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function Coin({ currency }: { currency: string }) {
  const known: Record<string, { glyph: string; className: string }> = {
    BTC: { glyph: "₿", className: "btc" },
    ETH: { glyph: "◆", className: "eth" },
    USDC: { glyph: "$", className: "usdc" },
    USDT: { glyph: "₮", className: "usdt" },
  };
  const appearance = known[currency];
  return (
    <span className={`okx-coin${appearance === undefined ? "" : ` ${appearance.className}`}`}>
      {appearance === undefined ? currency.slice(0, 1) : appearance.glyph}
    </span>
  );
}

export function InlineError({ message }: { message: string }) {
  return <div className="okx-inline-error"><Icon name="alert" size={17} /><span>{message}</span></div>;
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return <div className="okx-empty"><span><Icon name="doc" size={22} /></span><strong>{title}</strong>{hint !== undefined && <p>{hint}</p>}</div>;
}

export function TableSkeleton({ rows }: { rows: number }) {
  return <div className="okx-skeleton">{Array.from({ length: rows }, (_, index) => <span key={index} />)}</div>;
}
