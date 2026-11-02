// Relay.link provider adapter. Wraps the Relay v2 API endpoints we care
// about and exposes the neutral `SwapProvider` interface.
//
// Reference: https://docs.relay.link/references/api/overview
// OpenAPI:  https://api.relay.link/documentation/json
//
// Relay returns a single /quote/v2 response that already contains:
//  - human-readable swap details (amounts, fees, rate, slippage, eta)
//  - an ordered list of "steps" (approve + deposit) with fully-encoded tx
//    payloads, so we don't need a separate buildTx call.
// We extract everything we need from that response.

import { invoke } from '@tauri-apps/api/core';
import { formatUnits, parseUnits } from '../format';
import {
  isEvmChainId,
  isNativeAddress,
  NATIVE_TOKEN_ADDRESS,
  type NeutralFee,
  type NeutralQuote,
  type NeutralStatus,
  type PreparedSwap,
  type ProviderChain,
  type ProviderToken,
  type QuoteParams,
  sameQuoteInputs,
  type StatusArgs,
  type SwapProvider,
} from './types';

// App-fee config: every quote request adds 0.1% in basis points to the
// configured recipient. The user explicitly chose these settings.
const APP_FEE_RECIPIENT = '0x7521EDa00E2Ce05aC4a9d8353d096CCB970d5188';
const APP_FEE_BPS = '10'; // 10 bps = 0.1%

// Subset of Relay /chains response. Keeps just the fields we touch.
interface RelayChain {
  id: number;
  name: string;
  displayName?: string;
  vmType?: string;
  disabled?: boolean;
  iconUrl?: string | null;
  logoUrl?: string | null;
  currency?: { symbol?: string; name?: string; address?: string; decimals?: number };
  featuredTokens?: RelayCurrency[];
  erc20Currencies?: RelayCurrency[];
}

interface RelayCurrency {
  id?: string;
  symbol?: string;
  name?: string;
  address?: string;
  decimals?: number;
  metadata?: { logoURI?: string };
}

interface RelayCurrencyAmount {
  currency: {
    chainId: number;
    address: string;
    symbol: string;
    name: string;
    decimals: number;
    metadata?: { logoURI?: string; isNative?: boolean };
  };
  amount: string;
  amountFormatted: string;
  amountUsd?: string;
  minimumAmount?: string;
}

interface RelayStepItem {
  status: 'complete' | 'incomplete';
  data: {
    from?: string;
    to?: string;
    data?: string;
    value?: string;
    chainId?: number;
  };
  check?: { endpoint?: string; method?: string };
}

interface RelayStep {
  id: 'deposit' | 'approve' | 'authorize' | 'authorize1' | 'authorize2' | 'swap' | 'send';
  action: string;
  description: string;
  kind: 'transaction' | 'signature';
  requestId?: string;
  items: RelayStepItem[];
}

interface RelayQuoteResponse {
  steps: RelayStep[];
  fees: {
    gas?: RelayCurrencyAmount;
    relayer?: RelayCurrencyAmount;
    relayerGas?: RelayCurrencyAmount;
    relayerService?: RelayCurrencyAmount;
    app?: RelayCurrencyAmount;
  };
  details: {
    operation?: string;
    currencyIn?: RelayCurrencyAmount;
    currencyOut?: RelayCurrencyAmount;
    totalImpact?: { usd?: string; percent?: string };
    rate?: string;
    slippageTolerance?: { destination?: { percent?: string } };
    timeEstimate?: number;
  };
}

interface RelayStatusResponse {
  status: 'refund' | 'waiting' | 'depositing' | 'failure' | 'pending' | 'submitted' | 'success';
  details?: string;
  inTxHashes?: string[];
  txHashes?: string[];
  updatedAt?: number;
  originChainId?: number;
  destinationChainId?: number;
}

// Tauri rejects Rust errors as strings. Normalize at this API boundary so the
// quote UI displays the cause instead of its generic "Quote failed" message.
async function invokeRelay<T>(
  command: 'relay_chains' | 'relay_quote' | 'relay_status',
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error));
  }
}

export class RelayProvider implements SwapProvider {
  id = 'relay' as const;
  displayName = 'Relay';

  async loadChains(): Promise<ProviderChain[]> {
    const { chains } = await invokeRelay<{ chains: RelayChain[] }>('relay_chains');
    return chains
      .filter((c) => (c.vmType ?? 'evm') === 'evm' && !c.disabled && isEvmChainId(c.id))
      .map((c) => ({
        chainId: c.id,
        name: c.displayName || c.name,
        logo: c.iconUrl || c.logoUrl || '',
        nativeSymbol: c.currency?.symbol ?? '',
      }));
  }

  async loadTokensByChain(): Promise<Map<number, ProviderToken[]>> {
    // /chains already includes featuredTokens + erc20Currencies + native — one
    // call gives us a workable token universe without paginating /currencies.
    const { chains } = await invokeRelay<{ chains: RelayChain[] }>('relay_chains');
    const map = new Map<number, ProviderToken[]>();
    for (const c of chains) {
      if (!isEvmChainId(c.id)) continue;
      if ((c.vmType ?? 'evm') !== 'evm') continue;
      if (c.disabled) continue;
      const seen = new Set<string>();
      const list: ProviderToken[] = [];
      // Native first
      if (c.currency?.symbol) {
        const addr = (c.currency.address ?? NATIVE_TOKEN_ADDRESS).toLowerCase();
        seen.add(addr);
        list.push({
          chainId: c.id,
          address: addr === '' ? NATIVE_TOKEN_ADDRESS : addr,
          symbol: c.currency.symbol,
          name: c.currency.name ?? c.currency.symbol,
          decimals: c.currency.decimals ?? 18,
          logo: c.iconUrl || c.logoUrl || '',
        });
      }
      for (const t of [...(c.featuredTokens ?? []), ...(c.erc20Currencies ?? [])]) {
        if (!t.address || !t.symbol) continue;
        const addr = t.address.toLowerCase();
        if (seen.has(addr)) continue;
        seen.add(addr);
        list.push({
          chainId: c.id,
          address: addr,
          symbol: t.symbol,
          name: t.name ?? t.symbol,
          decimals: t.decimals ?? 18,
          logo: t.metadata?.logoURI ?? '',
        });
      }
      if (list.length > 0) map.set(c.id, list);
    }
    return map;
  }

  async getQuote(params: QuoteParams): Promise<NeutralQuote> {
    const amountRaw = parseUnits(params.fromAmount, params.fromToken.decimals).toString();
    const body = {
      user: params.fromAddress,
      recipient: params.toAddress,
      originChainId: params.fromChainId,
      destinationChainId: params.toChainId,
      originCurrency: relayCurrencyAddress(params.fromToken.address),
      destinationCurrency: relayCurrencyAddress(params.toToken.address),
      amount: amountRaw,
      tradeType: 'EXACT_INPUT',
      slippageTolerance: Math.round(params.slippage * 10_000).toString(),
      appFees: [{ recipient: APP_FEE_RECIPIENT, fee: APP_FEE_BPS }],
      referrer: 'auto-desktop',
    };
    const q = await invokeRelay<RelayQuoteResponse>('relay_quote', { body });
    return toNeutralQuote(q, params);
  }

  async prepareSwap(params: QuoteParams, quote: NeutralQuote): Promise<PreparedSwap> {
    // The cached tx below was priced for quote.quotedFor. Sending it for any
    // other inputs would sign a different trade than the screen shows.
    if (!sameQuoteInputs(quote.quotedFor, params)) {
      throw new Error('Relay quote is out of date for the current inputs — wait for the new quote');
    }
    // The opaque payload is the full quote response (cached during getQuote).
    // Pull the deposit step (the actual cross-chain send).
    const raw = quote.raw as RelayQuoteResponse;
    const depositStep = raw.steps.find((s) => s.id === 'deposit' || s.id === 'swap' || s.id === 'send');
    if (!depositStep) throw new Error('Relay quote returned no deposit step');
    const item = depositStep.items.find((i) => i.status === 'incomplete') ?? depositStep.items[0];
    if (!item?.data?.to) throw new Error('Relay deposit step missing tx data');
    if (item.data.chainId !== undefined && item.data.chainId !== params.fromChainId) {
      throw new Error(
        `Relay deposit is on chain ${item.data.chainId}, not the source chain ${params.fromChainId}`,
      );
    }
    return {
      providerId: this.id,
      swapTx: {
        to: item.data.to,
        data: item.data.data ?? '0x',
        value: item.data.value ?? '0',
        chainId: item.data.chainId ?? params.fromChainId,
      },
      requestId: depositStep.requestId,
    };
  }

  async getStatus({ params, sourceHash, requestId }: StatusArgs): Promise<NeutralStatus> {
    if (!requestId) {
      // Without a requestId we can't query Relay's status endpoint. Fall back
      // to a pending state so the UI keeps the user informed via tx links.
      return {
        state: 'pending',
        message: 'Awaiting Relay request id',
        sourceHash,
        receiveSymbol: params.toToken.symbol,
      };
    }
    const r = await invokeRelay<RelayStatusResponse>('relay_status', { requestId });
    return toNeutralStatus(r, params, sourceHash);
  }
}

function relayCurrencyAddress(address: string): string {
  // Relay accepts the all-zero address for native currency, same as XFlows.
  return isNativeAddress(address) ? NATIVE_TOKEN_ADDRESS : address;
}

function toNeutralQuote(q: RelayQuoteResponse, params: QuoteParams): NeutralQuote {
  const out = q.details?.currencyOut;
  const amountOut = out?.amountFormatted ?? '0';
  const amountOutRaw = out?.amount ?? '0';
  // Relay returns slippage as percent string on destination — compute min
  // received from amount × (1 - slippage). If absent, fall back to params.
  const destSlipPct = parseFloat(q.details?.slippageTolerance?.destination?.percent ?? '');
  const slipFrac = isFinite(destSlipPct) && destSlipPct > 0 ? destSlipPct / 100 : params.slippage;
  const amountOutMinRaw = (() => {
    try {
      const raw = BigInt(amountOutRaw);
      // multiply by (1 - slipFrac) using bps math to stay in integers
      const bps = BigInt(Math.max(0, Math.round((1 - slipFrac) * 10_000)));
      return ((raw * bps) / 10_000n).toString();
    } catch { return amountOutRaw; }
  })();
  const amountOutMin = (() => {
    try { return trimAmount(formatUnits(amountOutMinRaw, params.toToken.decimals, 8), 8); }
    catch { return amountOut; }
  })();

  const fees: NeutralFee[] = [];
  const gas = q.fees?.gas;
  if (gas?.currency?.symbol && gas?.amount) {
    fees.push({
      kind: 'network',
      amount: gas.amountFormatted || formatRaw(gas.amount, gas.currency.decimals),
      symbol: gas.currency.symbol,
    });
  }
  const relayer = q.fees?.relayer;
  if (relayer?.currency?.symbol && relayer?.amount) {
    fees.push({
      kind: 'relay',
      amount: relayer.amountFormatted || formatRaw(relayer.amount, relayer.currency.decimals),
      symbol: relayer.currency.symbol,
    });
  }
  const appFee = q.fees?.app;
  if (appFee?.currency?.symbol && appFee?.amount && BigInt(appFee.amount) > 0n) {
    fees.push({
      kind: 'app',
      amount: appFee.amountFormatted || formatRaw(appFee.amount, appFee.currency.decimals),
      symbol: appFee.currency.symbol,
    });
  }

  // Approval: if a step with id='approve' is present, decode its calldata to
  // extract the spender. We expose only the spender; the wallet's existing
  // approve flow will encode `approve(spender, MAX)` itself.
  const approveStep = q.steps?.find((s) => s.id === 'approve');
  const approvalSpender = approveStep ? decodeApproveSpender(approveStep) : undefined;

  // Decimal-aware impact percent (Relay returns a string).
  const impactPct = parseFloat(q.details?.totalImpact?.percent ?? '');
  const route = `Relay${q.details?.operation ? ` · ${q.details.operation}` : ''}`;

  // Net value for ranking. `currencyOut.amountUsd` is what the user actually
  // receives — relayer + app fees are already deducted from it server-side,
  // so we only subtract the *extra* costs paid on top: origin-chain gas.
  const amountOutUsd = parseFloatSafe(q.details?.currencyOut?.amountUsd);
  const gasUsd = parseFloatSafe(q.fees?.gas?.amountUsd);
  const netValueUsd = amountOutUsd !== undefined
    ? amountOutUsd - (gasUsd ?? 0)
    : undefined;

  return {
    providerId: 'relay',
    amountOut,
    amountOutRaw,
    amountOutMin,
    amountOutMinRaw,
    priceImpact: isFinite(impactPct) ? impactPct : undefined,
    rate: q.details?.rate,
    fees,
    routeDescription: route,
    estimatedTimeSeconds: q.details?.timeEstimate,
    approvalSpender,
    amountOutUsd,
    netValueUsd,
    raw: q,
    quotedFor: params,
  };
}

function parseFloatSafe(s: string | undefined): number | undefined {
  if (!s) return undefined;
  const n = parseFloat(s);
  return isFinite(n) ? n : undefined;
}

function decodeApproveSpender(step: RelayStep): string | undefined {
  const data = step.items?.find((i) => i.data?.data)?.data?.data;
  if (!data) return undefined;
  try {
    const hex = data.toLowerCase();
    if (!hex.startsWith('0x095ea7b3') || hex.length < 10 + 64) return undefined;
    return `0x${hex.slice(10 + 24, 10 + 64)}`;
  } catch {
    return undefined;
  }
}

function toNeutralStatus(
  r: RelayStatusResponse,
  params: QuoteParams,
  sourceHash: string,
): NeutralStatus {
  const state: NeutralStatus['state'] = (() => {
    switch (r.status) {
      case 'success': return 'success';
      case 'failure': return 'failed';
      case 'refund': return 'refunded';
      default: return 'pending'; // waiting, depositing, pending, submitted
    }
  })();
  return {
    state,
    message: r.details ?? r.status,
    sourceHash: r.inTxHashes?.[0] ?? sourceHash,
    destHash: r.txHashes?.[0],
    receiveSymbol: params.toToken.symbol,
  };
}

function formatRaw(raw: string, decimals: number): string {
  try { return trimAmount(formatUnits(raw, decimals, 8), 8); } catch { return raw; }
}

function trimAmount(s: string, maxDecimals: number): string {
  const num = parseFloat(s);
  if (!isFinite(num)) return s;
  if (num === 0) return '0';
  if (num >= 1) return num.toLocaleString('en-US', { maximumFractionDigits: 4 });
  const fixed = num.toFixed(maxDecimals);
  return fixed.replace(/\.?0+$/, '');
}
