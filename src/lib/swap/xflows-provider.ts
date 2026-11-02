// XFlows adapter — wraps the existing `lib/xflows` module and exposes the
// neutral `SwapProvider` interface so it can be used alongside Relay.
//
// We intentionally keep `lib/xflows.ts` untouched so any other code paths
// (background ERC20 helpers, etc.) keep working with the original types.

import {
  buildTx as xfBuildTx,
  getQuote as xfGetQuote,
  getStatus as xfGetStatus,
  getSupportedChains as xfGetSupportedChains,
  getSupportedTokens as xfGetSupportedTokens,
  isEvmChain,
  type XfQuote,
} from '../xflows';
import { formatUnits, parseUnits } from '../format';
import {
  isEvmChainId,
  type NeutralFee,
  type NeutralQuote,
  type NeutralStatus,
  type PreparedSwap,
  type ProviderChain,
  type ProviderToken,
  type QuoteParams,
  type StatusArgs,
  type SwapProvider,
} from './types';

export class XFlowsProvider implements SwapProvider {
  id = 'xflows' as const;
  displayName = 'Wanchain XFlows';

  async loadChains(): Promise<ProviderChain[]> {
    const chains = await xfGetSupportedChains();
    return chains.filter((c) => isEvmChain(c.chainId)).map((c) => ({
      chainId: c.chainId,
      name: c.chainName,
      logo: c.logo,
      nativeSymbol: c.symbol,
    }));
  }

  async loadTokensByChain(): Promise<Map<number, ProviderToken[]>> {
    const entries = await xfGetSupportedTokens();
    const map = new Map<number, ProviderToken[]>();
    for (const entry of entries) {
      if (!isEvmChainId(entry.chainId)) continue;
      map.set(
        entry.chainId,
        entry.tokens.map((t) => ({
          chainId: entry.chainId,
          address: t.tokenContractAddress,
          symbol: t.tokenSymbol,
          name: t.tokenName,
          decimals: Number(t.decimals),
          logo: t.tokenLogoUrl,
        })),
      );
    }
    return map;
  }

  async getQuote(params: QuoteParams): Promise<NeutralQuote> {
    const q = await xfGetQuote({
      fromChainId: params.fromChainId,
      toChainId: params.toChainId,
      fromTokenAddress: params.fromToken.address,
      toTokenAddress: params.toToken.address,
      fromAddress: params.fromAddress,
      toAddress: params.toAddress,
      fromAmount: params.fromAmount,
      slippage: params.slippage,
    });
    if (q.error) throw new Error(q.error);
    return toNeutralQuote(q, params);
  }

  async prepareSwap(params: QuoteParams, _quote: NeutralQuote): Promise<PreparedSwap> {
    const built = await xfBuildTx({
      fromChainId: params.fromChainId,
      toChainId: params.toChainId,
      fromTokenAddress: params.fromToken.address,
      toTokenAddress: params.toToken.address,
      fromAddress: params.fromAddress,
      toAddress: params.toAddress,
      fromAmount: params.fromAmount,
      slippage: params.slippage,
      partner: 'auto-desktop',
    });
    if (!built.tx?.to) throw new Error('XFlows did not return a target tx');
    return {
      providerId: this.id,
      swapTx: {
        to: built.tx.to,
        data: built.tx.data ?? '0x',
        value: built.tx.value ?? '0',
        chainId: built.chainId ?? params.fromChainId,
      },
    };
  }

  async getStatus({ params, sourceHash }: StatusArgs): Promise<NeutralStatus> {
    try {
      const status = await xfGetStatus({
        fromChainId: params.fromChainId,
        toChainId: params.toChainId,
        fromTokenAddress: params.fromToken.address,
        toTokenAddress: params.toToken.address,
        fromAddress: params.fromAddress,
        toAddress: params.toAddress,
        fromAmount: params.fromAmount,
        hash: sourceHash,
      });
      return toNeutralStatus(status, params, sourceHash);
    } catch (e: unknown) {
      // XFlows answers HTTP 200 + {success:false, error:"Tx Failed"} when the
      // source tx is on-chain but reverted. lib/xflows turns that into a
      // throw, but it's a terminal state, not an indexing delay — surface it
      // as a failed NeutralStatus so the poller stops and the UI shows the
      // failure. Anything else we re-throw so the poller keeps retrying.
      const msg = e instanceof Error ? e.message : String(e);
      if (isXFlowsTerminalError(msg)) {
        return {
          state: 'failed',
          message: msg,
          sourceHash,
          receiveSymbol: params.toToken.symbol,
        };
      }
      throw e;
    }
  }
}

// Exported for testing. Treats messages that indicate the source tx itself
// failed on-chain as terminal; everything else (network errors, "not found"
// while indexing) stays transient and lets the caller retry.
export function isXFlowsTerminalError(message: string): boolean {
  const m = message.toLowerCase();
  return m.includes('tx failed')
    || m.includes('transaction failed')
    || m.includes('reverted');
}

// Exported for direct testing (see tests/swap-provider.test.ts).
export function toNeutralQuote(q: XfQuote, params: QuoteParams): NeutralQuote {
  const toDecimals = params.toToken.decimals;
  const fees: NeutralFee[] = [];
  const dexExtra = (q.extraData as { dex?: RubicDexExtra } | undefined)?.dex;
  const messageFeeAmount = dexExtra?.params?.messageFee;
  let messageFeeClassified = false;
  for (const f of q.nativeFees ?? []) {
    if (f.nativeFeeAmount && f.nativeFeeSymbol) {
      const isMessageFee = !messageFeeClassified
        && messageFeeAmount != null
        && f.nativeFeeAmount === messageFeeAmount;
      if (isMessageFee) messageFeeClassified = true;
      fees.push({
        kind: isMessageFee ? 'message' : 'network',
        amount: formatRaw(f.nativeFeeAmount, f.nativeFeeDecimals ?? 18),
        symbol: f.nativeFeeSymbol,
      });
    }
  }
  for (const f of q.tokenFees ?? []) {
    if (f.tokenFeeAmount && f.tokenFeeSymbol) {
      fees.push({
        kind: 'bridge',
        amount: formatRaw(f.tokenFeeAmount, f.tokenFeeDecimals ?? 18),
        symbol: f.tokenFeeSymbol,
      });
    }
  }

  // For rubic-routed XFlows quotes, the top-level `nativeFees`/`tokenFees`
  // arrays come back empty — the actual fee breakdown lives inside
  // `extraData.dex.fees`. Mirror it into the neutral fee list so the
  // per-card display still shows the user what they're paying.
  // Same struct exposes `extraData.dex.estimate.durationInMinutes`, which is
  // the only ETA XFlows ever reports — surface it as estimatedTimeSeconds.
  let estimatedTimeSeconds: number | undefined;
  let amountOutUsd: number | undefined;
  let extraCostUsd: number | undefined;
  if (dexExtra) {
    if (fees.length === 0) {
      const gasFees = dexExtra.fees?.gasTokenFees;
      const native = gasFees?.nativeToken;
      const nativeSymbol = native?.symbol;
      const nativeDecimals = native?.decimals ?? 18;
      const gasWei = gasFees?.gas?.totalWeiAmount;
      if (gasWei && BigInt(gasWei) > 0n && nativeSymbol) {
        fees.push({ kind: 'network', amount: formatRaw(gasWei, nativeDecimals), symbol: nativeSymbol });
      }
      const protocolWei = gasFees?.protocol?.fixedWeiAmount;
      if (protocolWei && BigInt(protocolWei) > 0n && nativeSymbol) {
        fees.push({ kind: 'protocol', amount: formatRaw(protocolWei, nativeDecimals), symbol: nativeSymbol });
      }
      const providerWei = gasFees?.provider?.fixedWeiAmount;
      if (providerWei && BigInt(providerWei) > 0n && nativeSymbol) {
        fees.push({ kind: 'provider', amount: formatRaw(providerWei, nativeDecimals), symbol: nativeSymbol });
      }
      const pct = dexExtra.fees?.percentFees;
      if (pct?.token?.symbol && typeof pct.percent === 'number' && pct.percent > 0) {
        fees.push({ kind: 'dex', amount: `${(pct.percent * 100).toFixed(2)}%`, symbol: pct.token.symbol });
      }
    }
    const mins = dexExtra.estimate?.durationInMinutes;
    if (typeof mins === 'number' && isFinite(mins) && mins >= 0) {
      estimatedTimeSeconds = Math.round(mins * 60);
    }
    // USD values for net-value ranking. All three are paid on top of the
    // input in native currency, so they count as "extra cost". The percent
    // fee is taken from amountOut so it's already inside amountOutUsd.
    const dstUsd = dexExtra.estimate?.destinationUsdAmount;
    if (typeof dstUsd === 'number' && isFinite(dstUsd)) amountOutUsd = dstUsd;
    const sumUsd = (...xs: Array<number | undefined>) =>
      xs.reduce<number>((s, x) => s + (typeof x === 'number' && isFinite(x) ? x : 0), 0);
    const gasUsd = dexExtra.fees?.gasTokenFees?.gas?.totalUsdAmount;
    const protoUsd = dexExtra.fees?.gasTokenFees?.protocol?.fixedUsdAmount;
    const provUsd = dexExtra.fees?.gasTokenFees?.provider?.fixedUsdAmount;
    if (gasUsd !== undefined || protoUsd !== undefined || provUsd !== undefined) {
      extraCostUsd = sumUsd(gasUsd, protoUsd, provUsd);
    }
  }
  const netValueUsd = (amountOutUsd !== undefined && extraCostUsd !== undefined)
    ? amountOutUsd - extraCostUsd
    : undefined;

  // The XFlows API returns both amountOut and amountOutRaw; rely on raw to
  // compare quotes across providers (same decimals == direct comparison).
  const amountOutRaw = (() => {
    if (q.amountOutRaw) return q.amountOutRaw;
    try { return parseUnits(q.amountOut, toDecimals).toString(); } catch { return '0'; }
  })();
  const amountOutMinRaw = (() => {
    if (q.amountOutMinRaw) return q.amountOutMinRaw;
    try { return parseUnits(q.amountOutMin, toDecimals).toString(); } catch { return '0'; }
  })();
  return {
    providerId: 'xflows',
    amountOut: q.amountOut,
    amountOutRaw,
    amountOutMin: q.amountOutMin,
    amountOutMinRaw,
    priceImpact: q.priceImpact,
    fees,
    estimatedTimeSeconds,
    routeDescription: describeWorkMode(q.workMode, q.bridge, q.dex),
    approvalSpender: q.approvalAddress,
    amountOutUsd,
    netValueUsd,
    raw: q,
    quotedFor: params,
  };
}

// Shape of `extraData.dex` for rubic-routed quotes. We only care about the
// fee + duration fields; everything else is left as `unknown` to keep the
// type narrow while tolerating fields we don't surface.
interface RubicDexExtra {
  params?: {
    messageFee?: string;
  };
  estimate?: {
    durationInMinutes?: number;
    destinationUsdAmount?: number;
  };
  fees?: {
    gasTokenFees?: {
      nativeToken?: { symbol?: string; decimals?: number };
      gas?: { totalWeiAmount?: string; totalUsdAmount?: number };
      protocol?: { fixedWeiAmount?: string; fixedUsdAmount?: number };
      provider?: { fixedWeiAmount?: string; fixedUsdAmount?: number };
    };
    percentFees?: {
      percent?: number;
      token?: { symbol?: string };
    };
  };
}

function toNeutralStatus(
  status: import('../xflows').XfStatus,
  params: QuoteParams,
  sourceHash: string,
): NeutralStatus {
  const code = status.statusCode;
  let state: NeutralStatus['state'];
  if (code === 1) state = 'success';
  else if (code === 2 || code === 7) state = 'failed';
  else if (code === 4 || code === 5) state = 'refunded';
  else state = 'pending'; // 3 (Processing), 6 (Trusteeship)
  return {
    state,
    message: status.statusMsg,
    sourceHash: status.sourceHash ?? sourceHash,
    destHash: status.destinationHash,
    receiveAmount: status.receiveAmount,
    receiveSymbol: params.toToken.symbol,
    hint: code === 6 ? 'Trusteeship — contact techsupport@wanchain.org' : undefined,
  };
}

function describeWorkMode(workMode: number, bridge?: string, dex?: string): string {
  const base = (() => {
    switch (workMode) {
      case 1: return 'Direct bridge (WanBridge)';
      case 2: return 'Direct bridge (QUiX)';
      case 3: return 'Bridge + destination swap';
      case 4: return 'Bridge via Wanchain + swap out';
      case 5: return 'Same-chain swap';
      case 6: return 'Swap + bridge out';
      default: return `Mode ${workMode}`;
    }
  })();
  return [base, bridge, dex].filter(Boolean).join(' · ');
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
