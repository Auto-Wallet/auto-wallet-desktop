import { afterEach, expect, test } from 'bun:test';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { RelayProvider } from './relay-provider';
import { NATIVE_TOKEN_ADDRESS, type QuoteParams } from './types';

Object.defineProperty(globalThis, 'window', { value: globalThis, configurable: true });
const originalFetch = globalThis.fetch;
function blockFrontendFetch(message: string) {
  globalThis.fetch = Object.assign(async () => { throw new Error(message); }, {
    preconnect: originalFetch.preconnect,
  });
}
afterEach(() => {
  clearMocks();
  globalThis.fetch = originalFetch;
});

const params: QuoteParams = {
  fromChainId: 8453, toChainId: 42161,
  fromToken: { chainId: 8453, address: NATIVE_TOKEN_ADDRESS, symbol: 'ETH', name: 'Ether', decimals: 18, logo: '' },
  toToken: { chainId: 42161, address: NATIVE_TOKEN_ADDRESS, symbol: 'ETH', name: 'Ether', decimals: 18, logo: '' },
  fromAddress: '0x1111111111111111111111111111111111111111',
  toAddress: '0x2222222222222222222222222222222222222222',
  fromAmount: '0.01', slippage: 0.005,
};

test('Relay quotes use backend authentication and preserve swap inputs', async () => {
  const calls: unknown[] = [];
  blockFrontendFetch('Missing API key: frontend request is unauthenticated');
  mockIPC((command, args) => {
    calls.push({ command, args });
    return {
      steps: [], fees: {},
      details: { currencyOut: { amount: '9000000000000000', amountFormatted: '0.009' } },
    };
  });

  const quote = await new RelayProvider().getQuote(params);

  expect(quote.amountOutRaw).toBe('9000000000000000');
  expect(quote.amountOutMinRaw).toBe('8955000000000000');
  expect(calls).toEqual([{ command: 'relay_quote', args: { body: {
    user: params.fromAddress, recipient: params.toAddress,
    originChainId: 8453, destinationChainId: 42161,
    originCurrency: NATIVE_TOKEN_ADDRESS, destinationCurrency: NATIVE_TOKEN_ADDRESS,
    amount: '10000000000000000', tradeType: 'EXACT_INPUT', slippageTolerance: '50',
    appFees: [{ recipient: '0x7521EDa00E2Ce05aC4a9d8353d096CCB970d5188', fee: '10' }],
    referrer: 'auto-desktop',
  } } }]);
});

test('Relay metadata and status also use fixed backend commands', async () => {
  blockFrontendFetch('Relay requests must use the backend');
  const calls: unknown[] = [];
  mockIPC((command, args) => {
    calls.push({ command, args });
    if (command === 'relay_chains') return { chains: [{
      id: 8453, name: 'Base', vmType: 'evm',
      currency: { symbol: 'ETH', name: 'Ether', address: NATIVE_TOKEN_ADDRESS, decimals: 18 },
    }] };
    if (command === 'relay_status') return { status: 'success', txHashes: ['0xdestination'] };
    throw new Error(`Unexpected command: ${command}`);
  });
  const provider = new RelayProvider();
  expect(await provider.loadChains()).toEqual([{ chainId: 8453, name: 'Base', logo: '', nativeSymbol: 'ETH' }]);
  expect((await provider.loadTokensByChain()).get(8453)).toEqual([params.fromToken]);
  const status = await provider.getStatus({ params, sourceHash: '0xsource', requestId: 'req&another=value' });
  expect(status.state).toBe('success');
  expect(status.destHash).toBe('0xdestination');
  expect(calls).toEqual([
    { command: 'relay_chains', args: {} },
    { command: 'relay_chains', args: {} },
    { command: 'relay_status', args: { requestId: 'req&another=value' } },
  ]);
});

test('Relay backend errors remain visible in the quote UI', async () => {
  mockIPC(() => { throw 'RELAY_API_KEY is not configured'; });
  let caught: unknown;
  try { await new RelayProvider().getQuote(params); } catch (error) { caught = error; }
  expect(caught instanceof Error).toBe(true);
  expect((caught as Error).message).toBe('RELAY_API_KEY is not configured');
});

// Security review addendum #3: a quote fetched for one amount was sent after the
// user had typed another — prepareSwap took the old quote's tx as-is.
function depositQuote(stepChainId: number) {
  mockIPC(() => ({
    steps: [{
      id: 'deposit', action: '', description: '', kind: 'transaction', requestId: 'r-1',
      items: [{ status: 'incomplete', data: {
        to: '0x3333333333333333333333333333333333333333', data: '0x', value: '10000000000000000', chainId: stepChainId,
      } }],
    }],
    fees: {},
    details: { currencyOut: { amount: '9000000000000000', amountFormatted: '0.009' } },
  }));
  return new RelayProvider().getQuote(params);
}

test('a Relay quote prepares only for the inputs it was quoted for', async () => {
  const quote = await depositQuote(8453);
  const same = await new RelayProvider().prepareSwap({ ...params, fromAmount: '0.010' }, quote);
  expect(same.swapTx).toEqual({
    to: '0x3333333333333333333333333333333333333333', data: '0x', value: '10000000000000000', chainId: 8453,
  });

  for (const changed of [
    { ...params, fromAmount: '0.001' },
    { ...params, toChainId: 10 },
    { ...params, toAddress: '0x4444444444444444444444444444444444444444' },
    { ...params, slippage: 0.01 },
    { ...params, fromToken: { ...params.fromToken, address: '0x5555555555555555555555555555555555555555' } },
  ]) {
    let caught: unknown;
    try { await new RelayProvider().prepareSwap(changed, quote); } catch (e) { caught = e; }
    expect((caught as Error)?.message).toContain('out of date');
  }
});

test('a Relay deposit on another chain than the source is refused', async () => {
  const quote = await depositQuote(1);
  let caught: unknown;
  try { await new RelayProvider().prepareSwap(params, quote); } catch (e) { caught = e; }
  expect((caught as Error)?.message).toContain('chain 1');
});
