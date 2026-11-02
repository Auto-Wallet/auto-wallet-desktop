import { expect, test } from 'bun:test';
import { NATIVE_TOKEN_ADDRESS, sameQuoteInputs, type QuoteParams } from './types';

const base: QuoteParams = {
  fromChainId: 1, toChainId: 8453,
  fromToken: { chainId: 1, address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', symbol: 'USDC', name: 'USD Coin', decimals: 6, logo: '' },
  toToken: { chainId: 8453, address: NATIVE_TOKEN_ADDRESS, symbol: 'ETH', name: 'Ether', decimals: 18, logo: '' },
  fromAddress: '0x1111111111111111111111111111111111111111',
  toAddress: '0x1111111111111111111111111111111111111111',
  fromAmount: '12.5', slippage: 0.005,
};

test('same raw amount and same addresses in other case are the same inputs', () => {
  expect(sameQuoteInputs(base, { ...base, fromAmount: '12.500000' })).toBe(true);
  expect(sameQuoteInputs(base, {
    ...base,
    fromToken: { ...base.fromToken, address: base.fromToken.address.toLowerCase(), logo: 'x' },
  })).toBe(true);
});

test('any input that changes the trade makes a different quote', () => {
  const changes: Partial<QuoteParams>[] = [
    { fromAmount: '12.500001' },
    { fromAmount: '1.25' },
    { fromChainId: 10 },
    { toChainId: 1 },
    { toToken: { ...base.toToken, address: '0x4200000000000000000000000000000000000006' } },
    { fromToken: { ...base.fromToken, decimals: 18 } }, // same text, different raw amount
    { fromAddress: '0x2222222222222222222222222222222222222222' },
    { toAddress: '0x2222222222222222222222222222222222222222' },
    { slippage: 0.01 },
  ];
  for (const change of changes) {
    expect(sameQuoteInputs(base, { ...base, ...change })).toBe(false);
  }
});

test('an amount that does not parse never matches', () => {
  expect(sameQuoteInputs({ ...base, fromAmount: 'abc' }, { ...base, fromAmount: 'abc' })).toBe(false);
});
