import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

// i18n reads the saved language at module load; the test runtime has no DOM.
if (typeof localStorage === "undefined") {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    // Writable: later test files in the same run assign their own stub.
    writable: true,
    value: { getItem: () => null, setItem: () => {} },
  });
}
const { ApproveEditor, TransferSection, TypedDataDetails } = await import("./ApprovalView");
const { translate } = await import("./lib/i18n");
const { MAX_UINT160, MAX_UINT256 } = await import("./lib/decode");
const { shortAddress } = await import("./lib/format");

// Render with the real English strings: the assertions read what the user reads.
const t = (key: string, vars?: Record<string, string | number>) => translate("en", key, vars);

const TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const TOKEN_B = "0x6b175474e89094c44da98b954eedeac495271d0f";
const SPENDER = "0x1111111254eeb25477b68fb85ed929f73a960582";
const RECIPIENT = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";

function tx(value: string) {
  return {
    chain_id: "0x1",
    chain_name: "Ethereum",
    symbol: "ETH",
    from: RECIPIENT,
    to: TOKEN,
    value,
    data: "0x",
    gas: "0x5208",
    nonce: "0x0",
    max_priority_fee_per_gas: "0x1",
    max_fee_per_gas: "0x2",
  };
}

const INFO = { symbol: "USDC", decimals: 6, balanceRaw: "0x0", balance: "0" };
const noop = () => {};

describe("decoded tx cards show native coin sent along with the call (review addendum #1)", () => {
  const ONE_AND_HALF_ETH = `0x${(15n * 10n ** 17n).toString(16)}`;
  const nativeLine = t("approval.nativeAlsoSent", { amount: "1.5 ETH" });

  test("approve card shows a non-zero value", () => {
    const html = renderToStaticMarkup(
      <ApproveEditor
        tx={tx(ONE_AND_HALF_ETH)}
        details={{ tokenAddress: TOKEN, spender: SPENDER, amountRaw: 1n }}
        info={INFO}
        amount="0.000001"
        onAmount={noop}
        error=""
        t={t}
      />,
    );
    expect(html).toContain(nativeLine);
  });

  test("transfer card shows a non-zero value", () => {
    const html = renderToStaticMarkup(
      <TransferSection
        tx={tx(ONE_AND_HALF_ETH)}
        details={{ tokenAddress: TOKEN, owner: null, recipient: RECIPIENT, amountRaw: 1n }}
        t={t}
      />,
    );
    expect(html).toContain(nativeLine);
  });

  test("zero value adds no native line", () => {
    for (const v of ["0x0", "0x", "0x00"]) {
      const html = renderToStaticMarkup(
        <TransferSection
          tx={tx(v)}
          details={{ tokenAddress: TOKEN, owner: null, recipient: RECIPIENT, amountRaw: 1n }}
          t={t}
        />,
      );
      expect(html).not.toContain("apv-native-sent");
    }
  });
});

describe("approve card still shows the signed allowance when token info fails (review addendum #2)", () => {
  const failure = t("approval.approveTokenLoadFailed");

  test("raw allowance is on screen", () => {
    const raw = 987_654_321_123n;
    const html = renderToStaticMarkup(
      <ApproveEditor
        tx={tx("0x0")}
        details={{ tokenAddress: TOKEN, spender: SPENDER, amountRaw: raw }}
        info={null}
        amount=""
        onAmount={noop}
        error={failure}
        t={t}
      />,
    );
    expect(html).toContain(failure);
    expect(html).toContain(t("approval.rawAmount", { n: raw.toString() }));
  });

  test("max allowance is called unlimited", () => {
    const html = renderToStaticMarkup(
      <ApproveEditor
        tx={tx("0x0")}
        details={{ tokenAddress: TOKEN, spender: SPENDER, amountRaw: MAX_UINT256 }}
        info={null}
        amount=""
        onAmount={noop}
        error={failure}
        t={t}
      />,
    );
    expect(html).toContain(t("approval.permitAmountUnlimited"));
  });
});

describe("permit card lists every batch entry (review #2)", () => {
  test("second entry's token and unlimited allowance are on screen", () => {
    const html = renderToStaticMarkup(
      <TypedDataDetails
        data={{
          domain: { name: "Permit2", chainId: 1 },
          primaryType: "PermitBatch",
          message: {
            details: [
              { token: TOKEN, amount: "1", expiration: "1700000000", nonce: 0 },
              { token: TOKEN_B, amount: MAX_UINT160.toString(), expiration: "1800000000", nonce: 0 },
            ],
            spender: SPENDER,
            sigDeadline: "1700000600",
          },
        }}
        t={t}
      />,
    );
    expect(html).toContain(shortAddress(TOKEN, 10, 8));
    expect(html).toContain(shortAddress(TOKEN_B, 10, 8));
    expect(html).toContain(t("approval.rawAmount", { n: "1" }));
    expect(html).toContain(t("approval.permitAmountUnlimited"));
    expect(html).not.toContain(t("approval.permitIncomplete"));
  });

  test("an entry that does not parse is called out", () => {
    const html = renderToStaticMarkup(
      <TypedDataDetails
        data={{
          primaryType: "PermitBatch",
          message: { details: [{ token: TOKEN, amount: "1" }, { amount: "0xzz" }], spender: SPENDER },
        }}
        t={t}
      />,
    );
    expect(html).toContain(t("approval.permitIncomplete"));
  });
});
