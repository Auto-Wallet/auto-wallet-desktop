import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

if (!("localStorage" in globalThis)) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: () => null },
  });
}

const { ImportWalletForm, LedgerForm, WatchForm } = await import("./WalletPage");
const { ImportForm, LedgerPanel } = await import("./LockScreen");
const done = () => {};
const props = { onBack: done, onDone: done };

for (const [name, form] of [
  ["first-run recovery phrase import", <ImportForm {...props} />],
  ["add-wallet recovery phrase import", <ImportWalletForm {...props} needsPassword={false} />],
  ["first-run Ledger import", <LedgerPanel {...props} />],
  ["add-wallet Ledger import", <LedgerForm {...props} />],
  ["watch address import", <WatchForm {...props} />],
] as const) {
  test(`${name} includes an optional wallet name`, () => {
    const html = renderToStaticMarkup(form);
    const inputs = html.match(/<input\b[^>]*name="walletName"[^>]*>/g);
    expect(inputs?.length).toBe(1);
    expect(inputs![0]).not.toContain("required");
    expect(html).toMatch(/钱包名称（可选）|Wallet name \(optional\)/);
  });
}
