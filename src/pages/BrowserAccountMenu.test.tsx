import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

if (!("localStorage" in globalThis)) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: () => null },
  });
}

const { BrowserAccountMenu } = await import("./BrowserAccountMenu");
const accounts = [
  { label: "Trading", address: "0x1234567890abcdef1234567890abcdef12345678" },
  { label: "资金库", address: "0xabcdef9876543210abcdef9876543210abcdef12" },
];

function renderMenu(query: string) {
  return renderToStaticMarkup(
    <BrowserAccountMenu
      accounts={accounts}
      activeAddress={accounts[1].address}
      query={query}
      onQueryChange={() => {}}
      onSelect={() => {}}
      onDismiss={() => {}}
      copyTitle="Copy"
      onCopied={() => {}}
    />,
  );
}

test("shows a search field and every account for a blank query", () => {
  const html = renderMenu("  ");
  expect(html).toContain('aria-label="Search wallets or addresses"');
  expect(html).toContain('autofocus=""');
  expect(html).toContain(">Trading<");
  expect(html).toContain(">资金库<");
  expect(html).toContain('class="acct-opt on"');
});

test("searches names with trimmed, case-insensitive text", () => {
  const html = renderMenu("  TRAD  ");
  expect(html).toContain(">Trading<");
  expect(html).not.toContain(">资金库<");
  expect(renderMenu("资金")).toContain(">资金库<");
});

test("searches full addresses and address fragments without case sensitivity", () => {
  for (const query of [accounts[1].address.toUpperCase(), "EF9876543210AB"]) {
    const html = renderMenu(query);
    expect(html).toContain(">资金库<");
    expect(html).not.toContain(">Trading<");
  }
});

test("shows an empty result message when nothing matches", () => {
  const html = renderMenu("missing wallet");
  expect(html).toContain("No matching addresses");
  expect(html).not.toContain('role="button"');
});
