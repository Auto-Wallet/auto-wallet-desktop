import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { TFn } from "./lib/i18n";
import { VaultLoadError } from "./VaultLoadError";

const t = ((key: string) => key) as TFn;

test("a failed vault load shows the reason and retry without offering to delete or reset keys", () => {
  const html = renderToStaticMarkup(<VaultLoadError t={t} error="journal checksum mismatch; recovery files retained" busy={false} onRetry={() => {}} />);
  expect(html).toContain("journal checksum mismatch; recovery files retained");
  expect(html).toContain("wallet.loadFailed");
  expect(html).toContain("wallet.loadFailedHint");
  expect(html).toContain("wallet.retry");
  expect(html).not.toContain("reset");
  expect(html).not.toContain("delete");
});

test("a retry in flight disables the retry button", () => {
  const html = renderToStaticMarkup(<VaultLoadError t={t} error="read failed" busy onRetry={() => {}} />);
  expect(html).toMatch(/<button[^>]*disabled=""/);
});
