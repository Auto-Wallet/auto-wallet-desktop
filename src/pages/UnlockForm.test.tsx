import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

if (!("localStorage" in globalThis)) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: () => null },
  });
}
const { UnlockForm } = await import("./LockScreen");

test("does not display or focus the password field before checking the preferred unlock method", () => {
  const html = renderToStaticMarkup(<UnlockForm onDone={() => {}} onForgot={() => {}} />);
  expect(html).not.toContain('type="password"');
  expect(html).toContain('disabled=""');
});
