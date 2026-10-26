import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

if (!("localStorage" in globalThis)) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: () => null },
  });
}
const { ChangePasswordModal, validatePasswordChange } = await import("./ChangePasswordModal");

test("requires the current password, at least eight characters, and matching confirmation", () => {
  expect(validatePasswordChange("", "new-password", "new-password")).toBe("settings.currentPasswordRequired");
  expect(validatePasswordChange("old-password", "short", "short")).toBe("lock.errShort");
  expect(validatePasswordChange("old-password", "new-password", "different")).toBe("lock.errMatch");
  expect(validatePasswordChange("old-password", "old-password", "old-password")).toBe("settings.passwordUnchanged");
  expect(validatePasswordChange("old-password", "new-password", "new-password")).toBeNull();
  expect(validatePasswordChange("old-password", "指纹密码安全测试", "指纹密码安全测试")).toBeNull();
});

test("renders current, new, and confirmation fields as passwords", () => {
  const html = renderToStaticMarkup(<ChangePasswordModal onClose={() => {}} onChanged={() => {}} />);
  expect(html.match(/type="password"/g)?.length).toBe(3);
  expect(html).toContain('autoComplete="current-password"');
  expect(html.match(/autoComplete="new-password"/g)?.length).toBe(2);
  expect(html).toContain('role="dialog"');
});
