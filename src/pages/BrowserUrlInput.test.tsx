import { expect, test } from "bun:test";
import type { InputHTMLAttributes, KeyboardEvent, ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { BrowserUrlInput } from "./BrowserUrlInput";

function urlInput(
  onNavigate: (url: string) => Promise<void>,
  onError: (error: unknown) => void = (error) => { throw error; },
) {
  let input!: ReactElement<InputHTMLAttributes<HTMLInputElement>>;
  function Probe() {
    // Drive the real input handler; React supplies the component's hooks.
    input = BrowserUrlInput({
      currentUrl: "https://app.uniswap.org/",
      onFocusChange: () => {},
      onNavigate,
      onError,
    });
    return input;
  }
  renderToStaticMarkup(<Probe />);
  return input.props;
}

test("Enter opens the edited address with its query and hash intact", async () => {
  const navigated: string[] = [];
  const input = urlInput(async (url) => { navigated.push(url); });
  let prevented = false;
  expect(typeof input.onKeyDown).toBe("function");
  await input.onKeyDown!({
    key: "Enter",
    nativeEvent: { isComposing: false },
    currentTarget: { value: " https://app.aave.com/markets/?market=base#supply " },
    preventDefault() { prevented = true; },
  } as unknown as KeyboardEvent<HTMLInputElement>);

  expect(navigated).toEqual(["https://app.aave.com/markets/?market=base#supply"]);
  expect(prevented).toBe(true);
});

test("invalid addresses report an error without navigating", async () => {
  const navigated: string[] = [];
  const errors: unknown[] = [];
  const input = urlInput(async (url) => { navigated.push(url); }, (error) => errors.push(error));
  for (const value of ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "", "not a URL"]) {
    await input.onKeyDown!({
      key: "Enter",
      nativeEvent: { isComposing: false },
      currentTarget: { value },
      preventDefault() {},
    } as unknown as KeyboardEvent<HTMLInputElement>);
  }
  expect(navigated).toEqual([]);
  expect(errors.length).toBe(5);
  expect(errors.every((error) => error instanceof Error)).toBe(true);
});

test("addresses without a scheme use HTTPS", async () => {
  const navigated: string[] = [];
  const input = urlInput(async (url) => { navigated.push(url); });
  await input.onKeyDown!({
    key: "Enter",
    nativeEvent: { isComposing: false },
    currentTarget: { value: "app.aave.com/markets/?market=base#supply" },
    preventDefault() {},
  } as unknown as KeyboardEvent<HTMLInputElement>);
  expect(navigated).toEqual(["https://app.aave.com/markets/?market=base#supply"]);
});

test("HTTP and local hosts with ports keep the full address", async () => {
  const navigated: string[] = [];
  const input = urlInput(async (url) => { navigated.push(url); });
  for (const value of ["http://localhost:1420/demo?chain=1#connect", "localhost:1420/demo", "[::1]:1420/demo"]) {
    await input.onKeyDown!({
      key: "Enter",
      nativeEvent: { isComposing: false },
      currentTarget: { value },
      preventDefault() {},
    } as unknown as KeyboardEvent<HTMLInputElement>);
  }
  expect(navigated).toEqual([
    "http://localhost:1420/demo?chain=1#connect",
    "https://localhost:1420/demo",
    "https://[::1]:1420/demo",
  ]);
});

test("typing and IME confirmation do not submit the address", async () => {
  const navigated: string[] = [];
  const input = urlInput(async (url) => { navigated.push(url); });
  let prevented = 0;
  for (const [key, isComposing] of [["a", false], ["Enter", true]] as const) {
    await input.onKeyDown!({
      key,
      nativeEvent: { isComposing },
      currentTarget: { value: "https://app.aave.com/" },
      preventDefault() { prevented++; },
    } as unknown as KeyboardEvent<HTMLInputElement>);
  }
  expect(navigated).toEqual([]);
  expect(prevented).toBe(0);
});

test("a failed navigation reports the original error", async () => {
  const failure = new Error("Webview navigation failed");
  const errors: unknown[] = [];
  const input = urlInput(async () => { throw failure; }, (error) => errors.push(error));
  await input.onKeyDown!({
    key: "Enter",
    nativeEvent: { isComposing: false },
    currentTarget: { value: "https://app.aave.com/" },
    preventDefault() {},
  } as unknown as KeyboardEvent<HTMLInputElement>);
  expect(errors).toEqual([failure]);
});
