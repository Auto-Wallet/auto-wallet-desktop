import { describe, expect, test } from "bun:test";
import {
  MAX_UINT160,
  MAX_UINT256,
  chainIdToHex,
  detectPermit,
  encodeErc20Approve,
  isSafeDelegateCall,
  parseApprovalDetails,
  parseTransferDetails,
} from "./decode";

const TOKEN = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
const SPENDER = "0x1111111254eeb25477b68fb85ed929f73a960582";
const RECIPIENT = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
const OWNER = "0xab5801a7d398351b8be11c439e05c5b3259aec9b";

const pad = (hex: string) => hex.replace(/^0x/, "").toLowerCase().padStart(64, "0");

describe("parseTransferDetails", () => {
  test("decodes transfer(address,uint256) — recipient and amount, not the token contract", () => {
    const amount = 1_234_567n; // 1.234567 USDC (6 decimals)
    const tx = { to: TOKEN, data: `0xa9059cbb${pad(RECIPIENT)}${pad(`0x${amount.toString(16)}`)}` };
    const d = parseTransferDetails(tx);
    expect(d).not.toBeNull();
    expect(d!.tokenAddress).toBe(TOKEN);
    expect(d!.recipient.toLowerCase()).toBe(RECIPIENT.toLowerCase());
    expect(d!.owner).toBeNull();
    expect(d!.amountRaw).toBe(amount);
  });

  test("decodes transferFrom(address,address,uint256) including the owner", () => {
    const amount = 99_000_000_000_000_000_000n; // 99 tokens at 18 decimals
    const tx = {
      to: TOKEN,
      data: `0x23b872dd${pad(OWNER)}${pad(RECIPIENT)}${pad(`0x${amount.toString(16)}`)}`,
    };
    const d = parseTransferDetails(tx);
    expect(d!.owner!.toLowerCase()).toBe(OWNER.toLowerCase());
    expect(d!.recipient.toLowerCase()).toBe(RECIPIENT.toLowerCase());
    expect(d!.amountRaw).toBe(amount);
  });

  test("returns null for other selectors and truncated calldata", () => {
    expect(parseTransferDetails({ to: TOKEN, data: `0x095ea7b3${pad(SPENDER)}${pad("0x1")}` })).toBeNull();
    expect(parseTransferDetails({ to: TOKEN, data: `0xa9059cbb${pad(RECIPIENT)}` })).toBeNull();
    expect(parseTransferDetails({ to: TOKEN, data: "0x" })).toBeNull();
    expect(parseTransferDetails({ to: "", data: `0xa9059cbb${pad(RECIPIENT)}${pad("0x1")}` })).toBeNull();
  });
});

// Security review 2026-11-02 #5: a non-hex amount word made BigInt() throw
// during render, which blanked the whole approval window.
describe("malformed amount words return null instead of throwing", () => {
  const junkWords = ["z".repeat(64), `${"0".repeat(63)} `, `-${"1".repeat(63)}`, `0x${"1".repeat(62)}`];
  for (const junk of junkWords) {
    test(`approve with amount word ${JSON.stringify(junk.slice(0, 6))}…`, () => {
      expect(parseApprovalDetails({ to: TOKEN, data: `0x095ea7b3${pad(SPENDER)}${junk}` })).toBeNull();
    });
    test(`transfer with amount word ${JSON.stringify(junk.slice(0, 6))}…`, () => {
      expect(parseTransferDetails({ to: TOKEN, data: `0xa9059cbb${pad(RECIPIENT)}${junk}` })).toBeNull();
    });
    test(`transferFrom with amount word ${JSON.stringify(junk.slice(0, 6))}…`, () => {
      expect(
        parseTransferDetails({ to: TOKEN, data: `0x23b872dd${pad(OWNER)}${pad(RECIPIENT)}${junk}` }),
      ).toBeNull();
    });
  }
});

describe("parseApprovalDetails / encodeErc20Approve", () => {
  test("decode → re-encode round-trips exactly", () => {
    const amount = 500_000_000n; // 500 USDC
    const data = encodeErc20Approve(SPENDER, amount);
    const d = parseApprovalDetails({ to: TOKEN, data });
    expect(d!.spender.toLowerCase()).toBe(SPENDER.toLowerCase());
    expect(d!.amountRaw).toBe(amount);
    expect(encodeErc20Approve(d!.spender, d!.amountRaw)).toBe(data);
  });
});

describe("detectPermit", () => {
  test("ERC-2612 permit: spender, value, deadline, token = verifyingContract", () => {
    const deadline = 1_780_000_000n;
    const p = detectPermit({
      domain: { name: "USD Coin", chainId: 1, verifyingContract: TOKEN },
      primaryType: "Permit",
      message: {
        owner: OWNER,
        spender: SPENDER,
        value: "250000000",
        nonce: 0,
        deadline: deadline.toString(),
      },
    });
    expect(p).not.toBeNull();
    expect(p!.spender).toBe(SPENDER);
    expect(p!.grants[0].token).toBe(TOKEN);
    expect(p!.grants[0].amountRaw).toBe(250_000_000n);
    expect(p!.unlimited).toBe(false);
    expect(p!.deadline).toBe(deadline);
    expect(p!.chainHex).toBe("0x1");
  });

  test("flags max-uint256 allowance as unlimited", () => {
    const p = detectPermit({
      domain: { name: "Token", chainId: 1, verifyingContract: TOKEN },
      primaryType: "Permit",
      message: { owner: OWNER, spender: SPENDER, value: MAX_UINT256.toString(), deadline: "1" },
    });
    expect(p!.unlimited).toBe(true);
  });

  test("DAI-style permit (allowed: true) is unlimited with no numeric amount", () => {
    const p = detectPermit({
      domain: { name: "Dai Stablecoin", chainId: 1, verifyingContract: TOKEN },
      primaryType: "Permit",
      message: { holder: OWNER, spender: SPENDER, nonce: 1, expiry: 0, allowed: true },
    });
    expect(p!.unlimited).toBe(true);
    expect(p!.grants[0].amountRaw).toBeNull();
  });

  test("Permit2 PermitSingle: token/amount/expiration come from details", () => {
    const p = detectPermit({
      domain: { name: "Permit2", chainId: 137, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
      primaryType: "PermitSingle",
      message: {
        details: { token: TOKEN, amount: MAX_UINT160.toString(), expiration: "1893456000", nonce: 0 },
        spender: SPENDER,
        sigDeadline: "1780001234",
      },
    });
    expect(p!.grants[0].token).toBe(TOKEN);
    expect(p!.spender).toBe(SPENDER);
    expect(p!.unlimited).toBe(true); // max uint160 = Permit2 "infinite"
    expect(p!.deadline).toBe(1_780_001_234n);
    expect(p!.chainHex).toBe("0x89");
  });

  test("Permit2 PermitBatch with a single entry", () => {
    const p = detectPermit({
      domain: { name: "Permit2", chainId: 1 },
      primaryType: "PermitBatch",
      message: {
        details: [{ token: TOKEN, amount: "777", expiration: "1700000000", nonce: 0 }],
        spender: SPENDER,
        sigDeadline: "1700000600",
      },
    });
    expect(p!.grants[0].token).toBe(TOKEN);
    expect(p!.grants[0].amountRaw).toBe(777n);
  });

  // Security review 2026-11-02 #2: the summary used to describe only the first
  // batch entry, so an unlimited grant in entry 2 never reached the screen.
  test("Permit2 PermitBatch: every entry is surfaced, unlimited in a later entry flags the whole permit", () => {
    const TOKEN_B = "0x6B175474E89094C44Da98b954EedeAC495271d0F"; // DAI
    const p = detectPermit({
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
    });
    expect(p!.grants).toHaveLength(2);
    expect(p!.grants[0]).toEqual({ token: TOKEN, amountRaw: 1n, unlimited: false, expiration: 1_700_000_000n });
    expect(p!.grants[1]).toEqual({
      token: TOKEN_B,
      amountRaw: MAX_UINT160,
      unlimited: true,
      expiration: 1_800_000_000n,
    });
    expect(p!.unlimited).toBe(true);
    expect(p!.incomplete).toBe(false);
  });

  test("Permit2 PermitBatchTransferFrom: every `permitted` entry is surfaced", () => {
    const p = detectPermit({
      domain: { name: "Permit2", chainId: 1 },
      primaryType: "PermitBatchTransferFrom",
      message: {
        permitted: [
          { token: TOKEN, amount: "5" },
          { token: SPENDER, amount: "0x10" },
          { token: RECIPIENT, amount: "7" },
        ],
        spender: SPENDER,
        nonce: 1,
        deadline: "1700000600",
      },
    });
    expect(p!.grants.map((g) => [g.token, g.amountRaw])).toEqual([
      [TOKEN, 5n],
      [SPENDER, 16n],
      [RECIPIENT, 7n],
    ]);
    expect(p!.unlimited).toBe(false);
    expect(p!.incomplete).toBe(false);
  });

  test("a batch entry that does not parse marks the permit incomplete", () => {
    for (const bad of [
      { token: TOKEN, amount: "0xzz" },
      { amount: "5" },
      "junk",
      null,
    ]) {
      const p = detectPermit({
        primaryType: "PermitBatch",
        message: { details: [{ token: TOKEN, amount: "1" }, bad], spender: SPENDER },
      });
      expect(p!.incomplete).toBe(true);
    }
    const empty = detectPermit({ primaryType: "PermitBatch", message: { details: [], spender: SPENDER } });
    expect(empty!.grants).toEqual([]);
    expect(empty!.incomplete).toBe(true);
  });

  test("ERC-2612 permit is a single grant on the verifying contract", () => {
    const p = detectPermit({
      domain: { chainId: 1, verifyingContract: TOKEN },
      primaryType: "Permit",
      message: { owner: OWNER, spender: SPENDER, value: "250", nonce: 0, deadline: "99" },
    });
    expect(p!.grants).toEqual([{ token: TOKEN, amountRaw: 250n, unlimited: false, expiration: null }]);
    expect(p!.incomplete).toBe(false);
  });

  test("non-permit typed data (EIP-712 Mail) is NOT flagged", () => {
    const p = detectPermit({
      domain: { name: "Ether Mail", chainId: 1, verifyingContract: TOKEN },
      primaryType: "Mail",
      message: { from: { name: "Cow" }, to: { name: "Bob" }, contents: "Hello, Bob!" },
    });
    expect(p).toBeNull();
  });

  test("junk values from a malicious dApp do not throw", () => {
    const p = detectPermit({
      domain: { chainId: "not-a-number" },
      primaryType: "Permit",
      message: { spender: SPENDER, value: "0xzz", deadline: {} },
    });
    expect(p).not.toBeNull(); // primaryType says Permit → still warn
    expect(p!.grants[0].amountRaw).toBeNull();
    expect(p!.deadline).toBeNull();
    expect(p!.chainHex).toBeNull();
    expect(p!.incomplete).toBe(true); // nothing on screen can be trusted as the full grant
  });
});

describe("chainIdToHex", () => {
  test("accepts number, decimal string, and hex string", () => {
    expect(chainIdToHex(1)).toBe("0x1");
    expect(chainIdToHex("137")).toBe("0x89");
    expect(chainIdToHex("0x38")).toBe("0x38");
    expect(chainIdToHex("garbage")).toBeNull();
    expect(chainIdToHex(0)).toBeNull();
  });
});

describe("isSafeDelegateCall", () => {
  const safeTx = (operation: unknown) => ({

    primaryType: "SafeTx",
    domain: { chainId: 1, verifyingContract: TOKEN },
    message: { to: TOKEN, value: "0", data: "0x", operation, nonce: 7 },
  });

  test("flags operation 1 (number or string) on a SafeTx", () => {
    expect(isSafeDelegateCall(safeTx(1))).toBe(true);
    expect(isSafeDelegateCall(safeTx("1"))).toBe(true);
  });

  test("a plain CALL is not flagged", () => {
    expect(isSafeDelegateCall(safeTx(0))).toBe(false);
    expect(isSafeDelegateCall(safeTx("0"))).toBe(false);
  });

  test("only SafeTx typed data is considered", () => {
    expect(isSafeDelegateCall({ ...safeTx(1), primaryType: "Permit" })).toBe(false);
    expect(isSafeDelegateCall({ primaryType: "SafeTx", domain: {} })).toBe(false);
  });
});
