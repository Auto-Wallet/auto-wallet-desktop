// Decoders for what a dApp actually asks the user to sign — pure functions, no
// Tauri/network access, so the approval window can show real recipients,
// spenders and amounts instead of opaque calldata. All input is UNTRUSTED.

/** The subset of a prepared transaction the decoders need. */
export interface CalldataCarrier {
  to: string;
  data: string;
}

/** The EIP-712 payload as the dApp sent it (every field may be junk). */
export interface TypedDataPayload {
  domain?: Record<string, unknown>;
  primaryType?: string;
  message?: unknown;
}

export type ApprovalDetails = {
  tokenAddress: string;
  spender: string;
  amountRaw: bigint;
};

/** A decoded ERC-20 transfer / transferFrom carried by a dApp transaction. */
export type TransferDetails = {
  tokenAddress: string;
  owner: string | null;
  recipient: string;
  amountRaw: bigint;
};

/** One token allowance inside a permit. A batch permit carries several. */
export type PermitGrant = {
  token: string | null;
  amountRaw: bigint | null;
  unlimited: boolean;
  /** Permit2 per-token `expiration`; null when the permit has none. */
  expiration: bigint | null;
};

/** What a permit-style EIP-712 signature would grant, extracted for display. */
export type PermitInfo = {
  spender: string | null;
  /** Every allowance the signature grants — ALL of them, never just the first. */
  grants: PermitGrant[];
  /** True when any grant failed to decode: the screen may not show everything signed. */
  incomplete: boolean;
  /** True when any grant is unlimited. */
  unlimited: boolean;
  deadline: bigint | null;
  chainHex: string | null;
};

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const WORD_RE = /^[0-9a-fA-F]{64}$/;

/** An ABI uint256 word, or null if it is not 64 hex digits. dApp calldata is
 *  untrusted: a bare BigInt() on junk throws and takes the render down. */
function wordToBigint(word: string): bigint | null {
  return WORD_RE.test(word) ? BigInt(`0x${word}`) : null;
}

export function parseApprovalDetails(tx: CalldataCarrier): ApprovalDetails | null {
  if (!tx.to || !tx.data?.startsWith("0x095ea7b3")) return null;
  const data = tx.data.slice(2);
  if (data.length < 8 + 64 + 64) return null;
  const spenderWord = data.slice(8, 72);
  const amountWord = data.slice(72, 136);
  const spender = `0x${spenderWord.slice(24)}`;
  const amountRaw = wordToBigint(amountWord);
  if (!ADDR_RE.test(spender) || amountRaw === null) return null;
  return {
    tokenAddress: tx.to,
    spender,
    amountRaw,
  };
}

// Decode an ERC-20 transfer(address,uint256) / transferFrom(address,address,uint256)
// carried by a dApp transaction, so the approval window shows the REAL recipient
// and token amount instead of "to: token contract, 0 ETH".
export function parseTransferDetails(tx: CalldataCarrier): TransferDetails | null {
  if (!tx.to || !tx.data) return null;
  const data = tx.data.replace(/^0x/, "");
  const selector = data.slice(0, 8).toLowerCase();
  const word = (i: number) => data.slice(8 + i * 64, 8 + (i + 1) * 64);
  const addr = (w: string) => `0x${w.slice(24)}`;
  if (selector === "a9059cbb" && data.length >= 8 + 128) {
    const recipient = addr(word(0));
    const amountRaw = wordToBigint(word(1));
    if (!ADDR_RE.test(recipient) || amountRaw === null) return null;
    return { tokenAddress: tx.to, owner: null, recipient, amountRaw };
  }
  if (selector === "23b872dd" && data.length >= 8 + 192) {
    const owner = addr(word(0));
    const recipient = addr(word(1));
    const amountRaw = wordToBigint(word(2));
    if (!ADDR_RE.test(owner) || !ADDR_RE.test(recipient) || amountRaw === null) return null;
    return { tokenAddress: tx.to, owner, recipient, amountRaw };
  }
  return null;
}

export function encodeErc20Approve(spender: string, amount: bigint): string {
  const addr = spender.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(addr)) throw new Error("invalid spender");
  return `0x095ea7b3${addr.padStart(64, "0")}${amount.toString(16).padStart(64, "0")}`;
}

export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n; // Permit2 amounts are uint160
export const MAX_UINT96 = (1n << 96n) - 1n; // UNI-style permits are uint96

// dApp-supplied values may be numbers, decimal strings, or hex strings — or junk.
export function asBigint(v: unknown): bigint | null {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isFinite(v)) return BigInt(Math.trunc(v));
  if (typeof v === "string") {
    try {
      return BigInt(v);
    } catch {
      return null;
    }
  }
  return null;
}

/** A 0x-hex quantity such as a tx `value`. "0x" counts as zero; anything else
 *  that is not hex is null — the caller shows the raw text, never a guess. */
export function parseHexQuantity(v: string): bigint | null {
  if (!/^0x[0-9a-fA-F]*$/.test(v)) return null;
  return v === "0x" ? 0n : BigInt(v);
}

export function chainIdToHex(v: unknown): string | null {
  const n = asBigint(v);
  return n !== null && n > 0n ? `0x${n.toString(16)}` : null;
}

// Recognize permit-style typed data (ERC-2612, DAI permit, Permit2 single/batch/
// transfer) and pull out what the signature would actually grant. Untrusted
// input: anything that doesn't parse stays null and renders as "—".
export function detectPermit(data: TypedDataPayload): PermitInfo | null {
  const msg = data.message;
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
  const m = msg as Record<string, unknown>;
  const domain = (data.domain ?? {}) as Record<string, unknown>;
  const fallbackToken =
    typeof domain.verifyingContract === "string" ? domain.verifyingContract : null;
  const spender = typeof m.spender === "string" ? m.spender : null;
  const daiAllowed = m.allowed === true || m.allowed === "true";
  // Permit2 nests token+amount: PermitSingle/PermitBatch under `details`,
  // PermitTransferFrom under `permitted` — arrays for the batch variants, and
  // every entry is a separate allowance the user must see.
  const nestedRaw = m.details ?? m.permitted;
  const nestedList = nestedRaw === undefined ? null : Array.isArray(nestedRaw) ? nestedRaw : [nestedRaw];
  const grants: PermitGrant[] = nestedList
    ? nestedList.map((entry) => {
        const inner =
          entry && typeof entry === "object" && !Array.isArray(entry)
            ? (entry as Record<string, unknown>)
            : {};
        const amountRaw = asBigint(inner.amount ?? inner.value);
        return {
          token: typeof inner.token === "string" ? inner.token : null,
          amountRaw,
          unlimited: isUnlimitedAmount(amountRaw),
          expiration: asBigint(inner.expiration),
        };
      })
    : [
        // ERC-2612 / DAI: one allowance on the token the domain names.
        (() => {
          const amountRaw = daiAllowed ? null : asBigint(m.value ?? m.amount ?? m.wad);
          return {
            token: typeof m.token === "string" ? m.token : fallbackToken,
            amountRaw,
            unlimited: daiAllowed || isUnlimitedAmount(amountRaw),
            expiration: null,
          };
        })(),
      ];
  const anyAmount = grants.some((g) => g.amountRaw !== null);
  const primary = String(data.primaryType ?? "");
  if (!/permit/i.test(primary) && !(spender && (anyAmount || daiAllowed))) return null;
  const incomplete =
    grants.length === 0 ||
    grants.some((g) => g.token === null || (g.amountRaw === null && !g.unlimited));
  const deadline = asBigint(m.deadline ?? m.sigDeadline ?? m.expiry);
  return {
    spender,
    grants,
    incomplete,
    unlimited: grants.some((g) => g.unlimited),
    deadline,
    chainHex: chainIdToHex(domain.chainId),
  };
}

function isUnlimitedAmount(amountRaw: bigint | null): boolean {
  return amountRaw === MAX_UINT256 || amountRaw === MAX_UINT160 || amountRaw === MAX_UINT96;
}

/**
 * A Safe transaction (EIP-712 `SafeTx`) with `operation` 1 is a DELEGATECALL:
 * the target's code runs AS the Safe and can swap its owners or drain every
 * asset in one step — the usual shape of Safe thefts. The approval UI must say
 * so in plain words instead of leaving it as a digit inside the JSON.
 */
export function isSafeDelegateCall(data: TypedDataPayload): boolean {
  if (data.primaryType !== "SafeTx") return false;
  const msg = data.message;
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return false;
  const operation = (msg as Record<string, unknown>).operation;
  return operation === 1 || operation === "1";
}
