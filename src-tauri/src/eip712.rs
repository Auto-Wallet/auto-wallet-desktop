//! EIP-712 typed-data hashing for `eth_signTypedData_v4` — pure, no network.
//!
//! Produces the 32-byte digest a dApp's typed data must sign:
//!   keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(primaryType, message))
//! where hashStruct(t, v) = keccak256(typeHash(t) ‖ encodeData(t, v)) and
//! typeHash(t) = keccak256(encodeType(t)). lib.rs signs the digest with the vault
//! key. Verified against the canonical EIP-712 spec "Mail" example (see tests).

use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::BTreeSet;

fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The base type name with all array brackets stripped (`Person[2][]` → `Person`).
fn struct_base(t: &str) -> &str {
    t.split('[').next().unwrap_or(t)
}

/// If `t` is an array type, the element type with ONE level of brackets removed
/// (`uint[]` → `uint`, `Foo[2][]` → `Foo[2]`). `None` for non-array types.
fn array_element(t: &str) -> Option<&str> {
    if t.ends_with(']') {
        t.rfind('[').map(|i| &t[..i])
    } else {
        None
    }
}

/// Transitively collect the struct types referenced by `t` (including `t`).
fn collect_deps(t: &str, types: &Value, found: &mut BTreeSet<String>) {
    if found.contains(t) {
        return;
    }
    let Some(fields) = types.get(t).and_then(|v| v.as_array()) else {
        return;
    };
    found.insert(t.to_string());
    for f in fields {
        if let Some(ft) = f.get("type").and_then(|v| v.as_str()) {
            let base = struct_base(ft);
            if types.get(base).is_some() {
                collect_deps(base, types, found);
            }
        }
    }
}

/// `encodeType`: `Primary(t1 n1,…)` followed by each referenced struct type in
/// alphabetical order (EIP-712 §"Definition of encodeType").
pub fn encode_type(primary: &str, types: &Value) -> Result<String, String> {
    let mut deps = BTreeSet::new();
    collect_deps(primary, types, &mut deps);
    deps.remove(primary);

    let mut ordered = vec![primary.to_string()];
    ordered.extend(deps); // BTreeSet iterates sorted

    let mut out = String::new();
    for t in &ordered {
        let fields = types
            .get(t)
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("unknown type {t}"))?;
        out.push_str(t);
        out.push('(');
        let parts: Vec<String> = fields
            .iter()
            .map(|f| {
                let ty = f.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let nm = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
                format!("{ty} {nm}")
            })
            .collect();
        out.push_str(&parts.join(","));
        out.push(')');
    }
    Ok(out)
}

fn type_hash(primary: &str, types: &Value) -> Result<[u8; 32], String> {
    Ok(keccak(encode_type(primary, types)?.as_bytes()))
}

/// `hashStruct(t, v)` = keccak256(typeHash(t) ‖ encodeData(t, v)).
pub fn hash_struct(struct_type: &str, data: &Value, types: &Value) -> Result<[u8; 32], String> {
    let mut buf = type_hash(struct_type, types)?.to_vec();
    let fields = types
        .get(struct_type)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("unknown type {struct_type}"))?;
    for f in fields {
        let name = f
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("field missing name")?;
        let ftype = f
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or("field missing type")?;
        let value = data
            .get(name)
            .ok_or_else(|| format!("missing field '{name}' for {struct_type}"))?;
        buf.extend_from_slice(&encode_field(ftype, value, types)?);
    }
    Ok(keccak(&buf))
}

/// Encode one value of `field_type` to its 32-byte EIP-712 representation.
fn encode_field(field_type: &str, value: &Value, types: &Value) -> Result<[u8; 32], String> {
    // Array: keccak of the concatenated encodings of each element.
    if let Some(elem) = array_element(field_type) {
        let arr = value
            .as_array()
            .ok_or_else(|| format!("expected an array for {field_type}"))?;
        let mut buf = Vec::with_capacity(arr.len() * 32);
        for el in arr {
            buf.extend_from_slice(&encode_field(elem, el, types)?);
        }
        return Ok(keccak(&buf));
    }
    // Referenced struct: recurse via hashStruct.
    if types.get(field_type).is_some() {
        return hash_struct(field_type, value, types);
    }
    // Atomic types.
    match field_type {
        "string" => Ok(keccak(
            value.as_str().ok_or("string value expected")?.as_bytes(),
        )),
        "bytes" => Ok(keccak(&parse_hex(value)?)),
        "bool" => {
            let mut o = [0u8; 32];
            if value.as_bool().ok_or("bool value expected")? {
                o[31] = 1;
            }
            Ok(o)
        }
        "address" => {
            let addr = parse_address(value)?;
            let mut o = [0u8; 32];
            o[12..].copy_from_slice(&addr);
            Ok(o)
        }
        t if t.starts_with("uint") => {
            check_int_width(t, &t[4..])?;
            parse_uint256(value)
        }
        t if t.starts_with("int") => {
            check_int_width(t, &t[3..])?;
            parse_int256(value)
        }
        t if t.starts_with("bytes") => {
            // bytesN — left-aligned (the value is exactly N bytes). EIP-712
            // allows bytes1..bytes32 only; anything wider would overrun the
            // 32-byte word below.
            let n: usize = t[5..]
                .parse()
                .map_err(|_| format!("bad fixed-bytes type {t}"))?;
            if !(1..=32).contains(&n) {
                return Err(format!("bad fixed-bytes type {t}: size must be 1..=32"));
            }
            let b = parse_hex(value)?;
            if b.len() != n {
                return Err(format!("{t} expects {n} bytes, got {}", b.len()));
            }
            let mut o = [0u8; 32];
            o[..n].copy_from_slice(&b);
            Ok(o)
        }
        other => Err(format!("unsupported EIP-712 type {other}")),
    }
}

/// `uintN` / `intN`: N is 8..=256 in steps of 8. Bare `uint`/`int` is the
/// Solidity alias for 256.
fn check_int_width(ty: &str, suffix: &str) -> Result<(), String> {
    if suffix.is_empty() {
        return Ok(());
    }
    match suffix.parse::<u16>() {
        Ok(n) if n % 8 == 0 && (8..=256).contains(&n) => Ok(()),
        _ => Err(format!("bad integer type {ty}: width must be 8..=256 in steps of 8")),
    }
}

fn parse_hex(v: &Value) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or("expected a 0x-hex string")?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}

fn parse_address(v: &Value) -> Result<[u8; 20], String> {
    let b = parse_hex(v)?;
    if b.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", b.len()));
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&b);
    Ok(o)
}

/// uint256 from a JSON number, a 0x-hex string, or a decimal string → 32 BE bytes.
fn parse_uint256(v: &Value) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    if let Some(n) = v.as_u64() {
        out[24..].copy_from_slice(&n.to_be_bytes());
        return Ok(out);
    }
    let s = v.as_str().ok_or("uint value expected a number or string")?;
    if let Some(hexpart) = s.strip_prefix("0x") {
        let padded = if hexpart.len() % 2 == 1 {
            format!("0{hexpart}")
        } else {
            hexpart.to_string()
        };
        let bytes = hex::decode(&padded).map_err(|e| format!("bad uint hex: {e}"))?;
        if bytes.len() > 32 {
            return Err("uint256 exceeds 32 bytes".to_string());
        }
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        Ok(out)
    } else {
        decimal_to_be32(s)
    }
}

/// int256 — non-negative like uint; negative decimal as two's complement.
fn parse_int256(v: &Value) -> Result<[u8; 32], String> {
    if let Some(n) = v.as_i64() {
        let mut out = if n < 0 { [0xffu8; 32] } else { [0u8; 32] };
        out[24..].copy_from_slice(&n.to_be_bytes());
        return Ok(out);
    }
    if let Some(s) = v.as_str() {
        if let Some(mag_str) = s.strip_prefix('-') {
            let mag = decimal_to_be32(mag_str)?;
            // two's complement: (~mag) + 1
            let mut out = [0u8; 32];
            let mut carry = 1u16;
            for i in (0..32).rev() {
                let x = (!mag[i]) as u16 + carry;
                out[i] = (x & 0xff) as u8;
                carry = x >> 8;
            }
            return Ok(out);
        }
    }
    parse_uint256(v)
}

/// Decimal string → 32-byte big-endian (long arithmetic, overflow is an error).
fn decimal_to_be32(s: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    for ch in s.chars() {
        let d = ch
            .to_digit(10)
            .ok_or_else(|| format!("bad decimal digit in {s}"))? as u32;
        let mut carry = d;
        for i in (0..32).rev() {
            let cur = out[i] as u32 * 10 + carry;
            out[i] = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return Err("uint256 overflow".to_string());
        }
    }
    Ok(out)
}

/// The two 32-byte halves a Ledger's `eth_signTypedData_v4` consumes:
/// (domainSeparator, hashStruct(primaryType, message)). A local key combines them
/// into `signing_hash`; the device is sent the pair and hashes the 0x1901 envelope
/// itself. Sharing this keeps both paths on identical encoding.
pub fn domain_and_message_hash(typed: &Value) -> Result<([u8; 32], [u8; 32]), String> {
    let types = typed.get("types").ok_or("typed data missing 'types'")?;
    let domain = typed.get("domain").ok_or("typed data missing 'domain'")?;
    let primary = typed
        .get("primaryType")
        .and_then(|v| v.as_str())
        .ok_or("typed data missing 'primaryType'")?;
    let message = typed.get("message").ok_or("typed data missing 'message'")?;

    let domain_separator = hash_struct("EIP712Domain", domain, types)?;
    let message_hash = hash_struct(primary, message, types)?;
    Ok((domain_separator, message_hash))
}

/// The EIP-712 digest to sign: keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(primary, message)).
pub fn signing_hash(typed: &Value) -> Result<[u8; 32], String> {
    let (domain_separator, message_hash) = domain_and_message_hash(typed)?;
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(&domain_separator);
    buf.extend_from_slice(&message_hash);
    Ok(keccak(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The canonical EIP-712 spec example ("Mail").
    fn mail() -> Value {
        json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }
        })
    }

    #[test]
    fn encode_type_sorts_dependencies() {
        let t = mail();
        assert_eq!(
            encode_type("Mail", &t["types"]).unwrap(),
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
    }

    #[test]
    fn domain_separator_matches_spec() {
        let t = mail();
        let ds = hash_struct("EIP712Domain", &t["domain"], &t["types"]).unwrap();
        assert_eq!(
            hex::encode(ds),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );
    }

    #[test]
    fn signing_hash_matches_spec() {
        // The exact digest from the EIP-712 specification for this example.
        assert_eq!(
            hex::encode(signing_hash(&mail()).unwrap()),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn signing_with_the_spec_key_reproduces_the_spec_signature() {
        use k256::ecdsa::SigningKey;
        // The spec's signer: private key = keccak256("cow").
        let priv_key = keccak(b"cow");
        let key = SigningKey::from_slice(&priv_key).unwrap();
        // Sanity: that key is the "Cow" wallet in the message.
        assert_eq!(
            crate::address_from_verifying_key(key.verifying_key()).to_lowercase(),
            "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"
        );

        let digest = signing_hash(&mail()).unwrap();
        let (sig, recid) = key.sign_prehash_recoverable(&digest).unwrap();
        let bytes = sig.to_bytes();
        let v = 27 + recid.to_byte();
        // The canonical (r, s, v) from the EIP-712 spec example.
        assert_eq!(
            hex::encode(&bytes[..32]),
            "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d"
        );
        assert_eq!(
            hex::encode(&bytes[32..]),
            "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562"
        );
        assert_eq!(v, 28);
    }

    #[test]
    fn encodes_uint_from_number_hex_and_decimal() {
        // 1 as a number, 0x1 as hex, "1" as decimal must all encode identically.
        let n = parse_uint256(&json!(1)).unwrap();
        let h = parse_uint256(&json!("0x1")).unwrap();
        let d = parse_uint256(&json!("1")).unwrap();
        assert_eq!(n, h);
        assert_eq!(h, d);
        assert_eq!(n[31], 1);
        // a big decimal that overflows u64 must still encode (no silent truncation).
        let big = parse_uint256(&json!("1000000000000000000000")).unwrap(); // 1e21
        assert_eq!(
            hex::encode(big),
            "00000000000000000000000000000000000000000000003635c9adc5dea00000"
        );
    }

    /// Typed data with one field of `ty` holding `value`.
    fn one_field(ty: &str, value: Value) -> Value {
        json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Probe": [{"name": "v", "type": ty}]
            },
            "primaryType": "Probe",
            "domain": {"name": "probe"},
            "message": {"v": value}
        })
    }

    // Security review 2026-11-02 #6: bytes33 with 33 bytes passed the length
    // check, then sliced past the 32-byte word and panicked.
    #[test]
    fn fixed_bytes_outside_1_to_32_is_an_error_not_a_panic() {
        for (ty, len) in [("bytes33", 33), ("bytes64", 64), ("bytes0", 0)] {
            let value = json!(format!("0x{}", "ab".repeat(len)));
            let out = std::panic::catch_unwind(|| signing_hash(&one_field(ty, value)));
            let res = out.unwrap_or_else(|_| panic!("{ty} panicked"));
            let err = res.expect_err(&format!("{ty} must be refused"));
            assert!(err.contains(ty), "error should name {ty}: {err}");
        }
    }

    #[test]
    fn fixed_bytes_edges_still_encode() {
        let one = signing_hash(&one_field("bytes1", json!("0xab"))).unwrap();
        let full = signing_hash(&one_field("bytes32", json!(format!("0x{}", "cd".repeat(32))))).unwrap();
        assert_ne!(one, full);
        // Left-aligned: bytes1 0xab encodes as ab00…00.
        assert_eq!(
            encode_field("bytes1", &json!("0xab"), &json!({})).unwrap(),
            {
                let mut w = [0u8; 32];
                w[0] = 0xab;
                w
            }
        );
    }

    #[test]
    fn integer_widths_must_be_multiples_of_8_up_to_256() {
        for ty in ["uint7", "uint0", "uint264", "int12", "uintx"] {
            let err = signing_hash(&one_field(ty, json!("1"))).expect_err(ty);
            assert!(err.contains(ty), "error should name {ty}: {err}");
        }
        for ty in ["uint8", "uint256", "int8", "int256", "uint", "int"] {
            signing_hash(&one_field(ty, json!("1"))).unwrap_or_else(|e| panic!("{ty}: {e}"));
        }
    }
}
