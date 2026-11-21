//! Read-only OKX account integration.
//!
//! Credentials live in the operating system credential store. Only this trusted
//! Rust backend can read them; remote dApp webviews receive no matching ACL grant.

use std::collections::HashSet;
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use keyring::{Entry, Error as KeyringError};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, RETRY_AFTER};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use time::macros::format_description;
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEYRING_SERVICE: &str = "com.autodesktop.wallet.okx";
const KEYRING_ACCOUNT: &str = "read-only-v1";
const MAX_PRIVATE_GET_ATTEMPTS: usize = 3;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct OkxCredentials {
    api_key: String,
    secret_key: String,
    passphrase: String,
    region: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OkxConnectionStatus {
    configured: bool,
    api_key_hint: Option<String>,
    region: Option<String>,
}

fn credential_entry() -> Result<Entry, String> {
    Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| format!("opening the system credential store: {e}"))
}

fn validate_credentials(creds: &OkxCredentials) -> Result<(), String> {
    if creds.api_key.trim().is_empty() {
        return Err("API key is required".to_string());
    }
    if creds.secret_key.trim().is_empty() {
        return Err("Secret key is required".to_string());
    }
    if creds.passphrase.is_empty() {
        return Err("Passphrase is required".to_string());
    }
    if !creds.api_key.is_ascii() {
        return Err("API key must contain ASCII characters only".to_string());
    }
    base_url(&creds.region)?;
    Ok(())
}

fn save_to_keyring(creds: &OkxCredentials) -> Result<(), String> {
    let encoded =
        serde_json::to_string(creds).map_err(|e| format!("encoding OKX credentials: {e}"))?;
    credential_entry()?
        .set_password(&encoded)
        .map_err(|e| format!("saving OKX credentials to the system credential store: {e}"))
}

fn load_credentials() -> Result<Option<OkxCredentials>, String> {
    let encoded = match credential_entry()?.get_password() {
        Ok(value) => value,
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(e) => {
            return Err(format!(
                "reading OKX credentials from the system credential store: {e}"
            ))
        }
    };
    let creds: OkxCredentials =
        serde_json::from_str(&encoded).map_err(|e| format!("decoding OKX credentials: {e}"))?;
    validate_credentials(&creds)?;
    Ok(Some(creds))
}

fn require_credentials() -> Result<OkxCredentials, String> {
    load_credentials()?.ok_or_else(|| "OKX is not configured".to_string())
}

fn base_url(region: &str) -> Result<&'static str, String> {
    match region {
        "global" => Ok("https://www.okx.com"),
        "us" => Ok("https://us.okx.com"),
        "eu" => Ok("https://eea.okx.com"),
        "tr" => Ok("https://tr.okx.com"),
        _ => Err("unsupported OKX account region".to_string()),
    }
}

fn api_key_hint(api_key: &str) -> Result<String, String> {
    if api_key.len() < 4 {
        return Err("API key is too short".to_string());
    }
    Ok(format!("••••{}", &api_key[api_key.len() - 4..]))
}

fn validate_index_instrument_id(instrument_id: &str) -> Result<(), String> {
    let mut parts = instrument_id.split('-');
    let base = parts.next().unwrap_or_default();
    let quote = parts.next().unwrap_or_default();
    let valid_currency = |currency: &str| {
        (2..=12).contains(&currency.len())
            && currency
                .bytes()
                .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
    };
    if !valid_currency(base) || !valid_currency(quote) || parts.next().is_some() {
        return Err(format!("invalid OKX index instrument ID: {instrument_id}"));
    }
    Ok(())
}

fn timestamp() -> Result<String, String> {
    OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .map_err(|e| format!("formatting request timestamp: {e}"))
}

fn signature(
    timestamp: &str,
    method: &str,
    request_path: &str,
    secret: &str,
) -> Result<String, String> {
    let prehash = format!("{timestamp}{method}{request_path}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("preparing OKX request signature: {e}"))?;
    mac.update(prehash.as_bytes());
    Ok(B64.encode(mac.finalize().into_bytes()))
}

fn http_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(15))
                .pool_idle_timeout(std::time::Duration::from_secs(15))
                .tcp_keepalive(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| format!("building OKX client: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn calling_okx_error(error: &(dyn std::error::Error + 'static)) -> String {
    format!("calling OKX: {}", crate::error_chain(error))
}

fn required_response_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("OKX response is missing string field {key}"))
}

#[derive(Clone, Copy)]
enum ResponseCode {
    Required,
    Optional,
}

fn validate_private_response(
    mut value: Value,
    response_code: ResponseCode,
) -> Result<Value, String> {
    match value.get("code") {
        Some(Value::String(code)) if code == "0" => {}
        Some(Value::String(code)) => {
            let message = required_response_string(&value, "msg")?;
            return Err(format!("OKX API {code}: {message}"));
        }
        Some(Value::Number(code))
            if matches!(response_code, ResponseCode::Optional) && code.as_i64() == Some(0) =>
        {
            let object = value
                .as_object_mut()
                .ok_or_else(|| "OKX response must be an object".to_string())?;
            object.insert("code".to_string(), Value::String("0".to_string()));
        }
        Some(_) => return Err("OKX response field code must be a string".to_string()),
        None => match response_code {
            ResponseCode::Required => {
                return Err("OKX response is missing string field code".to_string())
            }
            ResponseCode::Optional => {
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| "OKX response must be an object".to_string())?;
                object.insert("code".to_string(), Value::String("0".to_string()));
                object.insert("msg".to_string(), Value::String(String::new()));
            }
        },
    }
    if !value.get("data").is_some_and(Value::is_array) {
        return Err("OKX response is missing data array".to_string());
    }
    Ok(value)
}

fn rate_limit_retry_delay(
    status: StatusCode,
    body: &str,
    attempt: usize,
    retry_after_seconds: Option<u64>,
) -> Option<std::time::Duration> {
    if attempt + 1 >= MAX_PRIVATE_GET_ATTEMPTS {
        return None;
    }
    let okx_rate_limited = match serde_json::from_str::<Value>(body) {
        Ok(value) => value.get("code").and_then(Value::as_str) == Some("50011"),
        Err(_) => false,
    };
    if status != StatusCode::TOO_MANY_REQUESTS && !okx_rate_limited {
        return None;
    }
    let seconds = match retry_after_seconds {
        Some(seconds) => seconds.max(1),
        None => (attempt + 1) as u64,
    };
    Some(std::time::Duration::from_secs(seconds))
}

async fn private_get_with_response_code(
    creds: &OkxCredentials,
    request_path: &str,
    response_code: ResponseCode,
) -> Result<Value, String> {
    if !request_path.starts_with("/api/v5/") {
        return Err("refusing an invalid OKX API path".to_string());
    }
    let url = format!("{}{request_path}", base_url(&creds.region)?);
    let mut attempt = 0;
    loop {
        let timestamp = timestamp()?;
        let sign = signature(&timestamp, "GET", request_path, &creds.secret_key)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "OK-ACCESS-KEY",
            HeaderValue::from_str(&creds.api_key)
                .map_err(|e| format!("invalid OKX API key: {e}"))?,
        );
        headers.insert(
            "OK-ACCESS-SIGN",
            HeaderValue::from_str(&sign).map_err(|e| format!("invalid OKX signature: {e}"))?,
        );
        headers.insert(
            "OK-ACCESS-TIMESTAMP",
            HeaderValue::from_str(&timestamp).map_err(|e| format!("invalid OKX timestamp: {e}"))?,
        );
        headers.insert(
            "OK-ACCESS-PASSPHRASE",
            HeaderValue::from_str(&creds.passphrase)
                .map_err(|e| format!("invalid OKX passphrase: {e}"))?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let response = http_client()?
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| calling_okx_error(&e))?;
        let status = response.status();
        let retry_after_seconds = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let body = response
            .text()
            .await
            .map_err(|e| format!("reading OKX response: {e}"))?;

        if let Some(delay) = rate_limit_retry_delay(status, &body, attempt, retry_after_seconds) {
            attempt += 1;
            tokio::time::sleep(delay).await;
            continue;
        }
        if !status.is_success() {
            return Err(format!("OKX returned HTTP {status}: {body}"));
        }
        let value: Value =
            serde_json::from_str(&body).map_err(|e| format!("decoding OKX response: {e}"))?;
        return validate_private_response(value, response_code);
    }
}

async fn private_get(creds: &OkxCredentials, request_path: &str) -> Result<Value, String> {
    private_get_with_response_code(creds, request_path, ResponseCode::Required).await
}

async fn private_get_with_optional_code(
    creds: &OkxCredentials,
    request_path: &str,
) -> Result<Value, String> {
    private_get_with_response_code(creds, request_path, ResponseCode::Optional).await
}

async fn public_get(region: &str, request_path: &str) -> Result<Value, String> {
    if !request_path.starts_with("/api/v5/market/index-tickers?") {
        return Err("refusing an invalid OKX public API path".to_string());
    }
    let url = format!("{}{request_path}", base_url(region)?);
    let response = http_client()?
        .get(&url)
        .send()
        .await
        .map_err(|e| calling_okx_error(&e))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("reading OKX response: {e}"))?;
    if !status.is_success() {
        return Err(format!("OKX returned HTTP {status}: {body}"));
    }
    let value: Value =
        serde_json::from_str(&body).map_err(|e| format!("decoding OKX response: {e}"))?;
    validate_private_response(value, ResponseCode::Required)
}

#[tauri::command]
pub fn okx_connection_status() -> Result<OkxConnectionStatus, String> {
    match load_credentials()? {
        Some(creds) => Ok(OkxConnectionStatus {
            configured: true,
            api_key_hint: Some(api_key_hint(&creds.api_key)?),
            region: Some(creds.region.clone()),
        }),
        None => Ok(OkxConnectionStatus {
            configured: false,
            api_key_hint: None,
            region: None,
        }),
    }
}

#[tauri::command]
pub async fn okx_save_credentials(creds: OkxCredentials) -> Result<OkxConnectionStatus, String> {
    validate_credentials(&creds)?;
    private_get(&creds, "/api/v5/account/balance").await?;
    let status = OkxConnectionStatus {
        configured: true,
        api_key_hint: Some(api_key_hint(&creds.api_key)?),
        region: Some(creds.region.clone()),
    };
    save_to_keyring(&creds)?;
    Ok(status)
}

#[tauri::command]
pub fn okx_delete_credentials() -> Result<(), String> {
    match credential_entry()?.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(e) => Err(format!(
            "deleting OKX credentials from the system credential store: {e}"
        )),
    }
}

#[tauri::command]
pub async fn okx_get_assets() -> Result<Value, String> {
    let creds = require_credentials()?;
    let valuation = private_get(&creds, "/api/v5/asset/asset-valuation?ccy=USDT").await?;
    let trading = private_get(&creds, "/api/v5/account/balance").await?;
    let funding = private_get(&creds, "/api/v5/asset/balances").await?;
    Ok(json!({ "valuation": valuation, "trading": trading, "funding": funding }))
}

fn optional_read(result: Result<Value, String>) -> Value {
    match result {
        Ok(data) => json!({ "data": data }),
        Err(error) => json!({ "error": error }),
    }
}

fn require_shell<R: tauri::Runtime>(webview: &tauri::Webview<R>) -> Result<(), String> {
    if webview.label() != "shell" {
        return Err("OKX finance reads are only available in the trusted shell".to_string());
    }
    Ok(())
}

#[tauri::command]
pub async fn okx_get_savings<R: tauri::Runtime>(webview: tauri::Webview<R>) -> Result<Value, String> {
    require_shell(&webview)?;
    let creds = require_credentials()?;
    let balances = private_get(&creds, "/api/v5/finance/savings/balance").await?;
    let rows = balances["data"]
        .as_array()
        .ok_or_else(|| "OKX savings response is missing data array".to_string())?;
    let history = if rows.is_empty() {
        None
    } else {
        Some(optional_read(
            private_get(&creds, "/api/v5/finance/savings/lending-history?limit=100").await,
        ))
    };
    Ok(json!({ "balances": balances, "history": history }))
}

#[tauri::command]
pub async fn okx_get_flexible_loans<R: tauri::Runtime>(
    webview: tauri::Webview<R>,
) -> Result<Value, String> {
    require_shell(&webview)?;
    let creds = require_credentials()?;
    let loans = private_get(&creds, "/api/v5/finance/flexible-loan/loan-info").await?;
    let updated_at = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    Ok(json!({ "loans": loans, "updatedAt": updated_at as i64 }))
}

#[tauri::command]
pub async fn okx_get_flexible_loan_interest<R: tauri::Runtime>(
    webview: tauri::Webview<R>,
    order_ids: Vec<String>,
) -> Result<Value, String> {
    require_shell(&webview)?;
    if order_ids
        .iter()
        .any(|id| id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("OKX flexible loan order ID must contain only digits".to_string());
    }
    let creds = require_credentials()?;
    let mut seen = HashSet::new();
    let mut interest = Vec::with_capacity(order_ids.len());
    for order_id in order_ids {
        if !seen.insert(order_id.clone()) {
            continue;
        }
        // This endpoint permits five reads per two seconds per user.
        if !interest.is_empty() && interest.len() % 5 == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let path = format!("/api/v5/finance/flexible-loan/interest-accrued?ordId={order_id}&limit=100");
        interest.push(json!({
            "orderId": order_id,
            "history": optional_read(private_get(&creds, &path).await),
        }));
    }
    Ok(json!(interest))
}

#[tauri::command]
pub async fn okx_get_dcd_orders() -> Result<Value, String> {
    let creds = require_credentials()?;
    private_get_with_optional_code(&creds, "/api/v5/finance/sfp/dcd/order-history?limit=100").await
}

#[tauri::command]
pub async fn okx_save_dcd_csv<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    webview: tauri::Webview<R>,
    csv: String,
) -> Result<String, String> {
    use std::io::Write;
    use tauri::Manager;
    if webview.label() != "shell" {
        return Err("CSV export is only available in the trusted shell".into());
    }
    if csv.len() > 10_000_000 || !csv.starts_with('\u{feff}') {
        return Err("Invalid CSV export".into());
    }
    let directory = app.path().download_dir().map_err(|e| e.to_string())?;
    let filename = format!("okx-dual-investment-{}.csv", OffsetDateTime::now_utc().unix_timestamp_nanos());
    let path = directory.join(filename);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
        .open(&path).map_err(|e| format!("Saving CSV: {e}"))?;
    file.write_all(csv.as_bytes()).map_err(|e| format!("Writing CSV: {e}"))?;
    Ok(path.to_string_lossy().into_owned())
}

#[tauri::command]
pub async fn okx_get_dcd_index_prices(instrument_ids: Vec<String>) -> Result<Value, String> {
    const MAX_INDEX_INSTRUMENTS: usize = 20;

    let creds = require_credentials()?;
    let mut unique_ids = HashSet::new();
    let mut prices = Vec::new();
    for instrument_id in instrument_ids {
        validate_index_instrument_id(&instrument_id)?;
        if !unique_ids.insert(instrument_id.clone()) {
            continue;
        }
        if unique_ids.len() > MAX_INDEX_INSTRUMENTS {
            return Err(format!(
                "at most {MAX_INDEX_INSTRUMENTS} OKX index instruments can be requested"
            ));
        }
        let response = public_get(
            &creds.region,
            &format!("/api/v5/market/index-tickers?instId={instrument_id}"),
        )
        .await?;
        let rows = response
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| "OKX index price response is missing data array".to_string())?;
        if rows.len() != 1 {
            return Err(format!(
                "OKX index price response for {instrument_id} must contain one ticker"
            ));
        }
        prices.push(rows[0].clone());
    }
    Ok(json!({ "code": "0", "msg": "", "data": prices }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn okx_transport_error_reports_the_underlying_cause() {
        #[derive(Debug)]
        struct Cause;
        impl std::fmt::Display for Cause {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "dns lookup failed")
            }
        }
        impl std::error::Error for Cause {}

        #[derive(Debug)]
        struct Wrapper(Cause);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "error sending request for url (https://www.okx.com/)")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        assert_eq!(
            calling_okx_error(&Wrapper(Cause)),
            "calling OKX: error sending request for url (https://www.okx.com/): dns lookup failed"
        );
    }

    #[test]
    fn signature_matches_fixed_vector() {
        let actual = signature(
            "2020-12-08T09:08:57.715Z",
            "GET",
            "/api/v5/account/balance?ccy=BTC",
            "22582BD0CFF14C41EDBF1AB98506286D",
        )
        .unwrap();
        assert_eq!(actual, "HiZhvSfMtWJA3uUIVXV3a/bSXNPCWvYFXoGCVS8V4zY=");
    }

    #[test]
    fn timestamp_has_exact_millisecond_precision() {
        let actual = timestamp().unwrap();

        assert_eq!(actual.len(), 24, "unexpected OKX timestamp: {actual}");
        assert_eq!(&actual[19..20], ".");
        assert!(actual[20..23]
            .chars()
            .all(|character| character.is_ascii_digit()));
        assert!(actual.ends_with('Z'));
    }

    #[test]
    fn region_is_an_allowlist() {
        assert_eq!(base_url("global").unwrap(), "https://www.okx.com");
        assert_eq!(base_url("eu").unwrap(), "https://eea.okx.com");
        assert!(base_url("https://attacker.example").is_err());
    }

    #[test]
    fn dual_investment_index_ids_are_allowlisted() {
        assert!(validate_index_instrument_id("BTC-USDC").is_ok());
        assert!(validate_index_instrument_id("ETH-USDT").is_ok());
        assert!(validate_index_instrument_id("../../account/balance").is_err());
        assert!(validate_index_instrument_id("btc-usdc").is_err());
    }

    #[test]
    fn trusted_shell_can_call_dual_investment_index_prices() {
        let capability = include_str!("../capabilities/default.json");
        let permissions = include_str!("../permissions/okx-account.toml");

        assert!(capability.contains("\"allow-okx-get-dcd-index-prices\""));
        assert!(permissions.contains("commands.allow = [\"okx_get_dcd_index_prices\"]"));
    }

    #[test]
    fn rate_limited_read_gets_a_bounded_retry_delay() {
        let body = r#"{"msg":"Too many requests","code":"50011"}"#;
        let first_delay =
            rate_limit_retry_delay(reqwest::StatusCode::TOO_MANY_REQUESTS, body, 0, None);
        let api_code_delay = rate_limit_retry_delay(reqwest::StatusCode::OK, body, 1, None);
        let exhausted =
            rate_limit_retry_delay(reqwest::StatusCode::TOO_MANY_REQUESTS, body, 2, None);
        let auth_failure = rate_limit_retry_delay(
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"msg":"Invalid API key","code":"50111"}"#,
            0,
            None,
        );

        assert_eq!(first_delay, Some(std::time::Duration::from_secs(1)));
        assert_eq!(api_code_delay, Some(std::time::Duration::from_secs(2)));
        assert_eq!(exhausted, None);
        assert_eq!(auth_failure, None);
    }

    #[test]
    fn code_less_dcd_success_is_normalized_for_the_frontend() {
        let response = json!({
            "data": [{
                "ordId": "123",
                "productId": "BTC-USDT-260827-120000-C"
            }]
        });

        let normalized = validate_private_response(response, ResponseCode::Optional).unwrap();

        assert_eq!(normalized["code"], "0");
        assert_eq!(normalized["msg"], "");
        assert_eq!(normalized["data"][0]["ordId"], "123");
    }

    #[test]
    fn numeric_dcd_success_code_is_normalized_for_the_frontend() {
        let response = json!({
            "code": 0,
            "msg": "",
            "data": [{
                "ordId": "456",
                "productId": "BTC-USDT-260827-120000-C"
            }]
        });

        let normalized = validate_private_response(response, ResponseCode::Optional).unwrap();

        assert_eq!(normalized["code"], "0");
        assert_eq!(normalized["msg"], "");
        assert_eq!(normalized["data"][0]["ordId"], "456");
    }

    #[test]
    #[ignore = "calls the live OKX public API"]
    fn live_public_request_uses_the_same_client_as_account_reads() {
        let response = tauri::async_runtime::block_on(public_get(
            "global",
            "/api/v5/market/index-tickers?instId=BTC-USDT",
        ))
        .unwrap();

        assert_eq!(response["code"], "0");
        assert_eq!(response["data"].as_array().map(Vec::len), Some(1));
    }
}
