//! HTTP client for the Etherscan v2 unified multichain API.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};

/// Etherscan v2 unified API endpoint. The `chainid` query parameter selects
/// the chain; the host is the same for every supported chain.
const ETHERSCAN_V2_BASE: &str = "https://api.etherscan.io/v2/api";

/// Default request timeout (Etherscan can be slow under load).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Etherscan returned status {status}: {message}")]
    Api { status: String, message: String },
    #[error("Etherscan returned empty result")]
    Empty,
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Curated list of well-supported Etherscan v2 chains.
///
/// Use `Chain::Other(<id>)` for any other supported chain (HyperEVM, Sonic, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Ethereum,  // 1
    Optimism,  // 10
    Bsc,       // 56
    Polygon,   // 137
    Arbitrum,  // 42161
    Base,      // 8453
    Avalanche, // 43114
    Other(u64),
}

impl Chain {
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::Optimism => 10,
            Chain::Bsc => 56,
            Chain::Polygon => 137,
            Chain::Arbitrum => 42161,
            Chain::Base => 8453,
            Chain::Avalanche => 43114,
            Chain::Other(id) => *id,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Chain::Ethereum => "Ethereum",
            Chain::Optimism => "Optimism",
            Chain::Bsc => "BNB Smart Chain",
            Chain::Polygon => "Polygon",
            Chain::Arbitrum => "Arbitrum One",
            Chain::Base => "Base",
            Chain::Avalanche => "Avalanche C-Chain",
            Chain::Other(_) => "Other",
        }
    }

    /// Parse a chain name or numeric chain id.
    pub fn parse(s: &str) -> Option<Chain> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "1" | "eth" | "ethereum" | "mainnet" => Some(Chain::Ethereum),
            "10" | "op" | "optimism" => Some(Chain::Optimism),
            "56" | "bsc" | "bnb" | "binance" => Some(Chain::Bsc),
            "137" | "polygon" | "matic" => Some(Chain::Polygon),
            "42161" | "arb" | "arbitrum" => Some(Chain::Arbitrum),
            "8453" | "base" => Some(Chain::Base),
            "43114" | "avax" | "avalanche" => Some(Chain::Avalanche),
            _ => s.parse::<u64>().ok().map(Chain::Other),
        }
    }
}

/// Etherscan v2 client. Cloneable (wraps an `Arc` internally via `reqwest`).
#[derive(Debug, Clone)]
pub struct EtherscanClient {
    http: reqwest::Client,
    api_key: Option<String>,
    base_url: String,
}

impl EtherscanClient {
    /// Construct a client.
    ///
    /// - `api_key` is optional. Without a key, Etherscan applies a strict
    ///   public rate limit (~1 req/sec).
    pub fn new(api_key: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent("sol-agent/etherscan-fetcher (+https://cli.devin.ai)")
            .build()
            .expect("reqwest client build failed");
        Self {
            http,
            api_key,
            base_url: ETHERSCAN_V2_BASE.to_string(),
        }
    }

    /// Override the base URL (mainly used in tests).
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into();
        self
    }

    /// Fetch the raw `getsourcecode` response and return the first contract
    /// entry. Caller passes this to [`crate::extractor::extract`] to
    /// reconstruct files.
    pub async fn fetch_raw(
        &self,
        chain: Chain,
        address: &str,
    ) -> Result<RawContractEntry, FetchError> {
        info!(
            "Etherscan fetch: chain={} ({}) address={}",
            chain.name(),
            chain.chain_id(),
            address
        );
        let mut req = self.http.get(&self.base_url).query(&[
            ("chainid", chain.chain_id().to_string()),
            ("module", "contract".to_string()),
            ("action", "getsourcecode".to_string()),
            ("address", address.to_string()),
        ]);
        if let Some(key) = &self.api_key {
            req = req.query(&[("apikey", key.clone())]);
        }
        let res = req.send().await?;
        let status_code = res.status();
        let body_text = res.text().await?;
        debug!(
            "Etherscan response status={} length={}",
            status_code,
            body_text.len()
        );
        let envelope: EtherscanEnvelope = serde_json::from_str(&body_text).map_err(|e| {
            FetchError::InvalidResponse(format!(
                "failed to parse envelope: {} (body starts: {})",
                e,
                truncate(&body_text, 200)
            ))
        })?;
        if envelope.status != "1" {
            // Merge `result` (often a human-readable error string) into the message.
            let extra = envelope.result_as_string();
            let combined = if extra.is_empty() {
                envelope.message.clone()
            } else if envelope.message.eq_ignore_ascii_case("NOTOK") {
                extra
            } else {
                format!("{} ({})", envelope.message, extra)
            };
            return Err(FetchError::Api {
                status: envelope.status,
                message: combined,
            });
        }
        envelope
            .into_results()?
            .into_iter()
            .next()
            .ok_or(FetchError::Empty)
    }

    /// Fetch + extract: returns a fully reconstructed contract bundle.
    pub async fn fetch_contract(
        &self,
        chain: Chain,
        address: &str,
    ) -> Result<crate::extractor::ContractBundle, FetchError> {
        let raw = self.fetch_raw(chain, address).await?;
        crate::extractor::extract(chain, address, raw)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Envelope returned by Etherscan for both v1 and v2 endpoints.
///
/// On success: `result` is `Vec<RawContractEntry>`.
/// On error: `result` is often a plain string (e.g. "Missing/Invalid API Key").
/// We deserialize into untyped JSON and decode lazily based on `status`.
#[derive(Debug, Deserialize)]
struct EtherscanEnvelope {
    status: String,
    message: String,
    #[serde(default)]
    result: serde_json::Value,
}

impl EtherscanEnvelope {
    /// Convert `result` into a Vec of contract entries. Returns `Vec::new()` if
    /// `result` is not a JSON array (which usually means an error response).
    fn into_results(self) -> Result<Vec<RawContractEntry>, FetchError> {
        if !self.result.is_array() {
            return Ok(Vec::new());
        }
        serde_json::from_value(self.result).map_err(FetchError::Json)
    }

    /// Render `result` as a string for error messages, regardless of JSON shape.
    fn result_as_string(&self) -> String {
        match &self.result {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            v => v.to_string(),
        }
    }
}

/// One entry in the `result` array. All fields come back as strings from
/// Etherscan (their schema is intentionally permissive).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RawContractEntry {
    #[serde(default)]
    pub source_code: String,
    #[serde(default)]
    pub abi: String,
    #[serde(default)]
    pub contract_name: String,
    #[serde(default)]
    pub compiler_version: String,
    #[serde(default)]
    pub compiler_type: String,
    #[serde(default)]
    pub optimization_used: String,
    #[serde(default)]
    pub runs: String,
    #[serde(default)]
    pub constructor_arguments: String,
    #[serde(default, rename = "EVMVersion")]
    pub evm_version: String,
    #[serde(default)]
    pub library: String,
    #[serde(default)]
    pub contract_file_name: String,
    #[serde(default)]
    pub license_type: String,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub implementation: String,
    #[serde(default)]
    pub swarm_source: String,
    #[serde(default)]
    pub similar_match: String,
}

impl RawContractEntry {
    /// True if `proxy` field is "1" (Etherscan returns string booleans).
    pub fn is_proxy(&self) -> bool {
        self.proxy == "1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_parsing() {
        assert_eq!(Chain::parse("1"), Some(Chain::Ethereum));
        assert_eq!(Chain::parse("eth"), Some(Chain::Ethereum));
        assert_eq!(Chain::parse("base"), Some(Chain::Base));
        assert_eq!(Chain::parse("42161"), Some(Chain::Arbitrum));
        assert_eq!(Chain::parse("9999"), Some(Chain::Other(9999)));
        assert_eq!(Chain::parse("not-a-chain"), None);
    }

    #[test]
    fn chain_ids_match_docs() {
        assert_eq!(Chain::Ethereum.chain_id(), 1);
        assert_eq!(Chain::Optimism.chain_id(), 10);
        assert_eq!(Chain::Bsc.chain_id(), 56);
        assert_eq!(Chain::Polygon.chain_id(), 137);
        assert_eq!(Chain::Arbitrum.chain_id(), 42161);
        assert_eq!(Chain::Base.chain_id(), 8453);
        assert_eq!(Chain::Avalanche.chain_id(), 43114);
    }

    #[test]
    fn parses_single_source_envelope() {
        let body = r#"{
            "status": "1",
            "message": "OK",
            "result": [{
                "SourceCode": "pragma solidity 0.8.20;\ncontract Foo {}",
                "ABI": "[]",
                "ContractName": "Foo",
                "CompilerVersion": "v0.8.20+commit.a1b79de6",
                "OptimizationUsed": "1",
                "Runs": "200",
                "ConstructorArguments": "",
                "EVMVersion": "Default",
                "Library": "",
                "LicenseType": "MIT",
                "Proxy": "0",
                "Implementation": ""
            }]
        }"#;
        let env: EtherscanEnvelope = serde_json::from_str(body).unwrap();
        assert_eq!(env.status, "1");
        let results = env.into_results().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].contract_name, "Foo");
        assert_eq!(results[0].compiler_version, "v0.8.20+commit.a1b79de6");
        assert!(!results[0].is_proxy());
    }

    #[test]
    fn parses_api_error_envelope_array_result() {
        let body = r#"{"status":"0","message":"NOTOK","result":[]}"#;
        let env: EtherscanEnvelope = serde_json::from_str(body).unwrap();
        assert_eq!(env.status, "0");
        assert_eq!(env.message, "NOTOK");
        assert!(env.result_as_string().contains("[]"));
    }

    #[test]
    fn parses_api_error_envelope_string_result() {
        // Etherscan returns `result` as a plain string when authentication fails.
        let body = r#"{"status":"0","message":"NOTOK","result":"Missing/Invalid API Key"}"#;
        let env: EtherscanEnvelope = serde_json::from_str(body).unwrap();
        assert_eq!(env.status, "0");
        assert_eq!(env.result_as_string(), "Missing/Invalid API Key");
        // Calling into_results on this returns an empty vec rather than failing.
        let results = env.into_results().unwrap();
        assert!(results.is_empty());
    }
}
