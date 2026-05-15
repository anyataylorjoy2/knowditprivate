//! Reconstruction of Solidity source files from an Etherscan response.
//!
//! Etherscan's `SourceCode` field comes in three flavours, which we detect
//! automatically:
//!
//! 1. **Single source**: just the raw Solidity code. Written to
//!    `src/<ContractName>.sol`.
//! 2. **Multi-file JSON** (used by the legacy multi-file verifier): a JSON
//!    object mapping path → `{"content": "..."}`, wrapped in single curly braces.
//! 3. **Standard JSON Input** (modern format): wrapped in DOUBLE curly braces
//!    (`{{ ... }}`) — Etherscan adds an extra pair so embedded JSON survives
//!    their pretty-printer. The inner object has the shape
//!    `{"language":"Solidity","sources":{"<path>":{"content":"..."}},"settings":{...}}`.
//!
//! Proxies: if `Proxy=1` and `Implementation` is set, we surface this as
//! [`ProxyInfo`] but do NOT auto-fetch the implementation (caller decides).

use crate::client::{Chain, FetchError, RawContractEntry};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// A reconstructed contract bundle ready to be written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractBundle {
    pub chain_id: u64,
    pub chain_name: String,
    pub address: String,
    /// Name of the primary contract (per Etherscan).
    pub primary_contract: String,
    /// All reconstructed source files. Relative paths are POSIX-style.
    pub files: Vec<ExtractedFile>,
    pub metadata: SolMetadata,
    /// Set only if Etherscan flags this as a proxy contract.
    pub proxy: Option<ProxyInfo>,
    /// Compiler `settings` JSON if present in the Standard JSON Input format,
    /// otherwise `None`. Used by `foundry_gen` to write `remappings.txt`.
    pub raw_settings: Option<serde_json::Value>,
}

/// Compilation metadata extracted from the Etherscan response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolMetadata {
    /// Like "v0.8.20+commit.a1b79de6" (raw Etherscan string).
    pub compiler_version_raw: String,
    /// Just the semver portion like "0.8.20".
    pub compiler_semver: String,
    pub optimizer_enabled: bool,
    pub optimizer_runs: u32,
    /// EVM target like "Paris", "Shanghai". May be "Default" or empty.
    pub evm_version: String,
    pub license: String,
    pub constructor_args_hex: String,
}

/// Proxy resolution hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInfo {
    /// Address of the implementation contract.
    pub implementation_address: String,
}

/// One reconstructed file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    /// Relative path within the project (POSIX-style separators).
    pub rel_path: String,
    pub content: String,
}

/// Reconstruct a [`ContractBundle`] from a raw Etherscan entry.
pub fn extract(
    chain: Chain,
    address: &str,
    raw: RawContractEntry,
) -> Result<ContractBundle, FetchError> {
    let primary = raw.contract_name.clone();
    let metadata = build_metadata(&raw);
    let proxy = if raw.is_proxy() && !raw.implementation.is_empty() {
        Some(ProxyInfo {
            implementation_address: raw.implementation.clone(),
        })
    } else {
        None
    };

    let (files, raw_settings) = parse_source_code(&raw.source_code, &primary)?;
    debug!(
        "Extracted {} file(s) for {} ({})",
        files.len(),
        primary,
        address
    );

    Ok(ContractBundle {
        chain_id: chain.chain_id(),
        chain_name: chain.name().to_string(),
        address: address.to_string(),
        primary_contract: primary,
        files,
        metadata,
        proxy,
        raw_settings,
    })
}

fn build_metadata(raw: &RawContractEntry) -> SolMetadata {
    SolMetadata {
        compiler_version_raw: raw.compiler_version.clone(),
        compiler_semver: extract_semver(&raw.compiler_version),
        optimizer_enabled: raw.optimization_used == "1",
        optimizer_runs: raw.runs.parse::<u32>().unwrap_or(200),
        evm_version: raw.evm_version.clone(),
        license: raw.license_type.clone(),
        constructor_args_hex: raw.constructor_arguments.clone(),
    }
}

/// Pull "0.8.20" from a compiler version string like "v0.8.20+commit.a1b79de6".
fn extract_semver(raw: &str) -> String {
    let stripped = raw.strip_prefix('v').unwrap_or(raw);
    stripped.split('+').next().unwrap_or(stripped).to_string()
}

/// Detect which of the three source-code formats we're looking at and
/// produce a list of [`ExtractedFile`]s.
fn parse_source_code(
    source_code: &str,
    primary_name: &str,
) -> Result<(Vec<ExtractedFile>, Option<serde_json::Value>), FetchError> {
    let trimmed = source_code.trim();
    if trimmed.is_empty() {
        return Err(FetchError::Empty);
    }

    // Standard JSON Input format: wrapped in DOUBLE braces by Etherscan.
    if trimmed.starts_with("{{") && trimmed.ends_with("}}") {
        let inner = &trimmed[1..trimmed.len() - 1];
        let value: serde_json::Value = serde_json::from_str(inner)
            .map_err(|e| FetchError::InvalidResponse(format!("standard-json: {}", e)))?;
        let files = extract_from_standard_json(&value)?;
        let settings = value.get("settings").cloned();
        return Ok((files, settings));
    }

    // Multi-file JSON: single braces with a `sources`-like object map.
    // Some Etherscan responses use this for legacy multi-file verifier.
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            // If it has a top-level `sources` key, treat as Standard JSON without double-brace wrap.
            if value.get("sources").is_some() {
                let files = extract_from_standard_json(&value)?;
                let settings = value.get("settings").cloned();
                return Ok((files, settings));
            }
            // Otherwise expect path -> {content: "..."} mapping.
            if let Some(obj) = value.as_object() {
                let mut files = Vec::with_capacity(obj.len());
                for (path, entry) in obj {
                    if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
                        files.push(ExtractedFile {
                            rel_path: normalize_path(path),
                            content: content.to_string(),
                        });
                    }
                }
                if !files.is_empty() {
                    return Ok((files, None));
                }
            }
        }
        // Fallthrough: not JSON we recognize → treat as raw source.
    }

    // Single-source fallback.
    Ok((
        vec![ExtractedFile {
            rel_path: format!("src/{primary}.sol", primary = primary_name),
            content: source_code.to_string(),
        }],
        None,
    ))
}

fn extract_from_standard_json(value: &serde_json::Value) -> Result<Vec<ExtractedFile>, FetchError> {
    let sources = value
        .get("sources")
        .and_then(|s| s.as_object())
        .ok_or_else(|| FetchError::InvalidResponse("missing `sources` object".to_string()))?;
    let mut files = Vec::with_capacity(sources.len());
    for (path, entry) in sources {
        let Some(content) = entry.get("content").and_then(|c| c.as_str()) else {
            warn!("Skipping source entry without `content`: {}", path);
            continue;
        };
        files.push(ExtractedFile {
            rel_path: normalize_path(path),
            content: content.to_string(),
        });
    }
    if files.is_empty() {
        return Err(FetchError::InvalidResponse(
            "standard-json had no usable sources".to_string(),
        ));
    }
    Ok(files)
}

/// Convert any path separators / leading slashes into a clean POSIX-style
/// relative path. Strip leading `/` and `./`.
fn normalize_path(p: &str) -> String {
    let mut out = p.replace('\\', "/");
    if out.starts_with("./") {
        out.drain(..2);
    }
    out.trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(source: &str, name: &str) -> RawContractEntry {
        RawContractEntry {
            source_code: source.to_string(),
            abi: "[]".to_string(),
            contract_name: name.to_string(),
            compiler_version: "v0.8.20+commit.a1b79de6".to_string(),
            compiler_type: "solc".to_string(),
            optimization_used: "1".to_string(),
            runs: "200".to_string(),
            constructor_arguments: String::new(),
            evm_version: "paris".to_string(),
            library: String::new(),
            contract_file_name: String::new(),
            license_type: "MIT".to_string(),
            proxy: "0".to_string(),
            implementation: String::new(),
            swarm_source: String::new(),
            similar_match: String::new(),
        }
    }

    #[test]
    fn extracts_semver() {
        assert_eq!(extract_semver("v0.8.20+commit.a1b79de6"), "0.8.20");
        assert_eq!(extract_semver("0.4.26+commit.4563c3fc"), "0.4.26");
        assert_eq!(extract_semver(""), "");
    }

    #[test]
    fn handles_single_source() {
        let raw = make_raw("pragma solidity 0.8.20;\ncontract Foo {}", "Foo");
        let bundle = extract(Chain::Ethereum, "0x1234", raw).unwrap();
        assert_eq!(bundle.files.len(), 1);
        assert_eq!(bundle.files[0].rel_path, "src/Foo.sol");
        assert!(bundle.files[0].content.contains("contract Foo"));
        assert_eq!(bundle.metadata.compiler_semver, "0.8.20");
        assert!(bundle.metadata.optimizer_enabled);
        assert!(bundle.proxy.is_none());
    }

    #[test]
    fn handles_multifile_json_single_braces() {
        let src = r#"{
            "src/A.sol": {"content": "// A\ncontract A {}"},
            "src/B.sol": {"content": "// B\ncontract B {}"}
        }"#;
        let raw = make_raw(src, "A");
        let bundle = extract(Chain::Ethereum, "0x1234", raw).unwrap();
        assert_eq!(bundle.files.len(), 2);
        assert!(bundle.files.iter().any(|f| f.rel_path == "src/A.sol"));
        assert!(bundle.files.iter().any(|f| f.rel_path == "src/B.sol"));
    }

    #[test]
    fn handles_standard_json_double_braces() {
        let inner = r#"{
            "language": "Solidity",
            "sources": {
                "contracts/Vault.sol": {"content": "// Vault\ncontract Vault {}"},
                "contracts/lib/Math.sol": {"content": "// Math\nlibrary Math {}"}
            },
            "settings": {
                "remappings": ["@oz/=lib/oz/"],
                "optimizer": {"enabled": true, "runs": 200}
            }
        }"#;
        let wrapped = format!("{{{}}}", inner);
        let raw = make_raw(&wrapped, "Vault");
        let bundle = extract(Chain::Ethereum, "0xdead", raw).unwrap();
        assert_eq!(bundle.files.len(), 2);
        let math = bundle
            .files
            .iter()
            .find(|f| f.rel_path == "contracts/lib/Math.sol")
            .unwrap();
        assert!(math.content.contains("library Math"));
        // Settings preserved
        let settings = bundle.raw_settings.unwrap();
        assert!(settings.get("remappings").is_some());
    }

    #[test]
    fn handles_standard_json_single_braces() {
        // Some Etherscan responses don't wrap in double braces.
        let src = r#"{
            "language": "Solidity",
            "sources": {
                "X.sol": {"content": "contract X {}"}
            },
            "settings": {}
        }"#;
        let raw = make_raw(src, "X");
        let bundle = extract(Chain::Ethereum, "0x", raw).unwrap();
        assert_eq!(bundle.files.len(), 1);
        assert_eq!(bundle.files[0].rel_path, "X.sol");
    }

    #[test]
    fn detects_proxy() {
        let mut raw = make_raw("contract P {}", "Proxy");
        raw.proxy = "1".to_string();
        raw.implementation = "0xdeadbeef".to_string();
        let bundle = extract(Chain::Ethereum, "0x1", raw).unwrap();
        assert!(bundle.proxy.is_some());
        assert_eq!(bundle.proxy.unwrap().implementation_address, "0xdeadbeef");
    }

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize_path("src/Foo.sol"), "src/Foo.sol");
        assert_eq!(normalize_path("./src/Foo.sol"), "src/Foo.sol");
        assert_eq!(normalize_path("/src/Foo.sol"), "src/Foo.sol");
        assert_eq!(normalize_path("src\\Foo.sol"), "src/Foo.sol");
    }

    #[test]
    fn empty_source_errors() {
        let raw = make_raw("", "Empty");
        let err = extract(Chain::Ethereum, "0x", raw).unwrap_err();
        match err {
            FetchError::Empty => {}
            other => panic!("expected Empty, got {:?}", other),
        }
    }
}
