//! Etherscan source fetcher (Etherscan v2 unified multichain API).
//!
//! Downloads verified Solidity source code from Etherscan-compatible explorers
//! for any supported chain, reconstructs the multi-file project tree, and
//! optionally emits a ready-to-build Foundry project.
//!
//! ## Example
//!
//! ```no_run
//! # async fn run() -> Result<(), etherscan_fetcher::FetchError> {
//! use etherscan_fetcher::{EtherscanClient, Chain, FetchOptions};
//!
//! let client = EtherscanClient::new(None); // no API key → uses public limit
//! let bundle = client
//!     .fetch_contract(Chain::Ethereum, "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413")
//!     .await?;
//!
//! // Write a Foundry project to /tmp/dao
//! let opts = FetchOptions::default();
//! etherscan_fetcher::write_foundry_project(&bundle, "/tmp/dao", &opts)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Supported Chains
//!
//! Etherscan v2 unified API supports 60+ chains via the `chainid` parameter.
//! We model the common ones as [`Chain`] variants; arbitrary chains can be
//! used via [`Chain::Other`].

pub mod client;
pub mod extractor;
pub mod foundry_gen;

pub use client::{Chain, EtherscanClient, FetchError, RawContractEntry};
pub use extractor::{ContractBundle, ExtractedFile, ProxyInfo, SolMetadata};
pub use foundry_gen::{FetchOptions, write_foundry_project};
