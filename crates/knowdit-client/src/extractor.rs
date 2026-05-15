//! LLM-driven DeFi semantic extractor.
//!
//! Given a project's source code, prompts an LLM to identify short canonical
//! DeFi semantics (e.g. "share accounting", "price oracle", "liquidation").
//! These are then used as queries against the Knowdit knowledge graph.
//!
//! The extractor follows Knowdit paper Stage I (DeFi Semantics Extraction):
//! 1. Classify business type (heuristic + optional LLM fallback)
//! 2. Summarize each contract's core mechanism (LLM)
//! 3. Deduplicate / canonicalize semantic names

use crate::project::{FileKind, ProjectFile, read_concatenated};
use agent_core::{BusinessType, DefiSemantic};
use agent_llm::LlmClient;

/// Trait for components that can extract DeFi semantics from project source.
/// Decoupled from KnowditMapper so we can swap a mock implementation in tests.
#[async_trait::async_trait]
pub trait SemanticExtractor: Send + Sync {
    async fn extract(
        &self,
        files: &[ProjectFile],
        business: &[BusinessType],
    ) -> Result<Vec<DefiSemantic>, ExtractorError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractorError {
    #[error("LLM error: {0}")]
    Llm(#[from] agent_llm::LlmError),
    #[error("No files to extract from")]
    NoFiles,
    #[error("LLM produced no semantics")]
    EmptyResult,
}

/// LLM-backed semantic extractor.
pub struct LlmSemanticExtractor {
    pub client: LlmClient,
    /// Hard cap on bytes per file sent to the LLM.
    pub max_bytes_per_file: usize,
    /// Hard cap on total prompt bytes for the legacy single-prompt mode.
    pub max_total_bytes: usize,
    /// When true, extract semantics per primary contract instead of one
    /// monolithic prompt. This dramatically improves semantic diversity
    /// for multi-contract projects.
    pub per_contract: bool,
    /// Maximum primary contracts to extract semantics from (per-contract mode).
    pub max_contracts: usize,
}

impl LlmSemanticExtractor {
    pub fn new(client: LlmClient) -> Self {
        Self {
            client,
            max_bytes_per_file: 8 * 1024,
            max_total_bytes: 48 * 1024,
            per_contract: true,
            max_contracts: 8,
        }
    }

    /// Legacy single-prompt mode (for backward compat / small projects).
    pub fn single_prompt_mode(client: LlmClient) -> Self {
        Self {
            client,
            max_bytes_per_file: 16 * 1024,
            max_total_bytes: 96 * 1024,
            per_contract: false,
            max_contracts: 8,
        }
    }
}

#[async_trait::async_trait]
impl SemanticExtractor for LlmSemanticExtractor {
    async fn extract(
        &self,
        files: &[ProjectFile],
        business: &[BusinessType],
    ) -> Result<Vec<DefiSemantic>, ExtractorError> {
        if files.is_empty() {
            return Err(ExtractorError::NoFiles);
        }

        if self.per_contract {
            self.extract_per_contract(files, business).await
        } else {
            self.extract_single_prompt(files, business).await
        }
    }
}

impl LlmSemanticExtractor {
    /// Per-contract extraction: one LLM call per primary contract, then merge.
    async fn extract_per_contract(
        &self,
        files: &[ProjectFile],
        business: &[BusinessType],
    ) -> Result<Vec<DefiSemantic>, ExtractorError> {
        let business_summary: Vec<&str> = business.iter().map(|b| b.as_str()).collect();
        let business_str = if business_summary.is_empty() {
            "Unknown".to_string()
        } else {
            business_summary.join(", ")
        };

        // Group files by contract name (extract from filename).
        let primary_files: Vec<&ProjectFile> = files
            .iter()
            .filter(|f| f.kind == FileKind::Primary)
            .collect();

        if primary_files.is_empty() {
            // Fallback to single-prompt with all files
            return self.extract_single_prompt(files, business).await;
        }

        // Build a contract-name → file mapping.
        let contract_groups = group_by_contract(primary_files);
        let contract_names: Vec<String> = contract_groups
            .keys()
            .cloned()
            .take(self.max_contracts)
            .collect();

        let system = "You are a senior smart contract security auditor with deep DeFi expertise. \
            Respond strictly in the requested format. Be concise and concrete.";

        let mut all_semantics = Vec::new();

        for contract_name in &contract_names {
            let contract_files = contract_groups.get(contract_name).unwrap();
            let source_blob = read_concatenated(contract_files, self.max_bytes_per_file);

            let prompt = build_per_contract_prompt(
                &business_str,
                &contract_name,
                &source_blob,
                &contract_names,
            );

            let response = match self.client.chat(Some(system), &prompt).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "LLM extraction failed for contract '{}': {}",
                        contract_name,
                        e
                    );
                    continue;
                }
            };

            let contract_semantics = parse_response(&response, business);
            tracing::info!(
                "Extracted {} semantics from contract '{}'",
                contract_semantics.len(),
                contract_name
            );
            all_semantics.extend(contract_semantics);
        }

        // Deduplicate by canonical name.
        let mut seen = std::collections::HashSet::new();
        all_semantics.retain(|s| seen.insert(s.name.clone()));

        if all_semantics.is_empty() {
            return Err(ExtractorError::EmptyResult);
        }
        Ok(all_semantics)
    }

    /// Legacy single-prompt extraction (all files in one prompt).
    async fn extract_single_prompt(
        &self,
        files: &[ProjectFile],
        business: &[BusinessType],
    ) -> Result<Vec<DefiSemantic>, ExtractorError> {
        let business_summary: Vec<&str> = business.iter().map(|b| b.as_str()).collect();
        let business_str = if business_summary.is_empty() {
            "Unknown".to_string()
        } else {
            business_summary.join(", ")
        };

        let mut concatenated = read_concatenated(files, self.max_bytes_per_file);
        if concatenated.len() > self.max_total_bytes {
            concatenated.truncate(self.max_total_bytes);
            concatenated.push_str("\n// (total prompt truncated)\n");
        }

        let prompt = build_prompt(&business_str, &concatenated);
        let system = "You are a senior smart contract security auditor with deep DeFi expertise. \
            Respond strictly in the requested format. Be concise and concrete.";
        let response = self.client.chat(Some(system), &prompt).await?;

        let semantics = parse_response(&response, business);
        if semantics.is_empty() {
            return Err(ExtractorError::EmptyResult);
        }
        Ok(semantics)
    }
}

/// Group primary files by contract name (derived from filename without extension).
fn group_by_contract(
    files: Vec<&ProjectFile>,
) -> std::collections::HashMap<String, Vec<ProjectFile>> {
    let mut groups = std::collections::HashMap::new();
    for f in files {
        let file_name = f
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        // Strip .t or .s suffix (e.g., Foo.t → Foo), but these should already be filtered.
        let contract_name = file_name
            .strip_suffix(".t")
            .or_else(|| file_name.strip_suffix(".s"))
            .unwrap_or(file_name)
            .to_string();
        groups
            .entry(contract_name)
            .or_insert_with(Vec::new)
            .push((*f).clone());
    }
    groups
}

/// Build a per-contract extraction prompt.
fn build_per_contract_prompt(
    business: &str,
    contract_name: &str,
    source_blob: &str,
    all_contracts: &[String],
) -> String {
    let contract_list = all_contracts.join(", ");
    format!(
        r#"Analyze this Solidity contract and list its DeFi semantics.

A "DeFi semantic" is a short canonical name (2-5 words) for a recurring economic
mechanism that smart contracts implement. Examples (DO NOT JUST COPY THESE — pick what
the actual code implements):

- "share accounting" — proportional ownership via shares
- "price oracle dependency" — read price from external oracle
- "spot price computation" — derive price from reserves
- "reward distribution" — per-staker reward accrual
- "liquidation accounting" — collateral seizure / debt repayment
- "flash loan callback" — borrow and require repayment within tx
- "cross-chain message dispatch" — emit / receive bridge message
- "token approval flow" — allowance-driven transferFrom
- "vault deposit / withdraw" — ERC4626-like or custom share/asset conversion
- "redemption queue" — withdraw via queued / delayed process
- "fee accumulation" — per-unit fee accrued into pool
- "voting power computation" — sum of stake or delegated balance
- "liquidity pool creation" — deploying and initializing AMM pools
- "peg rebalancing" — maintaining token peg via swaps
- "swap routing" — routing trades through DEX pools

The project's business types are: {business}
This contract is: {contract_name}
All contracts in the project: [{contract_list}]

Rules:
1. List the 3-8 most important semantics found in THIS contract.
2. Each semantic MUST be a short noun phrase, lowercase, NO punctuation other than spaces.
3. For each semantic, list the contracts that implement it (just contract names, comma-separated).
4. Output strictly in this format:

SEMANTIC: <short canonical name>
CATEGORY: <one of Lending, Dexes, Yield, Services, Derivatives, Yield Aggregator, Real World Assets, Stablecoins, Indexes, Insurance, NFT Marketplace, NFT Lending, Cross Chain, Others>
CONTRACTS: <Contract1, Contract2>
DESCRIPTION: <one sentence>

(blank line between entries)

5. Do NOT include explanations, headers, or markdown.
6. IMPORTANT: You MUST list at least 3 distinct semantics. Different contracts
   in this project implement different mechanisms — identify ALL of them.

Source code for {contract_name} (some may be truncated):
{source_blob}
"#,
    )
}

fn build_prompt(business: &str, source_blob: &str) -> String {
    format!(
        r#"Analyze this Solidity project and list its DeFi semantics.

A "DeFi semantic" is a short canonical name (2-5 words) for a recurring economic
mechanism that smart contracts implement. Examples (DO NOT JUST COPY THESE — pick what
the actual code implements):

- "share accounting" — proportional ownership via shares
- "price oracle dependency" — read price from external oracle
- "spot price computation" — derive price from reserves
- "reward distribution" — per-staker reward accrual
- "liquidation accounting" — collateral seizure / debt repayment
- "flash loan callback" — borrow and require repayment within tx
- "cross-chain message dispatch" — emit / receive bridge message
- "token approval flow" — allowance-driven transferFrom
- "vault deposit / withdraw" — ERC4626-like or custom share/asset conversion
- "redemption queue" — withdraw via queued / delayed process
- "fee accumulation" — per-unit fee accrued into pool
- "voting power computation" — sum of stake or delegated balance

The project's business types are: {business}

Rules:
1. List the 5-15 most important semantics found in the code.
2. Each semantic MUST be a short noun phrase, lowercase, NO punctuation other than spaces.
3. For each semantic, list the contracts that implement it (just contract names, comma-separated).
4. Output strictly in this format:

SEMANTIC: <short canonical name>
CATEGORY: <one of Lending, Dexes, Yield, Services, Derivatives, Yield Aggregator, Real World Assets, Stablecoins, Indexes, Insurance, NFT Marketplace, NFT Lending, Cross Chain, Others>
CONTRACTS: <Contract1, Contract2>
DESCRIPTION: <one sentence>

(blank line between entries)

5. Do NOT include explanations, headers, or markdown.

Source code (some may be truncated):
{source_blob}
"#,
    )
}

fn parse_response(response: &str, business: &[BusinessType]) -> Vec<DefiSemantic> {
    let mut out = Vec::new();
    let default_category = business
        .first()
        .map(|b| b.as_str().to_string())
        .unwrap_or_else(|| "Others".to_string());

    let mut current_name: Option<String> = None;
    let mut current_category: Option<String> = None;
    let mut current_contracts: Vec<String> = Vec::new();
    let mut current_desc: Option<String> = None;

    let flush = |name: &mut Option<String>,
                 category: &mut Option<String>,
                 contracts: &mut Vec<String>,
                 desc: &mut Option<String>,
                 default_category: &str,
                 out: &mut Vec<DefiSemantic>| {
        if let Some(n) = name.take() {
            let clean_name = canonicalize_name(&n);
            if clean_name.is_empty() {
                return;
            }
            out.push(DefiSemantic {
                name: clean_name,
                description: desc.take().unwrap_or_default(),
                category: category
                    .take()
                    .unwrap_or_else(|| default_category.to_string()),
                contracts: std::mem::take(contracts),
            });
        }
    };

    for raw in response.lines() {
        let line = raw.trim();
        if line.is_empty() {
            flush(
                &mut current_name,
                &mut current_category,
                &mut current_contracts,
                &mut current_desc,
                &default_category,
                &mut out,
            );
            continue;
        }
        if let Some(val) = strip_prefix_ci(line, "SEMANTIC:") {
            // Starting a new block — flush any in-progress entry first.
            flush(
                &mut current_name,
                &mut current_category,
                &mut current_contracts,
                &mut current_desc,
                &default_category,
                &mut out,
            );
            current_name = Some(val.trim().to_string());
        } else if let Some(val) = strip_prefix_ci(line, "CATEGORY:") {
            current_category = Some(val.trim().to_string());
        } else if let Some(val) = strip_prefix_ci(line, "CONTRACTS:") {
            current_contracts = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if let Some(val) = strip_prefix_ci(line, "DESCRIPTION:") {
            current_desc = Some(val.trim().to_string());
        } else if let Some(ref mut desc) = current_desc {
            // Treat continuation lines as part of description.
            desc.push(' ');
            desc.push_str(line);
        }
    }
    // Final flush
    flush(
        &mut current_name,
        &mut current_category,
        &mut current_contracts,
        &mut current_desc,
        &default_category,
        &mut out,
    );

    // Deduplicate by canonical name.
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.name.clone()));
    out
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn canonicalize_name(s: &str) -> String {
    let lower = s.to_lowercase();
    let collapsed: String = lower
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_response() {
        let response = r#"
SEMANTIC: share accounting
CATEGORY: Yield Aggregator
CONTRACTS: Vault, Strategy
DESCRIPTION: ERC4626-style share/asset conversion

SEMANTIC: liquidation accounting
CATEGORY: Lending
CONTRACTS: Pool
DESCRIPTION: Seize collateral and repay debt
"#;
        let parsed = parse_response(response, &[BusinessType::Others]);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "share accounting");
        assert_eq!(parsed[0].category, "Yield Aggregator");
        assert_eq!(parsed[0].contracts, vec!["Vault", "Strategy"]);
        assert_eq!(parsed[1].name, "liquidation accounting");
    }

    #[test]
    fn skips_garbage_blocks() {
        let response = r#"
Some preamble text that should be ignored.

SEMANTIC: vault deposit
CATEGORY: Yield Aggregator
CONTRACTS: Vault
DESCRIPTION: Deposit assets, mint shares

Random trailing garbage.
"#;
        let parsed = parse_response(response, &[]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "vault deposit");
    }

    #[test]
    fn dedupes_same_name() {
        let response = r#"
SEMANTIC: oracle dependency
CATEGORY: Services
CONTRACTS: Pool
DESCRIPTION: a

SEMANTIC: oracle dependency
CATEGORY: Services
CONTRACTS: Other
DESCRIPTION: b
"#;
        let parsed = parse_response(response, &[]);
        assert_eq!(parsed.len(), 1);
    }
}
