//! Specification Generator agent.
//!
//! Takes a `SemanticVulnPair` + project context, asks an LLM to produce a concrete
//! `AuditSpec` (initial / pre-vuln / post-vuln states) that a fuzzer can verify.
//!
//! The agent is multi-contract aware: it uses [`source_loader`] to assemble a
//! prompt blob covering the primary semantic contract(s) plus their imports,
//! so the LLM can reason across the whole subsystem.

pub mod source_loader;

use agent_core::{AgentResult, AuditSpec, SemanticVulnPair, SpecificationGenerator, WorkingMemory};
use agent_llm::LlmClient;
use async_trait::async_trait;
use source_loader::{LoaderConfig, load_project_sources, render_context_for_prompt};
use std::path::Path;
use tracing::{info, warn};

/// Default LLM-driven specification generator.
pub struct LlmSpecGenerator {
    client: LlmClient,
    loader: LoaderConfig,
}

impl LlmSpecGenerator {
    pub fn new(client: LlmClient) -> Self {
        Self {
            client,
            loader: LoaderConfig::default(),
        }
    }

    pub fn with_loader_config(mut self, cfg: LoaderConfig) -> Self {
        self.loader = cfg;
        self
    }

    /// Build a multi-contract source blob for the given pair, using the
    /// pair's `semantic.contracts` as seed targets.
    fn build_source_blob(&self, project_root: &str, pair: &SemanticVulnPair) -> String {
        let root = Path::new(project_root);
        if pair.semantic.contracts.is_empty() {
            warn!(
                "Pair '{}' has no associated contracts; loader will skip",
                pair.vulnerability.title
            );
            return "// no contracts in semantic; nothing to load\n".to_string();
        }
        match load_project_sources(root, &pair.semantic.contracts, &self.loader) {
            Ok(ctx) => {
                if !ctx.missing_targets.is_empty() {
                    warn!(
                        "Source loader could not find: {}",
                        ctx.missing_targets.join(", ")
                    );
                }
                render_context_for_prompt(&ctx)
            }
            Err(e) => {
                warn!("Source loader failed for {}: {}", root.display(), e);
                "// source loader error; LLM will work without project context\n".to_string()
            }
        }
    }
}

impl Default for LlmSpecGenerator {
    fn default() -> Self {
        Self {
            client: LlmClient::new(agent_llm::LlmConfig::from_env().unwrap_or_else(|| {
                agent_llm::LlmConfig {
                    provider: agent_llm::LlmProvider::Ollama,
                    api_key: String::new(),
                    model: String::new(),
                    base_url: "http://localhost:11434".to_string(),
                    max_tokens: 2048,
                    temperature: 0.2,
                    system_prompt: None,
                }
            })),
            loader: LoaderConfig::default(),
        }
    }
}

#[async_trait]
impl SpecificationGenerator for LlmSpecGenerator {
    async fn generate(
        &self,
        pair: &SemanticVulnPair,
        project_root: &str,
        _memory: &WorkingMemory,
    ) -> AgentResult<Option<AuditSpec>> {
        if !self.client.is_enabled() {
            warn!("LlmSpecGenerator disabled: no LLM configured");
            return Ok(None);
        }

        let primary_contract = pair
            .semantic
            .contracts
            .first()
            .cloned()
            .unwrap_or_else(|| "Target".to_string());
        let source_blob = self.build_source_blob(project_root, pair);

        let prompt = spec_prompt(pair, &primary_contract, &source_blob);
        info!(
            "Requesting spec from LLM for pair: {} (contracts: {})",
            pair.vulnerability.title,
            pair.semantic.contracts.join(", "),
        );

        let response = match self.client.complete(&prompt).await {
            Ok(r) => r,
            Err(e) => {
                warn!("LLM spec generation failed: {}", e);
                return Ok(None);
            }
        };

        match parse_audit_spec(&response, &pair_id(pair)) {
            Some(spec) => Ok(Some(spec)),
            None => {
                warn!("Failed to parse AuditSpec from LLM response");
                Ok(None)
            }
        }
    }

    async fn regenerate(
        &self,
        pair: &SemanticVulnPair,
        previous: &AuditSpec,
        feedback: &str,
        project_root: &str,
    ) -> AgentResult<Option<AuditSpec>> {
        if !self.client.is_enabled() {
            return Ok(None);
        }
        let primary_contract = pair
            .semantic
            .contracts
            .first()
            .cloned()
            .unwrap_or_else(|| "Target".to_string());
        let source_blob = self.build_source_blob(project_root, pair);

        let prompt = format!(
            "{}
\nPREVIOUS SPEC (which was flawed):\n{}\n\nFEEDBACK ON WHY IT FAILED:\n{}\n\nPlease regenerate the corrected AuditSpec JSON.\n",
            spec_prompt(pair, &primary_contract, &source_blob),
            serde_json::to_string_pretty(previous).unwrap_or_default(),
            feedback
        );

        let response = match self.client.complete(&prompt).await {
            Ok(r) => r,
            Err(e) => {
                warn!("LLM spec regeneration failed: {}", e);
                return Ok(None);
            }
        };

        match parse_audit_spec(&response, &pair_id(pair)) {
            Some(spec) => Ok(Some(spec)),
            None => Ok(None),
        }
    }
}

fn spec_prompt(pair: &SemanticVulnPair, contract_name: &str, source: &str) -> String {
    format!(
        r#"You are an expert smart contract security auditor. Given a vulnerability pattern and a primary target contract, produce a concrete audit specification (AuditSpec) that a fuzzing harness can verify.

VULNERABILITY PATTERN:
- Title: {title}
- Description: {desc}
- Severity: {severity}
- Attack Type: {attack_type}

SEMANTIC CONTEXT:
- Mechanism: {semantic_name}
- Description: {semantic_desc}
- Category: {semantic_cat}

PROJECT SOURCE (primary contract first, followed by direct dependencies; some files may be truncated):
```solidity
{source}
```

Your task: produce a JSON object matching this Rust struct exactly (no markdown fences, raw JSON only):

{{
  "pair_id": "<unique id>",
  "target_contracts": ["{contract_name}", "<dependency contract A>", "<dependency contract B>"],
  "target_function": "<function name where vulnerability manifests, or null>",
  "dependencies": [
    {{
      "contract": "{contract_name}",
      "constructor_args": ["<solidity expression>", "..."],
      "post_deploy_setters": ["targetA.setX(address(targetB))", "..."]
    }}
  ],
  "initial_state": [
    {{ "expression": "Solidity require/assert condition after setUp()", "description": "human-readable" }}
  ],
  "pre_vuln_state": [
    {{ "expression": "Solidity condition that must hold BEFORE the attack", "description": "human-readable" }}
  ],
  "post_vuln_state": [
    {{ "expression": "Solidity condition that must NEVER hold after the attack (the broken invariant)", "description": "human-readable" }}
  ],
  "attack_scenario": "Step-by-step description of how an attacker triggers the bug."
}}

Guidelines:
- `target_contracts`: List the primary contract FIRST, then any dependencies that must be deployed in `setUp()` to exercise the vulnerability (e.g., a Vault that depends on an ERC20 token + a Strategy). If only one contract is needed, use a single-element list.
- `dependencies`: One entry per contract in `target_contracts`. `constructor_args` are Solidity expressions evaluated in the harness scope (use `address(this)`, `attacker`, or other deployed contract instance names that match the contract names lowercased). `post_deploy_setters` are statements (without trailing `;`) executed after all contracts are deployed to wire the system together.
- `initial_state`: invariants that must be true after deployment / setUp (e.g., balances, ownership).
- `pre_vuln_state`: conditions that must hold right before the attack transaction (e.g., caller is not owner, amount > 0).
- `post_vuln_state`: the broken invariant — a Solidity expression that SHOULD be true in a correct implementation but is violated by the bug. Write it as a `require` condition that fails when the bug is present.
- Use only Solidity syntax in `expression`. No Yul or inline assembly unless necessary.
- Be concrete and project-specific; avoid generic statements.
- Output ONLY the raw JSON, no markdown, no explanations.
"#,
        title = pair.vulnerability.title,
        desc = pair.vulnerability.description,
        severity = pair.vulnerability.severity,
        attack_type = pair.vulnerability.attack_type,
        semantic_name = pair.semantic.name,
        semantic_desc = pair.semantic.description,
        semantic_cat = pair.semantic.category,
        contract_name = contract_name,
        source = source,
    )
}

/// Extract JSON from the LLM response (tolerates markdown fences).
fn parse_audit_spec(response: &str, default_pair_id: &str) -> Option<AuditSpec> {
    let trimmed = response.trim();
    let json_text = if trimmed.starts_with("```") {
        // Strip markdown fences
        let lines: Vec<&str> = trimmed.lines().collect();
        if lines.len() >= 3 {
            lines[1..lines.len() - 1].join("\n")
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };

    let mut spec: AuditSpec = serde_json::from_str(&json_text).ok()?;
    if spec.pair_id.is_empty() {
        spec.pair_id = default_pair_id.to_string();
    }
    // Reject specs without any target contract — downstream agents require it.
    if spec.target_contracts.is_empty() {
        return None;
    }
    Some(spec)
}

fn pair_id(pair: &SemanticVulnPair) -> String {
    format!(
        "{}__{}",
        pair.semantic.name.replace(' ', "_"),
        pair.vulnerability.title.replace(' ', "_")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::{DefiSemantic, SemanticVulnPair, VulnerabilityPattern};
    use agent_llm::{LlmConfig, LlmProvider};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn write_file(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    fn disabled_client() -> agent_llm::LlmClient {
        agent_llm::LlmClient::new(LlmConfig {
            provider: LlmProvider::Ollama,
            api_key: String::new(),
            model: String::new(),
            base_url: "http://localhost:11434".to_string(),
            max_tokens: 2048,
            temperature: 0.2,
            system_prompt: None,
        })
    }

    fn sample_pair(contracts: Vec<String>) -> SemanticVulnPair {
        SemanticVulnPair {
            semantic: DefiSemantic {
                name: "share accounting".to_string(),
                description: "Vault share accounting".to_string(),
                category: "Yield".to_string(),
                contracts,
            },
            vulnerability: VulnerabilityPattern {
                title: "inflated share price".to_string(),
                description: "First depositor can inflate share price".to_string(),
                root_cause: "incorrect initial share accounting".to_string(),
                severity: "High".to_string(),
                attack_type: "Arithmetic".to_string(),
            },
            relevance: 0.9,
        }
    }

    #[test]
    fn test_parse_audit_spec_raw_json_multi_contract() {
        let json = r#"{"pair_id":"","target_contracts":["Vault","Token"],"target_function":"deposit","dependencies":[{"contract":"Vault","constructor_args":["address(token)"],"post_deploy_setters":["vault.setStrategy(address(strategy))"]}],"initial_state":[{"expression":"vault.totalAssets() == 0","description":"initial assets zero"}],"pre_vuln_state":[{"expression":"amount > 0","description":"positive deposit"}],"post_vuln_state":[{"expression":"vault.totalAssets() >= amount","description":"assets must cover deposit"}],"attack_scenario":"First depositor inflates share price."}"#;
        let spec = parse_audit_spec(json, "id").unwrap();
        assert_eq!(spec.target_contracts, vec!["Vault", "Token"]);
        assert_eq!(spec.primary_contract(), "Vault");
        assert_eq!(spec.target_function, Some("deposit".to_string()));
        assert_eq!(spec.dependencies.len(), 1);
        assert_eq!(spec.dependencies[0].contract, "Vault");
        assert_eq!(
            spec.dependencies[0].constructor_args,
            vec!["address(token)"]
        );
        assert_eq!(spec.initial_state.len(), 1);
    }

    #[test]
    fn test_parse_audit_spec_legacy_single_contract_field() {
        // Backward compat: accept legacy `target_contract` string alongside missing `target_contracts`.
        let json = r#"{"pair_id":"","target_contract":"Vault","target_function":"deposit","initial_state":[],"pre_vuln_state":[],"post_vuln_state":[],"attack_scenario":"test"}"#;
        let spec = parse_audit_spec(json, "id").unwrap();
        assert_eq!(spec.target_contracts, vec!["Vault"]);
        assert_eq!(spec.primary_contract(), "Vault");
    }

    #[test]
    fn test_parse_audit_spec_with_fences() {
        let fenced = r#"
```json
{"pair_id":"","target_contracts":["Vault"],"target_function":null,"initial_state":[],"pre_vuln_state":[],"post_vuln_state":[],"attack_scenario":"test"}
```
"#;
        let spec = parse_audit_spec(fenced, "id").unwrap();
        assert_eq!(spec.primary_contract(), "Vault");
        assert!(spec.target_function.is_none());
    }

    #[test]
    fn test_parse_audit_spec_empty_targets_rejected() {
        let json = r#"{"pair_id":"x","target_contracts":[],"target_function":null,"initial_state":[],"pre_vuln_state":[],"post_vuln_state":[],"attack_scenario":""}"#;
        assert!(parse_audit_spec(json, "id").is_none());
    }

    #[test]
    fn build_source_blob_uses_pair_contracts_and_includes_dependencies() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "foundry.toml",
            "[profile.default]\nsrc = \"src\"\n",
        );
        write_file(
            dir.path(),
            "src/Vault.sol",
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./Token.sol";
import "./Strategy.sol";
contract Vault {
    Token public token;
    Strategy public strategy;
    constructor(Token _token) { token = _token; }
}
"#,
        );
        write_file(
            dir.path(),
            "src/Token.sol",
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balanceOf;
}
"#,
        );
        write_file(
            dir.path(),
            "src/Strategy.sol",
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Strategy {
    function harvest() external {}
}
"#,
        );

        let generator = LlmSpecGenerator::new(disabled_client());
        let pair = sample_pair(vec!["Vault".to_string()]);
        let blob = generator.build_source_blob(dir.path().to_str().unwrap(), &pair);

        assert!(blob.contains("Project type: Foundry"));
        assert!(blob.contains("Target (depth=0): src/Vault.sol"));
        assert!(blob.contains("Dependency (depth=1): src/Token.sol"));
        assert!(blob.contains("Dependency (depth=1): src/Strategy.sol"));
        assert!(blob.contains("contract Vault"));
        assert!(blob.contains("contract Token"));
        assert!(blob.contains("contract Strategy"));
    }
}
