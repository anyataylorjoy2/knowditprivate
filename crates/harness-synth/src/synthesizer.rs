use agent_core::{
    AgentResult, AuditSpec, ContractDependency, FuzzHarness, HarnessSynthesizer, WorkingMemory,
};
use agent_llm::LlmClient;
use async_trait::async_trait;
use tracing::{info, warn};

/// LLM-driven harness synthesizer that emits Foundry test contracts.
pub struct LlmHarnessSynthesizer {
    client: LlmClient,
}

impl LlmHarnessSynthesizer {
    pub fn new(client: LlmClient) -> Self {
        Self { client }
    }
}

impl Default for LlmHarnessSynthesizer {
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
        }
    }
}

#[async_trait]
impl HarnessSynthesizer for LlmHarnessSynthesizer {
    async fn synthesize(
        &self,
        spec: &AuditSpec,
        project_root: &str,
        _memory: &WorkingMemory,
    ) -> AgentResult<FuzzHarness> {
        if self.client.is_enabled() {
            let remappings = load_remappings(project_root);
            let prompt = harness_prompt(spec, &remappings);
            info!(
                "Requesting harness from LLM for spec: {} / {}",
                spec.pair_id,
                spec.primary_contract()
            );

            // Set environment variable for higher max_tokens in harness synthesis
            unsafe { std::env::set_var("HARNESS_SYNTHESIS", "1"); }

            match self.client.complete(&prompt).await {
                Ok(response) => {
                    let source = extract_solidity_source(&response);
                    if !source.contains("contract ") {
                        warn!("LLM harness response lacks a contract declaration; using fallback");
                    } else {
                        return Ok(FuzzHarness {
                            spec_id: spec.pair_id.clone(),
                            source,
                            file_path: format!("test/Knowdit_{}.t.sol", sanitize(&spec.pair_id)),
                            test_name: format!("test_invariant_{}", sanitize(&spec.pair_id)),
                        });
                    }
                }
                Err(e) => {
                    warn!("LLM harness synthesis failed: {}", e);
                }
            }
        }

        // Fallback: emit a minimal scaffold that Foundry can compile (and likely fail meaningfully).
        let source = fallback_harness(spec);
        Ok(FuzzHarness {
            spec_id: spec.pair_id.clone(),
            source,
            file_path: format!("test/Knowdit_{}.t.sol", sanitize(&spec.pair_id)),
            test_name: format!("test_invariant_{}", sanitize(&spec.pair_id)),
        })
    }

    async fn regenerate(
        &self,
        spec: &AuditSpec,
        previous: &FuzzHarness,
        error: &str,
        project_root: &str,
    ) -> AgentResult<FuzzHarness> {
        if !self.client.is_enabled() {
            return Ok(previous.clone());
        }
        let remappings = load_remappings(project_root);
        let prompt = format!(
            "{}
\nPREVIOUS HARNESS (which failed to compile or run):\n```solidity\n{}\n```\n\nERROR / FEEDBACK:\n{}\n\nPlease regenerate the corrected Solidity harness. Output ONLY the Solidity source, no markdown fences, no explanations.\n",
            harness_prompt(spec, &remappings),
            previous.source,
            error
        );

        // Set environment variable for higher max_tokens in harness synthesis
        unsafe { std::env::set_var("HARNESS_SYNTHESIS", "1"); }

        match self.client.complete(&prompt).await {
            Ok(response) => {
                let source = extract_solidity_source(&response);
                Ok(FuzzHarness {
                    spec_id: spec.pair_id.clone(),
                    source,
                    file_path: previous.file_path.clone(),
                    test_name: previous.test_name.clone(),
                })
            }
            Err(e) => {
                warn!("LLM harness regeneration failed: {}", e);
                Ok(previous.clone())
            }
        }
    }
}

fn harness_prompt(spec: &AuditSpec, remappings: &[(String, String)]) -> String {
    let invariants = |label: &str, list: &[agent_core::Invariant]| {
        let lines: Vec<String> = list
            .iter()
            .map(|i| format!("  - {}: {}", i.expression, i.description))
            .collect();
        if lines.is_empty() {
            format!("{}: (none specified)\n", label)
        } else {
            format!("{}:\n{}\n", label, lines.join("\n"))
        }
    };

    let primary = spec.primary_contract();
    let dependency_listing = render_dependency_listing(spec);
    let remappings_section = if remappings.is_empty() {
        String::new()
    } else {
        let lines: Vec<String> = remappings
            .iter()
            .map(|(k, v)| format!("  {} => {}", k, v))
            .collect();
        format!(
            "PROJECT REMAPPINGS (use these for import paths):\n{}\n\n",
            lines.join("\n")
        )
    };

    format!(
        r#"You are a smart contract security engineer. Generate a Foundry (forge) test contract that verifies the following audit specification.

PRIMARY CONTRACT: {primary}
TARGET FUNCTION: {target_function}

{remappings_section}CONTRACTS TO DEPLOY (in order):
{dependency_listing}

{initial_state}
{pre_vuln_state}
{post_vuln_state}
ATTACK SCENARIO:
{attack_scenario}

Instructions:
- Emit a single Solidity file named `Knowdit_{pair_id}.t.sol`.
- Import every contract listed above. Use the EXACT import paths from the project's source code — look at how the primary contract imports its dependencies and mirror those paths. For Foundry projects, prefer remapping-based imports (e.g., `@openzeppelin/contracts/...`) over relative paths when remappings exist. If a contract is in a subdirectory of `src/`, use the correct relative path (e.g., `../src/rebalance/LamboRebalanceOnUniwap.sol`). For contracts in `lib/` dependencies, use the remapping prefix (e.g., `@uniswap/contracts/UniswapV2ERC20.sol` or `morpho-blue/src/Morpho.sol`). Do NOT assume every contract lives at `src/<ContractName>.sol`.
- In `setUp()`, deploy every contract listed in CONTRACTS TO DEPLOY in the given order. Use the provided constructor args and the variable name `<contractName_lowercased>` for each deployed instance (so `Vault` becomes `vault`).
- After all deployments, execute every post-deploy setter listed under each contract.
- Write a test function `test_invariant_{pair_id}` that:
  1. Sets up additional state needed for the attack (e.g., funding the attacker via `deal`).
  2. Executes the attack scenario (e.g., calling the vulnerable function with crafted inputs, using multiple actors if needed).
  3. Asserts the post-vuln invariants using `assert*` or `require`. If the invariant should FAIL when the bug is present, write the test so it PASSES when the bug is present (PoC style; use `assertFalse(condition)` or have the call revert with a specific error).
- Use `vm.prank(address)` / `vm.startPrank(address)` for actor switching. Use `address(0xA11CE)` for `attacker`, `address(0xB0B)` for `bob`, etc., when needed.
- Do NOT use any console logging unless necessary.
- Output ONLY the raw Solidity source code. No markdown fences, no explanations.
"#,
        primary = primary,
        target_function = spec.target_function.as_deref().unwrap_or("(any)"),
        remappings_section = remappings_section,
        dependency_listing = dependency_listing,
        initial_state = invariants("INITIAL STATE INVARIANTS", &spec.initial_state),
        pre_vuln_state = invariants("PRE-VULN INVARIANTS", &spec.pre_vuln_state),
        post_vuln_state = invariants(
            "POST-VULN INVARIANTS (should be violated by the bug)",
            &spec.post_vuln_state
        ),
        attack_scenario = spec.attack_scenario,
        pair_id = sanitize(&spec.pair_id),
    )
}

/// Build a human-readable list of contracts + constructor args + setters,
/// covering both `spec.target_contracts` and `spec.dependencies`. If a contract
/// in `target_contracts` is missing from `dependencies`, it's emitted with
/// empty constructor args (zero-arg `new ContractName()`).
fn render_dependency_listing(spec: &AuditSpec) -> String {
    if spec.target_contracts.is_empty() {
        return "  (no contracts specified)".to_string();
    }
    let mut out = String::new();
    for (idx, contract) in spec.target_contracts.iter().enumerate() {
        let dep = find_dependency(spec, contract);
        let var = lowercase_first(contract);
        let args = dep
            .map(|d| d.constructor_args.join(", "))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {}. {} {} = new {}({});\n",
            idx + 1,
            contract,
            var,
            contract,
            args
        ));
        if let Some(d) = dep {
            for setter in &d.post_deploy_setters {
                out.push_str(&format!("       (post-deploy) {};\n", setter));
            }
        }
    }
    out
}

fn find_dependency<'a>(spec: &'a AuditSpec, contract: &str) -> Option<&'a ContractDependency> {
    spec.dependencies
        .iter()
        .find(|d| d.contract.eq_ignore_ascii_case(contract))
}

fn lowercase_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Extract Solidity source from LLM response, stripping markdown fences if present.
fn extract_solidity_source(response: &str) -> String {
    let trimmed = response.trim();
    if trimmed.starts_with("```solidity") || trimmed.starts_with("```") {
        let lines: Vec<&str> = trimmed.lines().collect();
        if lines.len() >= 3 {
            lines[1..lines.len() - 1].join("\n")
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    }
}

/// Minimal fallback harness when LLM is disabled or fails. Emits imports +
/// deployments for every contract in `spec.target_contracts`, applying any
/// constructor args / post-deploy setters from `spec.dependencies`.
fn fallback_harness(spec: &AuditSpec) -> String {
    let invariants: Vec<String> = spec
        .post_vuln_state
        .iter()
        .map(|inv| {
            format!(
                "        // Invariant: {}\n        // Expression: {}",
                inv.description, inv.expression
            )
        })
        .collect();

    let imports: String = spec
        .target_contracts
        .iter()
        .map(|c| format!("import \"../src/{c}.sol\";\n"))
        .collect();

    let state_vars: String = spec
        .target_contracts
        .iter()
        .map(|c| format!("    {c} public {var};\n", c = c, var = lowercase_first(c)))
        .collect();

    let mut deploys = String::new();
    for c in &spec.target_contracts {
        let var = lowercase_first(c);
        let args = find_dependency(spec, c)
            .map(|d| d.constructor_args.join(", "))
            .unwrap_or_default();
        deploys.push_str(&format!("        {var} = new {c}({args});\n"));
    }
    for c in &spec.target_contracts {
        if let Some(dep) = find_dependency(spec, c) {
            for setter in &dep.post_deploy_setters {
                deploys.push_str(&format!("        {setter};\n"));
            }
        }
    }

    let pair_id = sanitize(&spec.pair_id);

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
{imports}
contract Knowdit_{pair_id} is Test {{
{state_vars}
    function setUp() public {{
{deploys}    }}

    function test_invariant_{pair_id}() public {{
        // TODO: implement attack scenario per spec
{invariants}
    }}
}}
"#,
        imports = imports,
        state_vars = state_vars,
        deploys = deploys,
        pair_id = pair_id,
        invariants = invariants.join("\n"),
    )
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

/// Load Foundry remappings from `remappings.txt` in the project root.
/// Returns a list of (prefix, path) pairs, e.g. `("@openzeppelin/", "lib/openzeppelin-contracts/")`.
fn load_remappings(project_root: &str) -> Vec<(String, String)> {
    let root = std::path::Path::new(project_root);
    let remappings_path = root.join("remappings.txt");
    if !remappings_path.is_file() {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&remappings_path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let eq_pos = line.find('=')?;
            let prefix = line[..eq_pos].trim().to_string();
            let path = line[eq_pos + 1..].trim().to_string();
            if prefix.is_empty() || path.is_empty() {
                None
            } else {
                Some((prefix, path))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::Invariant;
    use std::path::Path;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write_file(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    fn multi_contract_spec() -> AuditSpec {
        AuditSpec {
            pair_id: "vault share inflation".to_string(),
            target_contracts: vec![
                "Token".to_string(),
                "Vault".to_string(),
                "Strategy".to_string(),
            ],
            target_function: Some("deposit".to_string()),
            dependencies: vec![
                ContractDependency {
                    contract: "Token".to_string(),
                    constructor_args: vec![],
                    post_deploy_setters: vec![],
                },
                ContractDependency {
                    contract: "Vault".to_string(),
                    constructor_args: vec!["address(token)".to_string()],
                    post_deploy_setters: vec!["vault.setStrategy(address(strategy))".to_string()],
                },
                ContractDependency {
                    contract: "Strategy".to_string(),
                    constructor_args: vec!["address(vault)".to_string()],
                    post_deploy_setters: vec!["strategy.setKeeper(address(this))".to_string()],
                },
            ],
            initial_state: vec![],
            pre_vuln_state: vec![],
            post_vuln_state: vec![Invariant {
                expression: "vault.totalAssets() >= token.balanceOf(address(vault))".to_string(),
                description: "vault assets cover token balance".to_string(),
            }],
            attack_scenario: "Attacker inflates share price before deposit".to_string(),
        }
    }

    #[test]
    fn fallback_harness_deploys_multi_contract_dependencies_in_order() {
        let source = fallback_harness(&multi_contract_spec());

        assert!(source.contains("import \"../src/Token.sol\";"));
        assert!(source.contains("import \"../src/Vault.sol\";"));
        assert!(source.contains("import \"../src/Strategy.sol\";"));
        assert!(source.contains("Token public token;"));
        assert!(source.contains("Vault public vault;"));
        assert!(source.contains("Strategy public strategy;"));

        let token_deploy = source.find("token = new Token();").unwrap();
        let vault_deploy = source.find("vault = new Vault(address(token));").unwrap();
        let strategy_deploy = source
            .find("strategy = new Strategy(address(vault));")
            .unwrap();
        let vault_setter = source
            .find("vault.setStrategy(address(strategy));")
            .unwrap();
        let strategy_setter = source.find("strategy.setKeeper(address(this));").unwrap();

        assert!(token_deploy < vault_deploy);
        assert!(vault_deploy < strategy_deploy);
        assert!(strategy_deploy < vault_setter);
        assert!(vault_setter < strategy_setter);
        assert!(source.contains("function test_invariant_vault_share_inflation() public"));
        assert!(source.contains("vault assets cover token balance"));
    }

    #[test]
    fn load_remappings_parses_remappings_txt() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "remappings.txt",
            "@openzeppelin/=lib/openzeppelin-contracts/\n@uniswap/=lib/v2-core/contracts/\n",
        );
        let remappings = load_remappings(dir.path().to_str().unwrap());
        assert_eq!(remappings.len(), 2);
        assert_eq!(
            remappings[0],
            (
                "@openzeppelin/".to_string(),
                "lib/openzeppelin-contracts/".to_string()
            )
        );
        assert_eq!(
            remappings[1],
            (
                "@uniswap/".to_string(),
                "lib/v2-core/contracts/".to_string()
            )
        );
    }

    #[test]
    fn load_remappings_returns_empty_when_no_file() {
        let dir = TempDir::new().unwrap();
        let remappings = load_remappings(dir.path().to_str().unwrap());
        assert!(remappings.is_empty());
    }

    #[test]
    fn harness_prompt_includes_remappings_section() {
        let spec = multi_contract_spec();
        let remappings = vec![
            (
                "@openzeppelin/".to_string(),
                "lib/openzeppelin-contracts/".to_string(),
            ),
            (
                "@uniswap/".to_string(),
                "lib/v2-core/contracts/".to_string(),
            ),
        ];
        let prompt = harness_prompt(&spec, &remappings);
        assert!(prompt.contains("PROJECT REMAPPINGS"));
        assert!(prompt.contains("@openzeppelin/ => lib/openzeppelin-contracts/"));
        assert!(prompt.contains("@uniswap/ => lib/v2-core/contracts/"));
    }

    #[test]
    fn harness_prompt_omits_remappings_when_empty() {
        let spec = multi_contract_spec();
        let prompt = harness_prompt(&spec, &[]);
        assert!(!prompt.contains("PROJECT REMAPPINGS"));
    }
}
