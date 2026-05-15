//! End-to-end `KnowditMapper` test using a mock extractor against the *live*
//! Knowdit API endpoint.
//!
//! This validates the full mapper pipeline (file discovery → classify → extract →
//! query Knowdit KG) without requiring a real LLM key.
//!
//! Run with:
//!   cargo test -p knowdit-client -- --ignored

use agent_core::{BusinessType, DefiSemantic, KnowledgeMapper};
use async_trait::async_trait;
use knowdit_client::{KnowditClient, KnowditConfig, KnowditMapper, ProjectFile, SemanticExtractor};
use std::sync::Arc;
use tempfile::TempDir;

struct FixedExtractor;

#[async_trait]
impl SemanticExtractor for FixedExtractor {
    async fn extract(
        &self,
        _files: &[ProjectFile],
        _business: &[BusinessType],
    ) -> Result<Vec<DefiSemantic>, knowdit_client::ExtractorError> {
        Ok(vec![
            DefiSemantic {
                name: "share accounting".to_string(),
                description: "ERC4626 style share/asset conversion".to_string(),
                category: "Yield Aggregator".to_string(),
                contracts: vec!["PasswordStore".to_string()],
            },
            DefiSemantic {
                name: "access control".to_string(),
                description: "Owner-only functions without proper access checks".to_string(),
                category: "DeFi".to_string(),
                contracts: vec!["PasswordStore".to_string()],
            },
        ])
    }
}

fn make_fake_project() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let contracts = dir.path().join("src");
    std::fs::create_dir_all(&contracts).unwrap();
    std::fs::write(
        contracts.join("PasswordStore.sol"),
        r#"
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract PasswordStore {
    address public s_owner;
    string private s_password;

    event SetNetPassword();

    constructor() {
        s_owner = msg.sender;
    }

    function setPassword(string memory newPassword) public {
        s_password = newPassword;
        emit SetNetPassword();
    }

    function getPassword() external view returns (string memory) {
        if (msg.sender != s_owner) {
            revert("__PasswordStore__not_owner");
        }
        return s_password;
    }
}
"#,
    )
    .unwrap();
    // Test file to be skipped
    std::fs::create_dir_all(dir.path().join("test")).unwrap();
    std::fs::write(
        dir.path().join("test/PasswordStore.t.sol"),
        "// fake test file",
    )
    .unwrap();
    dir
}

#[tokio::test]
#[ignore = "hits live Knowdit API (network required)"]
async fn mapper_e2e_with_live_api() {
    let project = make_fake_project();
    let project_path = project.path().to_string_lossy().to_string();

    let client = Arc::new(KnowditClient::new(KnowditConfig {
        token_cache_path: None,
        ..Default::default()
    }));
    let extractor: Arc<dyn SemanticExtractor> = Arc::new(FixedExtractor);

    let mapper = KnowditMapper::new(client, extractor)
        .with_cache(None)
        .with_max_pairs(20);

    // 1. Business classification
    let business = mapper
        .classify_business(&project_path)
        .await
        .expect("classify should succeed");
    assert!(!business.is_empty(), "expected at least one business type");

    // 2. Semantic extraction (via mock extractor)
    let semantics = mapper
        .extract_semantics(&project_path)
        .await
        .expect("extract should succeed");
    assert_eq!(semantics.len(), 2, "mock extractor returns 2 semantics");

    // 3. Map to vulnerability pairs (hits live API)
    let pairs = mapper
        .map_to_pairs(&semantics)
        .await
        .expect("map_to_pairs should succeed");

    assert!(
        !pairs.is_empty(),
        "expected at least one vulnerability pair from live API"
    );

    // All pairs should have valid relevance scores
    for pair in &pairs {
        assert!(
            pair.relevance >= 0.0 && pair.relevance <= 1.0,
            "relevance must be in [0,1]"
        );
        assert!(!pair.semantic.name.is_empty());
        assert!(!pair.vulnerability.title.is_empty());
    }

    // Relevance should be sorted descending
    for w in pairs.windows(2) {
        assert!(
            w[0].relevance >= w[1].relevance,
            "pairs must be sorted by relevance descending"
        );
    }

    eprintln!(
        "Live API returned {} pairs for project '{}'",
        pairs.len(),
        project_path
    );
    for (i, p) in pairs.iter().take(5).enumerate() {
        eprintln!(
            "  [{}] relevance={:.2} | semantic={:?} | vuln={:?} severity={}",
            i, p.relevance, p.semantic.name, p.vulnerability.title, p.vulnerability.severity
        );
    }
}
