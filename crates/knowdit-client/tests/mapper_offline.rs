//! End-to-end test of `KnowditMapper` using a mock semantic extractor and a
//! mocked Knowdit endpoint backed by a local HTTP server.
//!
//! Verifies the full pipeline (file discovery → classify → extract → query) without
//! requiring an LLM key or live network access.

use agent_core::{BusinessType, DefiSemantic, KnowledgeMapper};
use async_trait::async_trait;
use knowdit_client::{
    KnowditClient, KnowditConfig, KnowditMapper, MapperCache, ProjectFile, SemanticExtractor,
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

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
                contracts: vec!["Vault".to_string()],
            },
            DefiSemantic {
                name: "price oracle dependency".to_string(),
                description: "Reads price from oracle for redemption".to_string(),
                category: "Services".to_string(),
                contracts: vec!["Vault".to_string(), "Oracle".to_string()],
            },
        ])
    }
}

/// Spin up a tiny HTTP server that mimics the Knowdit API.
async fn start_mock_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{}", addr);

    tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(handle_conn(socket));
        }
    });
    base
}

async fn handle_conn(mut socket: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 8 * 1024];
    let mut total = 0;
    loop {
        let n = match socket.read(&mut buf[total..]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return,
        };
        total += n;
        let req = String::from_utf8_lossy(&buf[..total]).to_string();
        if req.contains("\r\n\r\n") {
            let (status, body) = if req.starts_with("GET /v1/session") {
                ("200 OK", "{\"token\":\"mock-token\"}".to_string())
            } else if req.starts_with("POST /v1/query") {
                let body = serde_json::json!({
                    "semantics": [
                        {"name": "Share Accounting", "category": "Yield Aggregator"},
                    ],
                    "semantic_vulnerability_links": [
                        {"share accounting": {
                            "title": "First-depositor share inflation attack",
                            "severity": "High"
                        }},
                        {"share accounting": {
                            "title": "Donation attack on share price",
                            "severity": "Medium"
                        }}
                    ],
                    "link_page": 1,
                    "page_next": null,
                    "links_per_page": 50,
                    "total_semantic_vulnerability_links": 2
                });
                ("200 OK", body.to_string())
            } else {
                ("404 Not Found", "{}".to_string())
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
            return;
        }
    }
}

fn make_fake_project() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let contracts = dir.path().join("src");
    std::fs::create_dir_all(&contracts).unwrap();
    // Primary file (a vault-like contract that should trigger Yield Aggregator heuristics)
    std::fs::write(
        contracts.join("Vault.sol"),
        r#"
contract Vault {
    function deposit(uint256 amount) external returns (uint256 shares) {
        shares = convertToShares(amount);
        totalAssets += amount;
    }
    function previewDeposit(uint256 amount) external view returns (uint256) {
        return convertToShares(amount);
    }
    function convertToShares(uint256 amount) public view returns (uint256) {
        return amount;
    }
    uint256 public totalAssets;
}
"#,
    )
    .unwrap();
    // Skip-pattern file (test) — shouldn't show up
    std::fs::create_dir_all(dir.path().join("test")).unwrap();
    std::fs::write(dir.path().join("test/VaultTest.t.sol"), "// fake test file").unwrap();
    dir
}

#[tokio::test]
async fn mapper_pipeline_runs_end_to_end() {
    let base_url = start_mock_server().await;

    let project = make_fake_project();
    let project_path = project.path().to_string_lossy().to_string();

    let client = Arc::new(KnowditClient::new(KnowditConfig {
        base_url,
        token: None,
        token_cache_path: None,
    }));
    let extractor: Arc<dyn SemanticExtractor> = Arc::new(FixedExtractor);

    let mapper = KnowditMapper::new(client, extractor)
        .with_cache(None)
        .with_max_pairs(20);

    let business = mapper.classify_business(&project_path).await.unwrap();
    assert!(
        business.contains(&BusinessType::YieldAggregator)
            || business.contains(&BusinessType::Yield)
            || business.contains(&BusinessType::Others),
        "expected Yield-related business type, got {:?}",
        business
    );

    let semantics = mapper.extract_semantics(&project_path).await.unwrap();
    assert_eq!(semantics.len(), 2);

    let pairs = mapper.map_to_pairs(&semantics).await.unwrap();
    // Both extracted semantics will query the mock endpoint which returns 2 vuln links
    // each, and the dedup is by (semantic_name, vuln_title) so we expect 4 pairs total.
    assert_eq!(pairs.len(), 4, "expected 4 pairs, got {}", pairs.len());

    // First pair should be High-severity.
    // Relevance = base_relevance * contract_name_relevance.
    // The mock titles contain generic DeFi terms ("share", "inflation") so
    // contract_name_relevance returns 0.7, making relevance = 0.85 * 0.7 = 0.595.
    assert!(
        pairs[0].relevance >= 0.5,
        "expected relevance >= 0.5, got {}",
        pairs[0].relevance
    );
    assert!(pairs[0].vulnerability.severity == "High");
    // Pairs sorted by relevance descending
    for w in pairs.windows(2) {
        assert!(
            w[0].relevance >= w[1].relevance,
            "pairs must be sorted by relevance"
        );
    }
}

#[tokio::test]
async fn cache_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let cache = MapperCache::new(dir.path());
    let key = knowdit_client::MapperCacheKey {
        project_root: "/tmp/fake".to_string(),
        content_hash: 12345,
    };
    let mapping = knowdit_client::cache::CachedMapping {
        key: key.clone(),
        business: vec![BusinessType::Lending],
        semantics: vec![],
        pairs: vec![],
        timestamp_ms: 0,
    };
    cache.store(&mapping).unwrap();
    let loaded = cache.load(&key).unwrap();
    assert_eq!(loaded.business, mapping.business);
}
