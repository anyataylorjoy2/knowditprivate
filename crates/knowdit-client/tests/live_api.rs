//! Live API probe tests. These hit the real Knowdit endpoint and require
//! network access; they are gated behind `#[ignore]` so `cargo test` doesn't
//! run them automatically.
//!
//! Run explicitly with:
//!   cargo test -p knowdit-client -- --ignored

use knowdit_client::{KnowditClient, KnowditConfig, QueryRequest};

#[tokio::test]
#[ignore]
async fn live_session_and_query() {
    let client = KnowditClient::new(KnowditConfig {
        token_cache_path: None,
        ..Default::default()
    });

    let req = QueryRequest {
        query: "share accounting".to_string(),
        category: Some("Yield Aggregator".to_string()),
        links_per_page: Some(5),
        link_page: None,
    };

    let resp = client
        .query(&req)
        .await
        .expect("Knowdit API should respond successfully");

    assert!(!resp.semantics.is_empty(), "expected at least one semantic");
    let links = resp.flat_links();
    assert!(
        !links.is_empty(),
        "expected at least one vulnerability link"
    );
    // Severity values we expect to see in the wild
    for link in &links {
        assert!(
            !link.title.is_empty(),
            "every link should have a non-empty title"
        );
        assert!(
            [
                "Critical",
                "High",
                "Medium",
                "Low",
                "Informational",
                "Unknown"
            ]
            .iter()
            .any(|s| link.severity.eq_ignore_ascii_case(s)),
            "unexpected severity: {}",
            link.severity
        );
    }
}
