//! Test Codex/api-x LLM provider integration.
//!
//! Requires api-x server running on http://127.0.0.1:8000
//!
//! Run with:
//!   cargo test -p agent-llm test_codex -- --ignored

use agent_llm::{LlmClient, LlmConfig, LlmProvider};

#[tokio::test]
#[ignore]
async fn test_codex_connection() {
    let config = LlmConfig {
        provider: LlmProvider::Codex,
        api_key: "local-key".to_string(),
        model: "codex-session".to_string(),
        base_url: "http://127.0.0.1:8000".to_string(),
        max_tokens: 100,
        temperature: 0.2,
        system_prompt: None,
    };

    let client = LlmClient::new(config);
    assert!(client.is_enabled(), "Codex client should be enabled");

    let response = client
        .complete("Hello, can you respond with 'ACK' in exactly 3 characters?")
        .await
        .expect("Codex API should respond");

    println!("Codex response: {}", response);
    assert!(!response.is_empty(), "response should not be empty");
}

#[tokio::test]
#[ignore]
async fn test_codex_chat() {
    let config = LlmConfig {
        provider: LlmProvider::Codex,
        api_key: "local-key".to_string(),
        model: "codex-session".to_string(),
        base_url: "http://127.0.0.1:8000".to_string(),
        max_tokens: 100,
        temperature: 0.2,
        system_prompt: None,
    };

    let client = LlmClient::new(config);
    let response = client
        .chat(
            Some("You are a helpful assistant. Be concise."),
            "What is 2 + 2? Answer with just the number.",
        )
        .await
        .expect("Codex chat should respond");

    println!("Codex chat response: {}", response);
    assert!(!response.is_empty(), "response should not be empty");
}
