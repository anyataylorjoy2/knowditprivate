//! HTTP client for Knowdit public API.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_BASE_URL: &str = "https://knowdit-kg.abort.rs/solidity";
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(1100);

/// Configuration for the Knowdit client.
#[derive(Debug, Clone)]
pub struct KnowditConfig {
    pub base_url: String,
    /// Optional pre-existing bearer token; if None, will be fetched via /v1/session.
    pub token: Option<String>,
    /// Optional path to persist token between runs (default: .knowdit).
    pub token_cache_path: Option<PathBuf>,
}

impl Default for KnowditConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            token: None,
            token_cache_path: Some(PathBuf::from(".knowdit")),
        }
    }
}

/// Request body for POST /v1/query.
#[derive(Debug, Clone, Serialize)]
pub struct QueryRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links_per_page: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_page: Option<u32>,
}

/// A semantic node returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSemantic {
    pub name: String,
    pub category: String,
}

/// A linked vulnerability finding returned by the API.
/// The API returns a map from semantic name → finding details, so we use a flexible representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVulnLink {
    pub semantic_name: String,
    pub title: String,
    pub severity: String,
}

/// Response body for POST /v1/query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub semantics: Vec<ApiSemantic>,
    #[serde(default)]
    pub semantic_vulnerability_links: Vec<serde_json::Value>,
    #[serde(default)]
    pub link_page: u32,
    #[serde(default)]
    pub page_next: Option<u32>,
    #[serde(default)]
    pub links_per_page: u32,
    #[serde(default)]
    pub total_semantic_vulnerability_links: u32,
}

impl QueryResponse {
    /// Flatten the heterogeneous `semantic_vulnerability_links` into a typed list.
    pub fn flat_links(&self) -> Vec<ApiVulnLink> {
        let mut out = Vec::new();
        for entry in &self.semantic_vulnerability_links {
            if let Some(obj) = entry.as_object() {
                for (sem_name, val) in obj {
                    if let Some(v) = val.as_object() {
                        let title = v
                            .get("title")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();
                        let severity = v
                            .get("severity")
                            .and_then(|s| s.as_str())
                            .unwrap_or("Unknown")
                            .to_string();
                        out.push(ApiVulnLink {
                            semantic_name: sem_name.clone(),
                            title,
                            severity,
                        });
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KnowditError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Token missing and /v1/session call failed")]
    NoToken,
    #[error("Response missing token field")]
    InvalidSessionResponse,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Client for the Knowdit Knowledge Graph API with rate limiting and token caching.
pub struct KnowditClient {
    config: KnowditConfig,
    http: reqwest::Client,
    token: Mutex<Option<String>>,
    last_request: Mutex<Option<Instant>>,
}

impl KnowditClient {
    pub fn new(config: KnowditConfig) -> Self {
        let token = config.token.clone();
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client build"),
            token: Mutex::new(token),
            last_request: Mutex::new(None),
        }
    }

    fn load_token_from_cache(&self) -> Option<String> {
        let path = self.config.token_cache_path.as_ref()?;
        let raw = std::fs::read_to_string(path).ok()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn save_token_to_cache(&self, token: &str) -> Result<(), std::io::Error> {
        if let Some(path) = &self.config.token_cache_path {
            std::fs::write(path, token)?;
        }
        Ok(())
    }

    async fn ensure_token(&self) -> Result<String, KnowditError> {
        // Already have a token in memory?
        if let Some(t) = self.token.lock().unwrap().clone() {
            return Ok(t);
        }
        // Try cache.
        if let Some(t) = self.load_token_from_cache() {
            *self.token.lock().unwrap() = Some(t.clone());
            return Ok(t);
        }
        // Fetch new.
        self.throttle().await;
        let url = format!("{}/v1/session", self.config.base_url);
        let resp = self.http.get(&url).send().await?;
        let json: serde_json::Value = resp.json().await?;
        let token = json
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or(KnowditError::InvalidSessionResponse)?
            .to_string();
        let _ = self.save_token_to_cache(&token);
        *self.token.lock().unwrap() = Some(token.clone());
        Ok(token)
    }

    /// Throttle to <= 1 request/sec.
    async fn throttle(&self) {
        let wait = {
            let mut last = self.last_request.lock().unwrap();
            let now = Instant::now();
            let wait = match *last {
                Some(prev) => {
                    let elapsed = now.duration_since(prev);
                    if elapsed < MIN_REQUEST_INTERVAL {
                        Some(MIN_REQUEST_INTERVAL - elapsed)
                    } else {
                        None
                    }
                }
                None => None,
            };
            *last = Some(now);
            wait
        };
        if let Some(d) = wait {
            tokio::time::sleep(d).await;
        }
    }

    /// Perform a single semantic query.
    pub async fn query(&self, req: &QueryRequest) -> Result<QueryResponse, KnowditError> {
        let token = self.ensure_token().await?;
        self.throttle().await;
        let url = format!("{}/v1/query", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .json(req)
            .send()
            .await?;
        let body: QueryResponse = resp.json().await?;
        Ok(body)
    }

    /// Convenience: query and auto-paginate to collect all linked vulnerabilities.
    /// Hard cap at `max_pages` to avoid runaway.
    pub async fn query_all(
        &self,
        req: &QueryRequest,
        max_pages: u32,
    ) -> Result<Vec<ApiVulnLink>, KnowditError> {
        let mut all = Vec::new();
        let mut page = 1u32;
        loop {
            let mut paged_req = req.clone();
            paged_req.link_page = Some(page);
            let resp = self.query(&paged_req).await?;
            all.extend(resp.flat_links());
            match resp.page_next {
                Some(next) if next > page && page < max_pages => page = next,
                _ => break,
            }
        }
        Ok(all)
    }
}
