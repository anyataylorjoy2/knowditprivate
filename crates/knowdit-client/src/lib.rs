//! HTTP client + Knowledge Mapper for the official Knowdit Knowledge Graph API.
//!
//! Endpoint: https://knowdit-kg.abort.rs/solidity
//! - `GET /v1/session` — issues bearer token
//! - `POST /v1/query` — query semantics + linked vulnerability findings
//!
//! Rate limit: 1 request per second. We enforce client-side throttling.

pub mod cache;
pub mod classifier;
pub mod client;
pub mod extractor;
pub mod mapper;
pub mod project;

pub use cache::{
    KgVocabCache, MapperCache, MapperCacheKey, PairArtifactCache, VocabMatchCache,
};
pub use classifier::{ClassificationResult, classify_heuristic};
pub use client::{ApiSemantic, KnowditClient, KnowditConfig, KnowditError, QueryRequest, QueryResponse};
pub use extractor::{ExtractorError, LlmSemanticExtractor, SemanticExtractor};
pub use mapper::KnowditMapper;
pub use project::{FileKind, ProjectFile, discover_project_files};
