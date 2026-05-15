//! Project-level cache for Knowledge Mapper outputs.
//!
//! The mapper makes 2 LLM calls + N Knowdit API calls per project (one per semantic).
//! We cache by `(project_path, content_hash)` so re-runs on the same project are free.
//!
//! Three layers of caching:
//!
//! 1. [`MapperCache`] — caches the full pipeline result (business + semantics + pairs)
//!    keyed by project + content hash. Idempotent reruns on the same project hit this.
//! 2. [`KgVocabCache`] — caches the KG vocabulary fetched per business-type set.
//!    The KG vocabulary changes only when Knowdit's catalog changes; we use a
//!    7-day TTL by default. Across different projects with the same business
//!    types, this is a huge win.
//! 3. [`VocabMatchCache`] — caches the LLM vocabulary-matching sub-step keyed by
//!    `(extracted_semantics_hash, kg_vocab_hash)`. Even if the project's
//!    extracted-semantic set shifts slightly between runs, identical sets
//!    avoid the most expensive single LLM call in the mapper phase.
//! 4. [`PairArtifactCache`] — caches spec-gen + harness-synth output per pair_id
//!    so an audit that aborts mid-run (e.g. Codex quota) can resume without
//!    re-running already-completed LLM calls.

use crate::client::ApiSemantic;
use agent_core::{AuditSpec, BusinessType, DefiSemantic, FuzzHarness, SemanticVulnPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache key combining project root + a stable hash of its discovered file paths + sizes.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MapperCacheKey {
    pub project_root: String,
    pub content_hash: u64,
}

impl MapperCacheKey {
    pub fn new(project_root: &str, files: &[crate::project::ProjectFile]) -> Self {
        let mut hasher = DefaultHasher::new();
        for f in files {
            f.path.to_string_lossy().hash(&mut hasher);
            f.byte_size.hash(&mut hasher);
        }
        Self {
            project_root: project_root.to_string(),
            content_hash: hasher.finish(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMapping {
    pub key: MapperCacheKey,
    pub business: Vec<BusinessType>,
    pub semantics: Vec<DefiSemantic>,
    pub pairs: Vec<SemanticVulnPair>,
    pub timestamp_ms: u64,
}

/// Simple JSON file cache. Reads/writes a single file per key.
pub struct MapperCache {
    pub dir: PathBuf,
}

impl MapperCache {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn default_path() -> Self {
        Self::new(".sol-agent-cache/mapper")
    }

    fn path_for(&self, key: &MapperCacheKey) -> PathBuf {
        self.dir.join(format!("{:x}.json", key.content_hash))
    }

    pub fn load(&self, key: &MapperCacheKey) -> Option<CachedMapping> {
        let path = self.path_for(key);
        let raw = std::fs::read_to_string(&path).ok()?;
        let parsed: CachedMapping = serde_json::from_str(&raw).ok()?;
        if parsed.key == *key {
            Some(parsed)
        } else {
            None
        }
    }

    pub fn store(&self, mapping: &CachedMapping) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.path_for(&mapping.key);
        std::fs::write(&path, serde_json::to_string_pretty(mapping).unwrap())
    }
}

// ---------------------------------------------------------------------------
// KG vocabulary cache — keyed by business-type set, TTL bounded.
// ---------------------------------------------------------------------------

const DEFAULT_KG_VOCAB_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Disk cache for KG vocabulary fetched per business-type set.
///
/// Key: sha256 of sorted business-type names. Cached entries expire after `ttl_secs`.
pub struct KgVocabCache {
    pub dir: PathBuf,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedKgVocab {
    pub business_types: Vec<String>,
    pub semantics: Vec<ApiSemantic>,
    pub timestamp_ms: u64,
}

impl KgVocabCache {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            ttl_secs: DEFAULT_KG_VOCAB_TTL_SECS,
        }
    }

    pub fn default_path() -> Self {
        Self::new(".sol-agent-cache/kg_vocab")
    }

    pub fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    fn key_for(business: &[BusinessType]) -> String {
        let mut names: Vec<String> = business.iter().map(|b| b.as_str().to_string()).collect();
        names.sort();
        let mut hasher = Sha256::new();
        for n in &names {
            hasher.update(n.as_bytes());
            hasher.update(b"|");
        }
        format!("{:x}", hasher.finalize())
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{}.json", key))
    }

    pub fn load(&self, business: &[BusinessType]) -> Option<Vec<ApiSemantic>> {
        let key = Self::key_for(business);
        let raw = std::fs::read_to_string(self.path_for(&key)).ok()?;
        let parsed: CachedKgVocab = serde_json::from_str(&raw).ok()?;
        let now = now_ms();
        let age = now.saturating_sub(parsed.timestamp_ms) / 1000;
        if age > self.ttl_secs {
            return None;
        }
        Some(parsed.semantics)
    }

    pub fn store(
        &self,
        business: &[BusinessType],
        semantics: &[ApiSemantic],
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let key = Self::key_for(business);
        let cached = CachedKgVocab {
            business_types: business.iter().map(|b| b.as_str().to_string()).collect(),
            semantics: semantics.to_vec(),
            timestamp_ms: now_ms(),
        };
        std::fs::write(self.path_for(&key), serde_json::to_string_pretty(&cached).unwrap())
    }
}

// ---------------------------------------------------------------------------
// Vocabulary-match sub-cache — keyed by (extracted set, kg vocab hash).
// ---------------------------------------------------------------------------

/// Disk cache for the LLM vocabulary-matching sub-step.
///
/// The matching step can be the single most expensive LLM call in the mapper
/// because it must consider many candidates. We cache the resulting
/// `extracted name → kg name` map keyed by both the extracted-semantic set and
/// the KG vocabulary fingerprint, so re-runs hit the cache.
pub struct VocabMatchCache {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVocabMatch {
    pub matches: Vec<(String, String)>, // (extracted_name, kg_name)
    pub timestamp_ms: u64,
}

impl VocabMatchCache {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn default_path() -> Self {
        Self::new(".sol-agent-cache/vocab_match")
    }

    pub fn key_for(extracted: &[DefiSemantic], kg_vocab: &[ApiSemantic]) -> String {
        let mut hasher = Sha256::new();
        let mut e_names: Vec<&str> = extracted.iter().map(|s| s.name.as_str()).collect();
        e_names.sort();
        for n in &e_names {
            hasher.update(n.as_bytes());
            hasher.update(b"|");
        }
        hasher.update(b"##");
        let mut k_names: Vec<&str> = kg_vocab.iter().map(|s| s.name.as_str()).collect();
        k_names.sort();
        for n in &k_names {
            hasher.update(n.as_bytes());
            hasher.update(b"|");
        }
        format!("{:x}", hasher.finalize())
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{}.json", key))
    }

    pub fn load(
        &self,
        extracted: &[DefiSemantic],
        kg_vocab: &[ApiSemantic],
    ) -> Option<Vec<(String, String)>> {
        let key = Self::key_for(extracted, kg_vocab);
        let raw = std::fs::read_to_string(self.path_for(&key)).ok()?;
        let parsed: CachedVocabMatch = serde_json::from_str(&raw).ok()?;
        Some(parsed.matches)
    }

    pub fn store(
        &self,
        extracted: &[DefiSemantic],
        kg_vocab: &[ApiSemantic],
        matches: &[(String, String)],
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let key = Self::key_for(extracted, kg_vocab);
        let cached = CachedVocabMatch {
            matches: matches.to_vec(),
            timestamp_ms: now_ms(),
        };
        std::fs::write(self.path_for(&key), serde_json::to_string_pretty(&cached).unwrap())
    }
}

// ---------------------------------------------------------------------------
// Per-pair spec / harness artifact cache — keyed by (project, pair_id).
// ---------------------------------------------------------------------------

/// Disk cache for per-pair spec-gen + harness-synth artifacts.
///
/// Audit runs frequently abort mid-pipeline (Codex quota, network). We cache
/// each LLM-produced artifact keyed by (project_root, pair_id) so a re-run
/// can skip the LLM calls and resume from where we stopped.
pub struct PairArtifactCache {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSpec {
    pub project_root: String,
    pub pair_id: String,
    pub spec: AuditSpec,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedHarness {
    pub project_root: String,
    pub spec_id: String,
    pub harness: FuzzHarness,
    pub timestamp_ms: u64,
}

impl PairArtifactCache {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn default_path() -> Self {
        Self::new(".sol-agent-cache/pair_artifacts")
    }

    fn project_hash(project_root: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(project_root.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    fn id_hash(id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        format!("{:x}", hasher.finalize())[..24].to_string()
    }

    fn spec_path(&self, project_root: &str, pair_id: &str) -> PathBuf {
        self.dir.join(format!(
            "spec_{}_{}.json",
            Self::project_hash(project_root),
            Self::id_hash(pair_id)
        ))
    }

    fn harness_path(&self, project_root: &str, spec_id: &str) -> PathBuf {
        self.dir.join(format!(
            "harness_{}_{}.json",
            Self::project_hash(project_root),
            Self::id_hash(spec_id)
        ))
    }

    pub fn load_spec(&self, project_root: &str, pair_id: &str) -> Option<AuditSpec> {
        let raw = std::fs::read_to_string(self.spec_path(project_root, pair_id)).ok()?;
        let parsed: CachedSpec = serde_json::from_str(&raw).ok()?;
        if parsed.project_root == project_root && parsed.pair_id == pair_id {
            Some(parsed.spec)
        } else {
            None
        }
    }

    pub fn store_spec(
        &self,
        project_root: &str,
        pair_id: &str,
        spec: &AuditSpec,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let cached = CachedSpec {
            project_root: project_root.to_string(),
            pair_id: pair_id.to_string(),
            spec: spec.clone(),
            timestamp_ms: now_ms(),
        };
        std::fs::write(
            self.spec_path(project_root, pair_id),
            serde_json::to_string_pretty(&cached).unwrap(),
        )
    }

    pub fn load_harness(&self, project_root: &str, spec_id: &str) -> Option<FuzzHarness> {
        let raw = std::fs::read_to_string(self.harness_path(project_root, spec_id)).ok()?;
        let parsed: CachedHarness = serde_json::from_str(&raw).ok()?;
        if parsed.project_root == project_root && parsed.spec_id == spec_id {
            Some(parsed.harness)
        } else {
            None
        }
    }

    pub fn store_harness(
        &self,
        project_root: &str,
        spec_id: &str,
        harness: &FuzzHarness,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let cached = CachedHarness {
            project_root: project_root.to_string(),
            spec_id: spec_id.to_string(),
            harness: harness.clone(),
            timestamp_ms: now_ms(),
        };
        std::fs::write(
            self.harness_path(project_root, spec_id),
            serde_json::to_string_pretty(&cached).unwrap(),
        )
    }

    /// Invalidate cached spec for a pair (used when reflector flags it as Problematic).
    pub fn invalidate_spec(&self, project_root: &str, pair_id: &str) {
        let _ = std::fs::remove_file(self.spec_path(project_root, pair_id));
    }

    /// Invalidate cached harness for a spec (used when fuzz reports HarnessFailure).
    pub fn invalidate_harness(&self, project_root: &str, spec_id: &str) {
        let _ = std::fs::remove_file(self.harness_path(project_root, spec_id));
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sem(name: &str) -> DefiSemantic {
        DefiSemantic {
            name: name.to_string(),
            description: String::new(),
            category: String::new(),
            contracts: Vec::new(),
        }
    }

    fn api_sem(name: &str) -> ApiSemantic {
        ApiSemantic {
            name: name.to_string(),
            category: "Cat".to_string(),
        }
    }

    #[test]
    fn kg_vocab_cache_round_trip() {
        let dir = TempDir::new().unwrap();
        let cache = KgVocabCache::new(dir.path());
        let bts = vec![BusinessType::Lending, BusinessType::Dexes];
        let vocab = vec![api_sem("share accounting"), api_sem("oracle dependency")];
        cache.store(&bts, &vocab).unwrap();
        let loaded = cache.load(&bts).expect("hit");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "share accounting");
    }

    #[test]
    fn kg_vocab_cache_ttl_expiry() {
        let dir = TempDir::new().unwrap();
        let cache = KgVocabCache::new(dir.path()).with_ttl(0); // immediate expiry
        let bts = vec![BusinessType::Lending];
        cache.store(&bts, &[api_sem("x")]).unwrap();
        // Force timestamp into the past by rewriting the file
        let key = KgVocabCache::key_for(&bts);
        let path = dir.path().join(format!("{}.json", key));
        let mut cached: CachedKgVocab =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        cached.timestamp_ms = 0;
        std::fs::write(&path, serde_json::to_string_pretty(&cached).unwrap()).unwrap();
        assert!(cache.load(&bts).is_none(), "expired entry must miss");
    }

    #[test]
    fn kg_vocab_cache_key_is_order_independent() {
        let a = KgVocabCache::key_for(&[BusinessType::Lending, BusinessType::Dexes]);
        let b = KgVocabCache::key_for(&[BusinessType::Dexes, BusinessType::Lending]);
        assert_eq!(a, b);
    }

    #[test]
    fn vocab_match_cache_round_trip() {
        let dir = TempDir::new().unwrap();
        let cache = VocabMatchCache::new(dir.path());
        let extracted = vec![sem("share accounting"), sem("oracle dependency")];
        let vocab = vec![api_sem("Share Accounting"), api_sem("Oracle Dependency")];
        let matches = vec![
            ("share accounting".to_string(), "Share Accounting".to_string()),
            ("oracle dependency".to_string(), "Oracle Dependency".to_string()),
        ];
        cache.store(&extracted, &vocab, &matches).unwrap();
        let loaded = cache.load(&extracted, &vocab).unwrap();
        assert_eq!(loaded, matches);
    }

    #[test]
    fn vocab_match_cache_misses_with_different_extracted() {
        let dir = TempDir::new().unwrap();
        let cache = VocabMatchCache::new(dir.path());
        let v1 = vec![sem("a")];
        let v2 = vec![sem("b")];
        let kg = vec![api_sem("x")];
        cache
            .store(&v1, &kg, &[("a".to_string(), "x".to_string())])
            .unwrap();
        assert!(cache.load(&v1, &kg).is_some());
        assert!(cache.load(&v2, &kg).is_none());
    }

    #[test]
    fn pair_artifact_cache_spec_round_trip() {
        let dir = TempDir::new().unwrap();
        let cache = PairArtifactCache::new(dir.path());
        let spec = AuditSpec {
            pair_id: "pid".into(),
            target_contracts: vec!["Vault".into()],
            target_function: None,
            dependencies: vec![],
            initial_state: vec![],
            pre_vuln_state: vec![],
            post_vuln_state: vec![],
            attack_scenario: "attack".into(),
        };
        cache.store_spec("/proj", "pid", &spec).unwrap();
        let loaded = cache.load_spec("/proj", "pid").unwrap();
        assert_eq!(loaded.pair_id, "pid");
        assert_eq!(loaded.target_contracts, vec!["Vault"]);

        // Different project root → miss
        assert!(cache.load_spec("/other", "pid").is_none());
        // Different pair id → miss
        assert!(cache.load_spec("/proj", "other").is_none());

        cache.invalidate_spec("/proj", "pid");
        assert!(cache.load_spec("/proj", "pid").is_none());
    }

    #[test]
    fn pair_artifact_cache_harness_round_trip() {
        let dir = TempDir::new().unwrap();
        let cache = PairArtifactCache::new(dir.path());
        let h = FuzzHarness {
            spec_id: "sid".into(),
            source: "// solidity".into(),
            file_path: "test/Foo.t.sol".into(),
            test_name: "test_x".into(),
        };
        cache.store_harness("/proj", "sid", &h).unwrap();
        let loaded = cache.load_harness("/proj", "sid").unwrap();
        assert_eq!(loaded.test_name, "test_x");
    }
}
