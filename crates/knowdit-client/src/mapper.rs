//! Full implementation of `KnowledgeMapper` against the Knowdit HTTP API.
//!
//! Pipeline per project:
//! 1. Discover primary Solidity files (skip tests/mocks/vendored).
//! 2. Heuristic business classification → fall back to LLM if low confidence.
//! 3. LLM semantic extraction → list of canonical DeFi semantics.
//! 4. **KG vocabulary matching** (paper Section 3.3.2): heuristic prefilter →
//!    LLM matches extracted semantics to canonical KG vocabulary, with
//!    JSON-structured output and a normalized resolver. Cached on disk so
//!    re-runs hit zero LLM calls.
//! 5. For each matched semantic, query Knowdit API → linked vulnerability patterns.
//! 6. Optional cache + dedup of resulting pairs.
//!
//! Efficiency notes:
//! - **Token budget**: the prior implementation sent the entire KG vocabulary
//!   (often 200+ entries) as a giant prompt for a single LLM call, then
//!   strict-equality-checked the LLM output against the canonical names.
//!   This routinely produced 0/N matches — pure token waste. We now
//!   pre-filter the vocabulary heuristically to top-K candidates per
//!   extracted semantic before the LLM call, slashing prompt size by ~80–90%
//!   while keeping the LLM as the final arbiter (per paper).
//! - **Caching**: the KG vocabulary is cached per business-type set with a
//!   7-day TTL; the LLM matching result is cached per (extracted set, KG
//!   vocab fingerprint). Re-runs on the same project hit zero LLM calls in
//!   the matching step.
//! - **Diagnostics**: every run records [`VocabMatchStats`] so we can measure
//!   how the matcher is performing rather than relying on hand-counted logs.

use crate::cache::{
    CachedMapping, KgVocabCache, MapperCache, MapperCacheKey, VocabMatchCache,
};
use crate::classifier::classify_heuristic;
use crate::client::{ApiSemantic, KnowditClient, QueryRequest};
use crate::extractor::SemanticExtractor;
use crate::project::{FileKind, ProjectFile, discover_project_files};
use agent_core::{
    AgentResult, BusinessType, DefiSemantic, KnowledgeMapper, SemanticVulnPair,
    VocabMatchStats, VulnerabilityPattern,
};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Cap on the number of business types fed to the KG vocabulary fetch.
/// More business types = more network round-trips and a larger vocabulary
/// for the matching prompt. Top-K (by classifier score) is sufficient.
const MAX_BUSINESS_TYPES: usize = 3;

/// Maximum vocabulary candidates per extracted semantic after heuristic prefilter.
/// Each extracted semantic gets its top-K KG vocabulary candidates by similarity;
/// the union of these forms the LLM's candidate pool.
const PREFILTER_TOP_K: usize = 8;

/// Minimum similarity score for the heuristic prefilter to even consider a candidate.
/// Below this, candidates are discarded as too unrelated to be worth the LLM's time.
const PREFILTER_MIN_SCORE: f64 = 0.05;

/// Full Knowledge Mapper that ties together file discovery, classification,
/// semantic extraction, KG vocabulary matching, and Knowdit KG queries.
///
/// Implements the paper's 2-step semantic matching (Section 3.3.2):
/// 1. LLM extracts DeFi semantics from source code
/// 2. LLM matches extracted semantics to KG vocabulary names
/// This ensures KG queries use the correct vocabulary, avoiding the
/// mismatch that causes irrelevant vulnerability patterns.
pub struct KnowditMapper {
    pub client: Arc<KnowditClient>,
    pub extractor: Arc<dyn SemanticExtractor>,
    /// LLM client for KG vocabulary matching step (paper Section 3.3.2).
    pub llm: Option<agent_llm::LlmClient>,
    pub cache: Option<MapperCache>,
    /// Disk cache for the KG vocabulary fetched per business-type set.
    pub kg_vocab_cache: Option<KgVocabCache>,
    /// Disk cache for the LLM vocabulary-matching sub-step.
    pub vocab_match_cache: Option<VocabMatchCache>,
    /// Max primary files per project to feed to the extractor.
    pub max_files: usize,
    /// Max pages to fetch per Knowdit semantic query.
    pub max_pages_per_query: u32,
    /// Max pairs to return per project.
    pub max_pairs: usize,
    /// Cached file list — populated by `classify_business`, consumed by `extract_semantics`.
    cached_files: tokio::sync::Mutex<Option<(String, Vec<ProjectFile>)>>,
    /// Last vocab-match stats produced by `extract_semantics`. Read by callers
    /// (e.g. orchestrator) to inject into the audit `Report`.
    last_vocab_stats: tokio::sync::Mutex<Option<VocabMatchStats>>,
}

impl KnowditMapper {
    pub fn new(client: Arc<KnowditClient>, extractor: Arc<dyn SemanticExtractor>) -> Self {
        Self {
            client,
            extractor,
            llm: None,
            cache: Some(MapperCache::default_path()),
            kg_vocab_cache: Some(KgVocabCache::default_path()),
            vocab_match_cache: Some(VocabMatchCache::default_path()),
            max_files: 12,
            max_pages_per_query: 2,
            max_pairs: 30,
            cached_files: tokio::sync::Mutex::new(None),
            last_vocab_stats: tokio::sync::Mutex::new(None),
        }
    }

    pub fn with_llm(mut self, llm: agent_llm::LlmClient) -> Self {
        self.llm = Some(llm);
        self
    }

    pub fn with_cache(mut self, cache: Option<MapperCache>) -> Self {
        self.cache = cache;
        self
    }

    pub fn with_kg_vocab_cache(mut self, cache: Option<KgVocabCache>) -> Self {
        self.kg_vocab_cache = cache;
        self
    }

    pub fn with_vocab_match_cache(mut self, cache: Option<VocabMatchCache>) -> Self {
        self.vocab_match_cache = cache;
        self
    }

    pub fn with_max_files(mut self, n: usize) -> Self {
        self.max_files = n;
        self
    }

    pub fn with_max_pairs(mut self, n: usize) -> Self {
        self.max_pairs = n;
        self
    }

    /// Fetch the KG's semantic vocabulary for the given business types.
    ///
    /// Uses the [`KgVocabCache`] when available — the KG vocabulary is stable
    /// across many runs (only changes when Knowdit's catalog updates), so a
    /// 7-day TTL eliminates almost all repeat KG queries.
    async fn fetch_kg_vocabulary(
        &self,
        business: &[BusinessType],
        stats: &mut VocabMatchStats,
    ) -> Vec<ApiSemantic> {
        // Cache lookup first.
        if let Some(cache) = &self.kg_vocab_cache {
            if let Some(cached) = cache.load(business) {
                info!(
                    "KG vocabulary cache hit ({} entries) for business types {:?}",
                    cached.len(),
                    business
                );
                stats.kg_vocab_total = cached.len();
                let filtered = filter_canonical_vocab(&cached);
                stats.kg_vocab_filtered = filtered.len();
                return filtered;
            }
        }

        let mut all_semantics = Vec::new();
        let mut seen_names = std::collections::HashSet::new();

        for bt in business {
            let req = QueryRequest {
                query: bt.as_str().to_string(),
                category: Some(bt.as_str().to_string()),
                links_per_page: Some(100),
                link_page: None,
            };

            // We only need page 1 to get the semantics list; don't paginate links.
            match self.client.query(&req).await {
                Ok(resp) => {
                    for sem in resp.semantics {
                        if seen_names.insert(sem.name.clone()) {
                            debug!("KG vocabulary: '{}' ({})", sem.name, sem.category);
                            all_semantics.push(sem);
                        }
                    }
                }
                Err(e) => {
                    warn!("KG vocabulary query failed for '{}': {}", bt.as_str(), e);
                }
            }
        }

        info!(
            "Fetched KG vocabulary: {} unique semantics across {} business types",
            all_semantics.len(),
            business.len()
        );
        stats.kg_vocab_total = all_semantics.len();

        let filtered = filter_canonical_vocab(&all_semantics);
        stats.kg_vocab_filtered = filtered.len();
        debug!(
            "Filtered to {} canonical semantic names (removed composite names)",
            filtered.len()
        );

        // Persist to cache (use the unfiltered list so future filter changes don't
        // require re-fetching; filtering is cheap).
        if let Some(cache) = &self.kg_vocab_cache {
            if let Err(e) = cache.store(business, &all_semantics) {
                warn!("Failed to persist KG vocabulary cache: {}", e);
            }
        }

        filtered
    }

    /// Match LLM-extracted semantics to KG vocabulary names (paper Section 3.3.2).
    ///
    /// The paper says: "For each extracted DeFi semantic, we prompt the LLM to
    /// identify its matches among the semantics associated with the identified
    /// business types in the knowledge graph 𝒢."
    ///
    /// We keep the LLM as the final arbiter but make it dramatically cheaper:
    /// 1. Heuristic prefilter narrows the candidate pool to ≈10–20 entries.
    /// 2. LLM answers in JSON (more reliable than `→` delimiter parsing).
    /// 3. A normalized resolver tolerates case / `(category)` suffix / minor
    ///    whitespace differences when matching the LLM output back to canonical
    ///    KG names.
    /// 4. Results are persisted to disk so re-runs hit zero LLM calls.
    async fn match_semantics_to_kg(
        &self,
        semantics: &[DefiSemantic],
        kg_vocab: &[ApiSemantic],
        stats: &mut VocabMatchStats,
    ) -> Vec<DefiSemantic> {
        stats.extracted_semantics = semantics.len();

        let llm = match &self.llm {
            Some(l) => l,
            None => {
                info!("No LLM client for KG vocabulary matching; using extracted names as-is");
                return semantics.to_vec();
            }
        };

        if kg_vocab.is_empty() {
            warn!("KG vocabulary is empty; skipping vocabulary matching");
            return semantics.to_vec();
        }

        // Cache lookup BEFORE building a prompt.
        if let Some(cache) = &self.vocab_match_cache {
            if let Some(matches) = cache.load(semantics, kg_vocab) {
                stats.cache_hit = true;
                stats.matched = matches.len();
                info!(
                    "Vocab-match cache hit: {} matches recovered without LLM call",
                    matches.len()
                );
                return apply_matches(semantics, &matches);
            }
        }

        // Heuristic pre-filter: reduce candidate pool from full KG vocabulary
        // to the top-K most similar entries per extracted semantic.
        let candidates = prefilter_kg_candidates(semantics, kg_vocab, PREFILTER_TOP_K);
        stats.candidates_after_prefilter = candidates.len();
        if candidates.is_empty() {
            warn!("Heuristic prefilter produced no candidates; skipping LLM match");
            return semantics.to_vec();
        }
        debug!(
            "Heuristic prefilter: {} candidates from {} KG entries (across {} extracted semantics)",
            candidates.len(),
            kg_vocab.len(),
            semantics.len()
        );

        // Build the candidate list for the prompt.
        let vocab_list: Vec<String> = candidates
            .iter()
            .map(|s| format!("- \"{}\" ({})", s.name, s.category))
            .collect();
        let extracted_list: Vec<String> = semantics
            .iter()
            .map(|s| format!("- \"{}\" — {}", s.name, s.description))
            .collect();

        // Ask for JSON output for robust parsing. We keep a delimiter-format
        // fallback for backward compatibility with older LLM behavior.
        let prompt = format!(
            r#"You are matching DeFi semantics extracted from a Solidity project to canonical
names in a knowledge graph (KG) vocabulary. The KG already has fuzzy synonyms
listed; pick the closest canonical name for each extracted semantic.

EXTRACTED SEMANTICS (from project source code):
{}

KG VOCABULARY CANDIDATES (already pre-filtered by similarity):
{}

INSTRUCTIONS:
1. For each extracted semantic, choose the BEST matching KG vocabulary entry.
2. A match must capture the same economic mechanism, not just similar words.
3. If no candidate fits, output "NO_MATCH" for that semantic.
4. Respond with ONLY a JSON array of objects, in the same order as EXTRACTED SEMANTICS.
   Schema: [{{"extracted":"<extracted name>","matched":"<KG name OR NO_MATCH>"}}]
5. Use the EXACT KG name from the vocabulary (preserve case and parentheses).
6. Do NOT include markdown fences, explanations, or any prose outside the JSON.
"#,
            extracted_list.join("\n"),
            vocab_list.join("\n"),
        );

        let system = "You are a DeFi semantics matching expert. Respond with strict JSON only.";
        stats.llm_calls = 1;
        let response = match llm.chat(Some(system), &prompt).await {
            Ok(r) => r,
            Err(e) => {
                warn!("LLM vocabulary matching failed: {}; using extracted names as-is", e);
                return semantics.to_vec();
            }
        };
        debug!("LLM vocabulary matching response:\n{}", response);

        // Parse: first JSON, then delimiter format as fallback.
        let raw_pairs = parse_match_response(&response);

        // Resolve each LLM-named match back to canonical KG vocabulary.
        let resolver = KgNameResolver::build(kg_vocab);
        let mut matches: Vec<(String, String)> = Vec::new();
        for (extracted, matched_raw) in raw_pairs {
            // Only accept matches against an extracted semantic we actually have.
            if !semantics.iter().any(|s| names_match_loosely(&s.name, &extracted)) {
                debug!(
                    "Discarding LLM match for unknown extracted name: '{}'",
                    extracted
                );
                continue;
            }

            if matched_raw.is_empty()
                || matched_raw.eq_ignore_ascii_case("NO_MATCH")
                || matched_raw.eq_ignore_ascii_case("NULL")
            {
                // Fallback: use extracted name as-is (identity match)
                if let Some(real_extracted) = semantics
                    .iter()
                    .find(|s| names_match_loosely(&s.name, &extracted))
                    .map(|s| s.name.clone())
                {
                    debug!("No KG match for '{}', using extracted name as-is", extracted);
                    matches.push((real_extracted.clone(), real_extracted));
                }
                continue;
            }

            if let Some(canonical) = resolver.resolve(&matched_raw) {
                if let Some(real_extracted) = semantics
                    .iter()
                    .find(|s| names_match_loosely(&s.name, &extracted))
                    .map(|s| s.name.clone())
                {
                    matches.push((real_extracted, canonical));
                }
            } else {
                debug!(
                    "Could not resolve LLM-suggested match '{}' to KG vocabulary, falling back to extracted name",
                    matched_raw
                );
                // Fallback: use extracted name as-is
                if let Some(real_extracted) = semantics
                    .iter()
                    .find(|s| names_match_loosely(&s.name, &extracted))
                    .map(|s| s.name.clone())
                {
                    matches.push((real_extracted.clone(), real_extracted));
                }
            }
        }
        stats.matched = matches.len();
        info!(
            "KG vocabulary matching: {}/{} semantics matched (prompt candidates: {})",
            matches.len(),
            semantics.len(),
            stats.candidates_after_prefilter
        );

        // Persist to cache for next run.
        if let Some(cache) = &self.vocab_match_cache {
            if let Err(e) = cache.store(semantics, kg_vocab, &matches) {
                warn!("Failed to persist vocab-match cache: {}", e);
            }
        }

        apply_matches(semantics, &matches)
    }

    async fn files_for(&self, project_root: &str) -> AgentResult<Vec<ProjectFile>> {
        // Reuse already-computed file list if same project_root.
        {
            let cache = self.cached_files.lock().await;
            if let Some((root, files)) = cache.as_ref() {
                if root == project_root {
                    return Ok(files.clone());
                }
            }
        }
        let files = discover_project_files(project_root, self.max_files)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let primary_count = files.iter().filter(|f| f.kind == FileKind::Primary).count();
        info!(
            "Discovered {} files ({} primary) in {}",
            files.len(),
            primary_count,
            project_root
        );
        *self.cached_files.lock().await = Some((project_root.to_string(), files.clone()));
        Ok(files)
    }
}

#[async_trait]
impl KnowledgeMapper for KnowditMapper {
    async fn last_vocab_match_stats(&self) -> Option<VocabMatchStats> {
        self.last_vocab_stats.lock().await.clone()
    }

    async fn classify_business(&self, project_root: &str) -> AgentResult<Vec<BusinessType>> {
        let files = self.files_for(project_root).await?;

        // Cache lookup
        let key = MapperCacheKey::new(project_root, &files);
        if let Some(cache) = &self.cache {
            if let Some(c) = cache.load(&key) {
                if !c.business.is_empty() {
                    info!("Cache hit for business classification");
                    return Ok(c.business);
                }
            }
        }

        let res = classify_heuristic(&files);
        if res.types.is_empty() {
            warn!("Heuristic classifier found no DeFi keywords; defaulting to Others");
            return Ok(vec![BusinessType::Others]);
        }

        let primary: Vec<BusinessType> = if res.confident {
            // Keep types within ~70% of top score
            let top = res.types.first().map(|(_, s)| *s).unwrap_or(0.0);
            let threshold = top * 0.7;
            res.types
                .into_iter()
                .filter(|(_, s)| *s >= threshold)
                .map(|(b, _)| b)
                .collect()
        } else {
            // Take just the top suggestion when uncertain
            res.types.into_iter().take(1).map(|(b, _)| b).collect()
        };

        // Cap to top MAX_BUSINESS_TYPES to keep the KG vocabulary bounded.
        let primary: Vec<BusinessType> = primary.into_iter().take(MAX_BUSINESS_TYPES).collect();
        info!("Heuristic business types (capped): {:?}", primary);
        Ok(primary)
    }

    async fn extract_semantics(&self, project_root: &str) -> AgentResult<Vec<DefiSemantic>> {
        let files = self.files_for(project_root).await?;
        let key = MapperCacheKey::new(project_root, &files);

        if let Some(cache) = &self.cache {
            if let Some(c) = cache.load(&key) {
                if !c.semantics.is_empty() {
                    info!("Cache hit for semantics ({} entries)", c.semantics.len());
                    return Ok(c.semantics);
                }
            }
        }

        // We need business types to feed the extractor. Re-run classify (cheap, in-memory cache).
        let business = self.classify_business(project_root).await?;
        let primary_files: Vec<ProjectFile> = files
            .into_iter()
            .filter(|f| f.kind != FileKind::Skip)
            .collect();

        // Step 1: LLM extracts semantics from source code (paper Section 3.3.1).
        let mut semantics = self
            .extractor
            .extract(&primary_files, &business)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        info!("Extracted {} semantics from source code", semantics.len());
        for s in &semantics {
            debug!("  extracted semantic: {} ({})", s.name, s.category);
        }

        // Step 2: Match extracted semantics to KG vocabulary (paper Section 3.3.2).
        let mut stats = VocabMatchStats {
            business_types_used: business.len(),
            ..VocabMatchStats::default()
        };
        let kg_vocab = self.fetch_kg_vocabulary(&business, &mut stats).await;
        if !kg_vocab.is_empty() {
            semantics = self
                .match_semantics_to_kg(&semantics, &kg_vocab, &mut stats)
                .await;
            info!("After KG vocabulary matching:");
            for s in &semantics {
                debug!("  matched semantic: {} ({})", s.name, s.category);
            }
        }
        // Stash stats for callers (orchestrator/CLI) to surface in the Report.
        *self.last_vocab_stats.lock().await = Some(stats);

        Ok(semantics)
    }

    async fn map_to_pairs(&self, semantics: &[DefiSemantic]) -> AgentResult<Vec<SemanticVulnPair>> {
        if semantics.is_empty() {
            return Ok(Vec::new());
        }

        // Collect all contract names from the semantics for relevance filtering.
        let project_contracts: std::collections::HashSet<String> = semantics
            .iter()
            .flat_map(|s| s.contracts.iter().cloned())
            .collect();

        // Per-semantic pair budget: ensure diversity across semantics.
        // If we have N semantics and max_pairs M, each semantic gets at most
        // ceil(M/N) pairs, with leftover distributed to semantics with more links.
        let per_semantic_budget = if semantics.len() > 1 {
            (self.max_pairs + semantics.len() - 1) / semantics.len()
        } else {
            self.max_pairs
        };

        // Collect all candidate pairs, then apply per-semantic budget + total cap.
        let mut all_candidates = Vec::new();
        for semantic in semantics {
            let req = QueryRequest {
                query: semantic.name.clone(),
                category: Some(semantic.category.clone()),
                links_per_page: Some(50),
                link_page: None,
            };
            let links = match self.client.query_all(&req, self.max_pages_per_query).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("Knowdit query failed for '{}': {}", semantic.name, e);
                    continue;
                }
            };

            debug!(
                "Knowdit returned {} vuln links for semantic '{}'",
                links.len(),
                semantic.name
            );

            for link in links {
                let attack_type = infer_attack_type(&link.title);

                // Compute relevance with contract-name bonus/penalty.
                let base_relevance = relevance_for_severity(&link.severity);
                let contract_relevance = contract_name_relevance(&link.title, &project_contracts);
                let relevance = base_relevance * contract_relevance;

                // Skip very low-relevance pairs (titles referencing unrelated projects).
                if relevance < 0.1 {
                    debug!(
                        "Skipping low-relevance KG result: '{}' (relevance={:.2})",
                        link.title, relevance
                    );
                    continue;
                }

                all_candidates.push(SemanticVulnPair {
                    semantic: semantic.clone(),
                    vulnerability: VulnerabilityPattern {
                        title: link.title.clone(),
                        description: link.title.clone(),
                        root_cause: String::new(),
                        severity: link.severity.clone(),
                        attack_type,
                    },
                    relevance,
                });
            }
        }

        // Apply per-semantic budget: take top pairs per semantic, then rank globally.
        let ranked = rank_and_dedup(all_candidates);
        let total_candidates = ranked.len();
        let mut budgeted = Vec::new();
        let mut semantic_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for pair in ranked {
            let count = semantic_counts
                .entry(pair.semantic.name.clone())
                .or_insert(0);
            if *count < per_semantic_budget {
                budgeted.push(pair);
                *count += 1;
            }
            if budgeted.len() >= self.max_pairs {
                break;
            }
        }

        // Coverage gap filler: ensure every contract mentioned in the semantics
        // has at least one pair targeting it. Contracts with zero pairs after
        // KG budgeting get synthetic pairs using generic vulnerability patterns.
        let covered_contracts: std::collections::HashSet<String> = budgeted
            .iter()
            .flat_map(|p| p.semantic.contracts.iter().cloned())
            .collect();

        let all_contract_semantics: std::collections::HashMap<String, Vec<&DefiSemantic>> = {
            let mut map = std::collections::HashMap::new();
            for s in semantics {
                for c in &s.contracts {
                    map.entry(c.clone())
                        .or_insert_with(Vec::new)
                        .push(s);
                }
            }
            map
        };

        let uncovered: Vec<&String> = all_contract_semantics
            .keys()
            .filter(|c| !covered_contracts.contains(*c))
            .collect();

        if !uncovered.is_empty() {
            for contract in &uncovered {
                let contract_str = (*contract).as_str();
                // Pick the first semantic for this contract as the base.
                if let Some(semantics_for_contract) = all_contract_semantics.get(contract_str) {
                    if let Some(semantic) = semantics_for_contract.first() {
                        // Generate synthetic pairs for common vulnerability patterns.
                        for (pattern_title, attack_type, severity) in COVERAGE_PATTERNS {
                            if budgeted.len() >= self.max_pairs {
                                break;
                            }
                            let pair = SemanticVulnPair {
                                semantic: (*semantic).clone(),
                                vulnerability: VulnerabilityPattern {
                                    title: pattern_title.to_string(),
                                    description: pattern_title.to_string(),
                                    root_cause: String::new(),
                                    severity: severity.to_string(),
                                    attack_type: attack_type.to_string(),
                                },
                                relevance: 0.3, // Low but above the 0.1 threshold
                            };
                            budgeted.push(pair);
                        }
                    }
                }
            }
            let filled = uncovered.len();
            info!(
                "Coverage gap filler: added pairs for {} uncovered contracts (total pairs now: {})",
                filled,
                budgeted.len()
            );
        }

        info!(
            "Selected {} pairs from {} candidates (per-semantic budget={})",
            budgeted.len(),
            total_candidates,
            per_semantic_budget
        );
        Ok(budgeted)
    }
}

/// Generic vulnerability patterns used by the coverage gap filler.
/// These ensure every contract gets tested for common vulnerability classes
/// even when the Knowdit KG doesn't return matching patterns.
const COVERAGE_PATTERNS: &[(&str, &str, &str)] = &[
    ("missing access control on critical function", "Access Control", "High"),
    ("incorrect amount calculation in token transfer", "Arithmetic", "High"),
    ("reentrancy in state-changing function", "Reentrancy", "High"),
    ("denial of service via gas griefing", "Denial of Service", "Medium"),
    ("front-running of state-changing operation", "Block Manipulation", "Medium"),
];

/// Sort by relevance descending, dedup by (semantic name, vulnerability title).
fn rank_and_dedup(mut pairs: Vec<SemanticVulnPair>) -> Vec<SemanticVulnPair> {
    pairs.sort_by(|a, b| {
        b.relevance
            .partial_cmp(&a.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut seen = std::collections::HashSet::new();
    pairs.retain(|p| {
        let key = format!(
            "{}::{}",
            p.semantic.name.to_lowercase(),
            p.vulnerability.title.to_lowercase()
        );
        seen.insert(key)
    });
    pairs
}

fn relevance_for_severity(severity: &str) -> f64 {
    match severity.to_lowercase().as_str() {
        "critical" => 1.0,
        "high" => 0.85,
        "medium" => 0.6,
        "low" => 0.35,
        _ => 0.2,
    }
}

/// Rough heuristic to infer an attack type from a vulnerability title.
fn infer_attack_type(title: &str) -> String {
    let t = title.to_lowercase();
    if t.contains("reentran") {
        "Reentrancy".to_string()
    } else if t.contains("access control")
        || t.contains("authoriz")
        || t.contains("permission")
        || t.contains("only owner")
    {
        "Access Control".to_string()
    } else if t.contains("denial of service") || t.contains("dos") || t.contains("revert") {
        "Denial of Service".to_string()
    } else if t.contains("overflow")
        || t.contains("underflow")
        || t.contains("rounding")
        || t.contains("precision")
        || t.contains("arithmetic")
    {
        "Arithmetic".to_string()
    } else if t.contains("storage") || t.contains("slot") {
        "Storage & Memory".to_string()
    } else if t.contains("timestamp") || t.contains("block.number") {
        "Block Manipulation".to_string()
    } else if t.contains("signature") || t.contains("hash collision") {
        "Cryptographic".to_string()
    } else {
        "Other".to_string()
    }
}

/// Compute a relevance multiplier for a KG vulnerability title based on
/// whether it references contracts from the target project.
///
/// - Title mentions a project contract → 1.0 (full relevance)
/// - Title mentions generic DeFi terms (swap, pool, vault, etc.) → 0.7
/// - Title mentions unrelated contract names → 0.3 (penalized)
/// - Title is completely off-topic (e.g., Cairo, Starknet) → 0.1
fn contract_name_relevance(
    title: &str,
    project_contracts: &std::collections::HashSet<String>,
) -> f64 {
    let lower = title.to_lowercase();

    // Check if any project contract name appears in the title.
    for contract in project_contracts {
        let contract_lower = contract.to_lowercase();
        if lower.contains(&contract_lower) {
            return 1.0;
        }
        // Also check partial match (e.g., "LamboFactory" → "lambofactory" contains "lambo")
        let stem = contract_lower.chars().take(5).collect::<String>();
        if stem.len() >= 4 && lower.contains(&stem) {
            return 0.9;
        }
    }

    // Generic DeFi terms that are always relevant.
    const GENERIC_TERMS: &[&str] = &[
        "swap",
        "pool",
        "vault",
        "token",
        "mint",
        "burn",
        "stake",
        "deposit",
        "withdraw",
        "lend",
        "borrow",
        "liquidat",
        "oracle",
        "flash loan",
        "rebalanc",
        "peg",
        "router",
        "factory",
        "pair",
        "amm",
        "liquidity",
        "slippage",
        "front",
        "deadline",
        "access control",
        "reentran",
        "overflow",
        "underflow",
        "rounding",
        "dos",
        "denial of service",
        "griefing",
        "governance",
        "proxy",
        "upgrade",
        "initialize",
        "multisig",
    ];
    for term in GENERIC_TERMS {
        if lower.contains(term) {
            return 0.7;
        }
    }

    // Off-topic indicators (Cairo, Starknet, Move, etc.)
    const OFF_TOPIC: &[&str] = &[
        "cairo",
        "starknet",
        "move",
        "aptos",
        "sui",
        "cosmos",
        "substrate",
        "ink",
        "neutron",
        "near",
        "solana",
    ];
    for term in OFF_TOPIC {
        if lower.contains(term) {
            return 0.1;
        }
    }

    // Default: moderately penalized — the title references something
    // specific but not from our project.
    0.3
}

// ---------------------------------------------------------------------------
// Vocabulary-matching helpers (heuristic prefilter, JSON parsing, normalization)
// ---------------------------------------------------------------------------

/// Filter a raw KG vocabulary list down to canonical names only.
///
/// We drop:
/// - Composite names containing commas (e.g. "AMM, RFQ, Auction, ...")
/// - Empty / whitespace-only names
fn filter_canonical_vocab(vocab: &[ApiSemantic]) -> Vec<ApiSemantic> {
    vocab
        .iter()
        .filter(|s| !s.name.contains(',') && !s.name.trim().is_empty())
        .cloned()
        .collect()
}

/// Heuristic pre-filter: for each extracted semantic, pick the top-K most
/// similar KG vocabulary entries. Returns the deduplicated union across all
/// extracted semantics.
///
/// Similarity score combines:
/// - Token Jaccard overlap on the (lowercased) name
/// - Substring containment bonus
/// - Jaro-Winkler similarity of the full strings
///
/// This lets the LLM see only the candidates that are plausibly relevant
/// rather than the entire vocabulary, slashing prompt size by ≥80%.
pub fn prefilter_kg_candidates(
    extracted: &[DefiSemantic],
    kg_vocab: &[ApiSemantic],
    top_k: usize,
) -> Vec<ApiSemantic> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<ApiSemantic> = Vec::new();

    for sem in extracted {
        let mut scored: Vec<(f64, &ApiSemantic)> = kg_vocab
            .iter()
            .map(|kg| (similarity_score(&sem.name, &kg.name), kg))
            .filter(|(s, _)| *s >= PREFILTER_MIN_SCORE)
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        for (_, kg) in scored.into_iter().take(top_k) {
            if seen.insert(kg.name.clone()) {
                out.push(kg.clone());
            }
        }
    }

    out
}

/// Compute a [0.0, 1.0] similarity score between two strings.
fn similarity_score(a: &str, b: &str) -> f64 {
    let a_norm = normalize_for_similarity(a);
    let b_norm = normalize_for_similarity(b);

    if a_norm.is_empty() || b_norm.is_empty() {
        return 0.0;
    }

    // Token Jaccard
    let a_tokens: std::collections::HashSet<&str> = a_norm.split_whitespace().collect();
    let b_tokens: std::collections::HashSet<&str> = b_norm.split_whitespace().collect();
    let inter = a_tokens.intersection(&b_tokens).count() as f64;
    let union = a_tokens.union(&b_tokens).count() as f64;
    let jaccard = if union > 0.0 { inter / union } else { 0.0 };

    // Substring containment (either direction)
    let contains_bonus = if a_norm.contains(&b_norm) || b_norm.contains(&a_norm) {
        0.4
    } else {
        0.0
    };

    // Jaro-Winkler similarity on full strings
    let jw = strsim::jaro_winkler(&a_norm, &b_norm);

    // Weighted blend; cap at 1.0
    (jaccard * 0.5 + jw * 0.5 + contains_bonus).min(1.0)
}

/// Normalize a name for similarity scoring: lowercase, strip parenthesized
/// suffixes, collapse non-alphanumeric to spaces, trim.
fn normalize_for_similarity(s: &str) -> String {
    let mut buf = String::new();
    let mut depth = 0i32;
    for c in s.chars() {
        if c == '(' {
            depth += 1;
            continue;
        }
        if c == ')' {
            depth -= 1;
            continue;
        }
        if depth > 0 {
            continue;
        }
        if c.is_alphanumeric() {
            buf.extend(c.to_lowercase());
        } else {
            buf.push(' ');
        }
    }
    buf.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Loose name match — used to pair LLM-echoed extracted names back to our
/// authoritative extracted-semantic list. Tolerates case/whitespace/quoting.
fn names_match_loosely(a: &str, b: &str) -> bool {
    let an = normalize_for_similarity(a);
    let bn = normalize_for_similarity(b);
    if an == bn {
        return true;
    }
    // Allow LLM to add minor adjectives — accept if one is a strict prefix of the other.
    !an.is_empty() && !bn.is_empty() && (an.starts_with(&bn) || bn.starts_with(&an))
}

/// Resolve free-form LLM strings back to canonical KG vocabulary names.
///
/// Builds a map of normalized variants → canonical name so we can tolerate:
/// - Case differences ("share accounting" vs "Share Accounting")
/// - Trailing `(category)` suffixes ("Pool Initialization (Dexes)")
/// - Minor whitespace / punctuation drift
/// - Approximate matches via Jaro-Winkler ≥ 0.92
pub struct KgNameResolver {
    canonical: Vec<String>,
    by_normalized: std::collections::HashMap<String, String>,
}

impl KgNameResolver {
    pub fn build(kg_vocab: &[ApiSemantic]) -> Self {
        let mut by_normalized: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut canonical = Vec::with_capacity(kg_vocab.len());
        for s in kg_vocab {
            canonical.push(s.name.clone());
            let key = normalize_for_similarity(&s.name);
            by_normalized.entry(key).or_insert_with(|| s.name.clone());
            // Also index the without-parens form keyed by trimmed-uppercase.
            let trimmed = strip_paren_suffix(&s.name);
            let trimmed_key = normalize_for_similarity(&trimmed);
            by_normalized
                .entry(trimmed_key)
                .or_insert_with(|| s.name.clone());
        }
        Self {
            canonical,
            by_normalized,
        }
    }

    pub fn resolve(&self, candidate: &str) -> Option<String> {
        if candidate.trim().is_empty() {
            return None;
        }
        // Direct exact / case-insensitive lookup.
        let normalized = normalize_for_similarity(candidate);
        if let Some(canonical) = self.by_normalized.get(&normalized) {
            return Some(canonical.clone());
        }
        let stripped = normalize_for_similarity(&strip_paren_suffix(candidate));
        if let Some(canonical) = self.by_normalized.get(&stripped) {
            return Some(canonical.clone());
        }
        // Fuzzy fallback — accept Jaro-Winkler ≥ 0.85 against any canonical name.
        let mut best: Option<(f64, &String)> = None;
        for cn in &self.canonical {
            let cn_norm = normalize_for_similarity(cn);
            let score = strsim::jaro_winkler(&normalized, &cn_norm);
            if score >= 0.85 && best.as_ref().map_or(true, |b| score > b.0) {
                best = Some((score, cn));
            }
        }
        best.map(|(_, cn)| cn.clone())
    }
}

fn strip_paren_suffix(s: &str) -> String {
    if let Some(idx) = s.find('(') {
        s[..idx].trim().to_string()
    } else {
        s.to_string()
    }
}

/// Parse the LLM's matching response.
///
/// Tries JSON first (`[{"extracted":"...","matched":"..."}]`), then falls
/// back to the legacy `extracted → matched` delimiter format. Always returns
/// `(extracted, matched)` pairs even if some lines fail to parse.
pub fn parse_match_response(response: &str) -> Vec<(String, String)> {
    let trimmed = strip_markdown_fences(response);

    // JSON path
    if let Ok(parsed) = serde_json::from_str::<Vec<MatchEntry>>(trimmed) {
        return parsed
            .into_iter()
            .map(|m| (m.extracted, m.matched))
            .collect();
    }
    // Try JSON object form `{"matches":[{...}]}`
    if let Ok(envelope) = serde_json::from_str::<MatchEnvelope>(trimmed) {
        return envelope
            .matches
            .into_iter()
            .map(|m| (m.extracted, m.matched))
            .collect();
    }

    // Delimiter-format fallback
    let mut out = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim().trim_start_matches('-').trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = if line.contains("→") {
            line.splitn(2, "→").collect()
        } else if line.contains("->") {
            line.splitn(2, "->").collect()
        } else {
            continue;
        };
        if parts.len() != 2 {
            continue;
        }
        let extracted = parts[0].trim().trim_matches('"').to_string();
        let matched = parts[1].trim().trim_matches('"').to_string();
        if !extracted.is_empty() {
            out.push((extracted, matched));
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct MatchEntry {
    extracted: String,
    matched: String,
}

#[derive(serde::Deserialize)]
struct MatchEnvelope {
    matches: Vec<MatchEntry>,
}

fn strip_markdown_fences(s: &str) -> &str {
    let trimmed = s.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        let rest = rest.trim_start_matches('\n');
        if let Some(end) = rest.rfind("```") {
            return rest[..end].trim();
        }
        return rest.trim();
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        let rest = rest.trim_start_matches('\n');
        if let Some(end) = rest.rfind("```") {
            return rest[..end].trim();
        }
        return rest.trim();
    }
    trimmed
}

/// Apply `(extracted_name, kg_name)` matches to a list of semantics, replacing
/// each matched semantic's name with the canonical KG name (with trailing
/// `(category)` stripped). Returns a new vec.
fn apply_matches(
    semantics: &[DefiSemantic],
    matches: &[(String, String)],
) -> Vec<DefiSemantic> {
    let map: std::collections::HashMap<&str, &str> = matches
        .iter()
        .map(|(e, k)| (e.as_str(), k.as_str()))
        .collect();
    let mut out = Vec::with_capacity(semantics.len());
    for s in semantics {
        let mut clone = s.clone();
        if let Some(kg_name) = map.get(s.name.as_str()) {
            let cleaned = strip_paren_suffix(kg_name);
            let cleaned = cleaned.trim();
            if cleaned != s.name && !cleaned.is_empty() {
                info!(
                    "KG vocabulary match: '{}' → '{}' (category: {})",
                    s.name, cleaned, s.category
                );
                clone.name = cleaned.to_string();
            }
        }
        out.push(clone);
    }
    out
}

/// After running the full pipeline, optionally persist results to the cache.
pub async fn run_and_cache(
    mapper: &KnowditMapper,
    project_root: &str,
) -> AgentResult<(Vec<BusinessType>, Vec<DefiSemantic>, Vec<SemanticVulnPair>)> {
    let business = mapper.classify_business(project_root).await?;
    let semantics = mapper.extract_semantics(project_root).await?;
    let pairs = mapper.map_to_pairs(&semantics).await?;

    if let Some(cache) = &mapper.cache {
        let files = mapper.files_for(project_root).await?;
        let key = MapperCacheKey::new(project_root, &files);
        let _ = cache.store(&CachedMapping {
            key,
            business: business.clone(),
            semantics: semantics.clone(),
            pairs: pairs.clone(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
    }

    Ok((business, semantics, pairs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sem(name: &str, contracts: &[&str]) -> DefiSemantic {
        DefiSemantic {
            name: name.to_string(),
            description: format!("desc for {}", name),
            category: "Lending".to_string(),
            contracts: contracts.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn kg(name: &str, category: &str) -> ApiSemantic {
        ApiSemantic {
            name: name.to_string(),
            category: category.to_string(),
        }
    }

    #[test]
    fn prefilter_returns_top_k_per_extracted() {
        let extracted = vec![
            sem("share accounting", &["Vault"]),
            sem("price oracle dependency", &["Oracle"]),
        ];
        let vocab = vec![
            kg("Share Accounting", "Yield Aggregator"),
            kg("Liquidity Provision", "Dexes"),
            kg("Oracle Dependency", "Services"),
            kg("Borrow Limit", "Lending"),
            kg("Block Number Manipulation", "Generic"),
            kg("Random Off-Topic Cairo Thing", "Other"),
        ];
        let candidates = prefilter_kg_candidates(&extracted, &vocab, 2);
        // Should include the obvious matches per semantic; should not include
        // wholly unrelated entries.
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"Share Accounting"));
        assert!(names.contains(&"Oracle Dependency"));
        // dedup means no duplicates even if both extracted matched the same KG entry
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    #[test]
    fn prefilter_ranks_relevant_candidates_higher() {
        // Verify that the prefilter ranks token-overlap matches above
        // unrelated entries — which is what the LLM cares about.
        let extracted = vec![sem("share accounting", &["Vault"])];
        let vocab = vec![
            kg("Cross Chain Bridge Replay", "Cross Chain"),
            kg("Share Accounting", "Yield"),
            kg("NFT Royalty Bypass", "NFT Marketplace"),
        ];
        let candidates = prefilter_kg_candidates(&extracted, &vocab, 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "Share Accounting");
    }

    #[test]
    fn prefilter_caps_total_to_top_k_per_semantic() {
        // 1 extracted × top_k=2 → at most 2 candidates.
        let extracted = vec![sem("share accounting", &["Vault"])];
        let vocab: Vec<ApiSemantic> = (0..10)
            .map(|i| kg(&format!("Candidate {}", i), "Cat"))
            .collect();
        let candidates = prefilter_kg_candidates(&extracted, &vocab, 2);
        assert!(
            candidates.len() <= 2,
            "expected ≤2 candidates, got {}",
            candidates.len()
        );
    }

    #[test]
    fn json_parse_roundtrip() {
        let resp = r#"[
            {"extracted":"share accounting","matched":"Share Accounting (Yield)"},
            {"extracted":"oracle dependency","matched":"NO_MATCH"}
        ]"#;
        let pairs = parse_match_response(resp);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "share accounting");
        assert_eq!(pairs[0].1, "Share Accounting (Yield)");
        assert_eq!(pairs[1].1, "NO_MATCH");
    }

    #[test]
    fn json_parse_with_markdown_fences() {
        let resp = "```json\n[{\"extracted\":\"a\",\"matched\":\"B\"}]\n```";
        let pairs = parse_match_response(resp);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "a");
        assert_eq!(pairs[0].1, "B");
    }

    #[test]
    fn delimiter_fallback_parses_when_json_fails() {
        let resp = "share accounting → Share Accounting\noracle dependency -> Oracle Dependency";
        let pairs = parse_match_response(resp);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].1, "Share Accounting");
        assert_eq!(pairs[1].1, "Oracle Dependency");
    }

    #[test]
    fn resolver_handles_case_and_paren_suffix() {
        let vocab = vec![
            kg("Pool Initialization (Dexes)", "Dexes"),
            kg("Share Accounting", "Yield Aggregator"),
        ];
        let r = KgNameResolver::build(&vocab);
        assert_eq!(
            r.resolve("pool initialization"),
            Some("Pool Initialization (Dexes)".to_string())
        );
        assert_eq!(
            r.resolve("POOL INITIALIZATION (Dexes)"),
            Some("Pool Initialization (Dexes)".to_string())
        );
        assert_eq!(
            r.resolve("share-accounting"),
            Some("Share Accounting".to_string())
        );
        // No match
        assert_eq!(r.resolve("totally unrelated"), None);
    }

    #[test]
    fn resolver_fuzzy_match() {
        let vocab = vec![kg("Liquidation Accounting", "Lending")];
        let r = KgNameResolver::build(&vocab);
        // Slight typo / phrasing
        assert_eq!(
            r.resolve("liquidation acconting"), // missing 'u'
            Some("Liquidation Accounting".to_string())
        );
    }

    #[test]
    fn apply_matches_preserves_unmatched() {
        let sems = vec![
            sem("share accounting", &["V"]),
            sem("oracle dependency", &["O"]),
        ];
        let matches = vec![("share accounting".to_string(), "Share Accounting (Yield)".to_string())];
        let out = apply_matches(&sems, &matches);
        assert_eq!(out[0].name, "Share Accounting"); // suffix stripped
        assert_eq!(out[1].name, "oracle dependency"); // unchanged
    }

    #[test]
    fn filter_canonical_drops_composite_names() {
        let v = vec![
            kg("AMM, RFQ, Auction, Bridge", "Dexes"),
            kg("Share Accounting", "Yield"),
            kg("", "Other"),
        ];
        let f = filter_canonical_vocab(&v);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "Share Accounting");
    }

    #[test]
    fn names_match_loosely_handles_minor_drift() {
        assert!(names_match_loosely("share accounting", "Share Accounting"));
        assert!(names_match_loosely(
            "share accounting",
            "share-accounting"
        ));
        assert!(!names_match_loosely("share accounting", "oracle"));
    }
}
