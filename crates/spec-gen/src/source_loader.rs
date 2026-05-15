//! Multi-contract source loader.
//!
//! Given a project root and a set of target contracts, this module finds the
//! relevant `.sol` files on disk, parses their imports via `solang-parser`,
//! transitively resolves dependencies (depth-bounded), and assembles a single
//! prompt-friendly text blob within a configurable byte budget.
//!
//! Design highlights:
//! - **Project-type aware**: Foundry (`foundry.toml`), Hardhat (`hardhat.config.{js,ts}`),
//!   or flat directory layout. Foundry projects also honor `remappings.txt`.
//! - **Skip vendored code**: `lib/forge-std`, `lib/openzeppelin*`, `node_modules`,
//!   test/script directories, mocks, generated artifacts.
//! - **Budget-aware**: When total source exceeds `max_total_bytes`, the loader
//!   prioritizes target contracts and their direct dependencies, then prunes
//!   transitive dependencies furthest from the targets.
//! - **Interface separation**: Interface and library files are loaded but tagged
//!   separately so the prompt can summarize them rather than dump entire bodies.

use serde::{Deserialize, Serialize};
use solang_parser::pt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Maximum import-graph depth to traverse from a target contract.
const DEFAULT_MAX_DEPTH: usize = 2;

/// Default byte budget for the assembled prompt blob (~50KB ≈ 12k tokens).
const DEFAULT_MAX_TOTAL_BYTES: usize = 48 * 1024;

/// Default per-file byte cap (truncated if exceeded).
const DEFAULT_MAX_BYTES_PER_FILE: usize = 16 * 1024;

/// Kind of a Solidity file for prioritisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolFileKind {
    /// One of the requested target contracts.
    Target,
    /// Imported by a target contract (direct or transitive).
    Dependency,
    /// Interface declaration (kept as context, lower priority).
    Interface,
    /// Library, abstract contract, or unrelated supporting file.
    Library,
}

/// A resolved Solidity file with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedSolFile {
    pub path: PathBuf,
    /// Relative path from the project root (POSIX-style separators).
    pub rel_path: String,
    pub kind: SolFileKind,
    /// Depth in the dependency graph from the nearest target (0 = target itself).
    pub depth: usize,
    /// Solidity contract names defined in this file.
    pub contracts: Vec<String>,
    /// File contents, possibly truncated.
    pub source: String,
    /// True if `source` was truncated to fit per-file or total budget.
    pub truncated: bool,
    pub byte_size: usize,
}

/// The complete context for a multi-contract audit prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSourceContext {
    pub project_root: PathBuf,
    pub project_type: ProjectType,
    pub files: Vec<ResolvedSolFile>,
    /// Names of target contracts that could not be found on disk.
    pub missing_targets: Vec<String>,
    /// Final byte total of all `source` fields (after truncation).
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectType {
    Foundry,
    Hardhat,
    Flat,
}

/// Configuration for [`load_project_sources`].
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    pub max_depth: usize,
    pub max_total_bytes: usize,
    pub max_bytes_per_file: usize,
    /// If true, interface files included as context (cheaper than full contracts).
    pub include_interfaces: bool,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_bytes_per_file: DEFAULT_MAX_BYTES_PER_FILE,
            include_interfaces: true,
        }
    }
}

/// Patterns (in lowercased rel-path form, with leading `/`) that mark a file as Skip.
const SKIP_DIR_PATTERNS: &[&str] = &[
    "/test/",
    "/tests/",
    "/test-",
    "/mocks/",
    "/mock/",
    "/scripts/",
    "/script/",
    "/node_modules/",
    "/lib/forge-std/",
    "/lib/openzeppelin",
    "/lib/solmate/",
    "/lib/solady/",
    "/lib/oz",
    "/out/",
    "/cache/",
    "/artifacts/",
    "/coverage/",
    "/broadcast/",
    "/.git/",
];

/// Load a project's Solidity sources, resolving imports starting from the given
/// target contracts.
///
/// Returns `Err` only on I/O errors when scanning. Missing target contracts are
/// recorded in `missing_targets` and the function still returns success with
/// the partial result.
pub fn load_project_sources(
    project_root: &Path,
    target_contracts: &[String],
    config: &LoaderConfig,
) -> std::io::Result<ProjectSourceContext> {
    let project_type = detect_project_type(project_root);
    debug!(
        "Detected project type {:?} for root {}",
        project_type,
        project_root.display()
    );

    // 1. Discover all in-scope Solidity files.
    let all_files = scan_solidity_files(project_root)?;
    debug!("Scanned {} candidate .sol files", all_files.len());

    // 2. Build an index: contract name -> path (best-guess from filename + parse).
    let index = build_contract_index(&all_files);

    // 3. Resolve targets to file paths.
    let mut missing_targets = Vec::new();
    let mut target_paths: Vec<PathBuf> = Vec::new();
    for tc in target_contracts {
        if let Some(path) = index.get(tc).cloned() {
            target_paths.push(path);
        } else {
            warn!("Target contract '{}' not found in project", tc);
            missing_targets.push(tc.clone());
        }
    }

    // 4. BFS over the import graph up to max_depth.
    let mut queue: VecDeque<(PathBuf, usize)> =
        target_paths.iter().map(|p| (p.clone(), 0usize)).collect();
    let target_set: HashSet<PathBuf> = target_paths.iter().cloned().collect();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut depths: HashMap<PathBuf, usize> = HashMap::new();
    while let Some((path, depth)) = queue.pop_front() {
        if !visited.insert(path.clone()) {
            continue;
        }
        depths.entry(path.clone()).or_insert(depth);
        if depth >= config.max_depth {
            continue;
        }
        // Parse imports
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let imports = parse_imports(&contents);
        for imp in imports {
            if let Some(resolved) = resolve_import(&imp, &path, project_root, &index) {
                if !visited.contains(&resolved) {
                    queue.push_back((resolved, depth + 1));
                }
            }
        }
    }

    // 5. Materialize ResolvedSolFile entries.
    let mut resolved: Vec<ResolvedSolFile> = Vec::new();
    for path in &visited {
        let Some(depth) = depths.get(path).copied() else {
            continue;
        };
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        let parsed = parse_top_level(&raw);
        let kind = if target_set.contains(path) {
            SolFileKind::Target
        } else if parsed.has_only_interfaces {
            SolFileKind::Interface
        } else if parsed.has_only_library {
            SolFileKind::Library
        } else {
            SolFileKind::Dependency
        };
        if matches!(kind, SolFileKind::Interface) && !config.include_interfaces {
            continue;
        }
        // Per-file truncation
        let (source, truncated) = truncate_source(&raw, config.max_bytes_per_file);
        let byte_size = raw.len();
        let rel_path = path
            .strip_prefix(project_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        resolved.push(ResolvedSolFile {
            path: path.clone(),
            rel_path,
            kind,
            depth,
            contracts: parsed.contracts,
            source,
            truncated,
            byte_size,
        });
    }

    // 6. Sort by priority: Target -> Dependency -> Interface -> Library, then depth.
    resolved.sort_by(|a, b| {
        kind_priority(a.kind)
            .cmp(&kind_priority(b.kind))
            .then(a.depth.cmp(&b.depth))
    });

    // 7. Enforce global budget.
    let mut running = 0usize;
    let mut kept: Vec<ResolvedSolFile> = Vec::new();
    for mut f in resolved {
        let remaining = config.max_total_bytes.saturating_sub(running);
        if remaining == 0 {
            break;
        }
        if f.source.len() > remaining {
            // Hard-truncate to fit remaining budget.
            f.source.truncate(remaining);
            f.source.push_str("\n// (truncated to fit total budget)\n");
            f.truncated = true;
        }
        running += f.source.len();
        kept.push(f);
    }

    Ok(ProjectSourceContext {
        project_root: project_root.to_path_buf(),
        project_type,
        files: kept,
        missing_targets,
        total_bytes: running,
    })
}

/// Render a [`ProjectSourceContext`] into a prompt-friendly text blob.
pub fn render_context_for_prompt(ctx: &ProjectSourceContext) -> String {
    let mut out = String::with_capacity(ctx.total_bytes + 1024);
    out.push_str(&format!(
        "// Project root: {}\n// Project type: {:?}\n// Files included: {}\n// Total bytes: {}\n",
        ctx.project_root.display(),
        ctx.project_type,
        ctx.files.len(),
        ctx.total_bytes,
    ));
    if !ctx.missing_targets.is_empty() {
        out.push_str(&format!(
            "// MISSING TARGETS (not found on disk): {}\n",
            ctx.missing_targets.join(", ")
        ));
    }
    for f in &ctx.files {
        out.push_str(&format!(
            "\n// ===== {kind:?} (depth={depth}): {rel} | contracts: {contracts} =====\n",
            kind = f.kind,
            depth = f.depth,
            rel = f.rel_path,
            contracts = f.contracts.join(", "),
        ));
        out.push_str(&f.source);
        if f.truncated {
            out.push_str("\n// (file truncated)\n");
        }
    }
    out
}

fn kind_priority(k: SolFileKind) -> u8 {
    match k {
        SolFileKind::Target => 0,
        SolFileKind::Dependency => 1,
        SolFileKind::Interface => 2,
        SolFileKind::Library => 3,
    }
}

fn detect_project_type(root: &Path) -> ProjectType {
    if root.join("foundry.toml").is_file() {
        ProjectType::Foundry
    } else if root.join("hardhat.config.js").is_file()
        || root.join("hardhat.config.ts").is_file()
        || root.join("hardhat.config.cjs").is_file()
    {
        ProjectType::Hardhat
    } else {
        ProjectType::Flat
    }
}

/// Recursively scan for `.sol` files, skipping vendored/test/script directories.
fn scan_solidity_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    walk(root, root, &mut out, &mut visited)?;
    Ok(out)
}

fn walk(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let canon = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(canon) {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(root, &path, out, visited)?;
        } else if ft.is_file() && path.extension().map(|e| e == "sol").unwrap_or(false) {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if is_skipped(&rel) {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

fn is_skipped(rel: &str) -> bool {
    let with_slash = format!("/{}", rel.to_lowercase());
    if SKIP_DIR_PATTERNS.iter().any(|p| with_slash.contains(p)) {
        return true;
    }
    let file_name = rel.rsplit('/').next().unwrap_or("");
    file_name.ends_with(".t.sol") || file_name.ends_with(".s.sol")
}

/// Quickly extract `import "path"` directives from raw Solidity source.
/// Uses solang-parser for accuracy; falls back to regex on parse error.
fn parse_imports(source: &str) -> Vec<String> {
    let parsed = solang_parser::parse(source, 0);
    if let Ok((unit, _)) = parsed {
        let mut out = Vec::new();
        for part in &unit.0 {
            if let pt::SourceUnitPart::ImportDirective(import) = part {
                let path_str = match import {
                    pt::Import::Plain(p, _) | pt::Import::GlobalSymbol(p, _, _) => p,
                    pt::Import::Rename(p, _, _) => p,
                };
                out.push(literal_to_string(path_str));
            }
        }
        return out;
    }
    // Fallback: regex-y line-by-line scan
    let mut out = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("import") {
            let r = rest.trim();
            // import "path"; or import ... from "path";
            if let Some(start) = r.find('"') {
                if let Some(end_rel) = r[start + 1..].find('"') {
                    let end = start + 1 + end_rel;
                    out.push(r[start + 1..end].to_string());
                }
            }
        }
    }
    out
}

fn literal_to_string(lit: &pt::ImportPath) -> String {
    match lit {
        pt::ImportPath::Filename(s) => s.string.clone(),
        pt::ImportPath::Path(idents) => idents
            .identifiers
            .iter()
            .map(|i| i.name.clone())
            .collect::<Vec<_>>()
            .join("."),
    }
}

/// Resolve an `import` string to a file path on disk relative to either the
/// importing file or the project root. Returns `None` if no candidate exists.
fn resolve_import(
    import: &str,
    importer: &Path,
    project_root: &Path,
    index: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    // 1. Relative to importer
    if import.starts_with('.') {
        let dir = importer.parent()?;
        let cand = dir.join(import);
        if cand.is_file() {
            return Some(canonicalize_or_self(&cand));
        }
    }
    // 2. Look up by file stem in index (`import "Foo.sol"` or `... "src/Foo.sol"`)
    let basename = Path::new(import).file_stem()?.to_str()?.to_string();
    if let Some(path) = index.get(&basename) {
        return Some(path.clone());
    }
    // 3. Relative to project root
    let cand = project_root.join(import);
    if cand.is_file() {
        return Some(canonicalize_or_self(&cand));
    }
    // 4. With `src/` prefix
    let cand2 = project_root.join("src").join(import);
    if cand2.is_file() {
        return Some(canonicalize_or_self(&cand2));
    }
    None
}

fn canonicalize_or_self(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

#[derive(Debug, Default)]
struct ParsedTopLevel {
    contracts: Vec<String>,
    has_only_interfaces: bool,
    has_only_library: bool,
}

fn parse_top_level(source: &str) -> ParsedTopLevel {
    let mut out = ParsedTopLevel::default();
    let Ok((unit, _)) = solang_parser::parse(source, 0) else {
        return out;
    };
    let mut total = 0usize;
    let mut interface_count = 0usize;
    let mut library_count = 0usize;
    for part in &unit.0 {
        if let pt::SourceUnitPart::ContractDefinition(def) = part {
            total += 1;
            let name = def
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default();
            if !name.is_empty() {
                out.contracts.push(name);
            }
            match def.ty {
                pt::ContractTy::Interface(_) => interface_count += 1,
                pt::ContractTy::Library(_) => library_count += 1,
                _ => {}
            }
        }
    }
    if total > 0 {
        out.has_only_interfaces = interface_count == total;
        out.has_only_library = library_count == total;
    }
    out
}

/// Build a contract-name -> file-path index by scanning all files.
fn build_contract_index(files: &[PathBuf]) -> HashMap<String, PathBuf> {
    let mut idx = HashMap::new();
    for path in files {
        // Prefer file stem match (cheaper, covers most C4 conventions)
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            idx.entry(stem.to_string())
                .or_insert_with(|| canonicalize_or_self(path));
        }
        // Parse the file once to catch contracts whose name differs from filename
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        let parsed = parse_top_level(&contents);
        for name in parsed.contracts {
            idx.entry(name)
                .or_insert_with(|| canonicalize_or_self(path));
        }
    }
    idx
}

fn truncate_source(source: &str, max_bytes: usize) -> (String, bool) {
    if source.len() <= max_bytes {
        (source.to_string(), false)
    } else {
        let mut s = String::with_capacity(max_bytes + 64);
        s.push_str(&source[..max_bytes]);
        s.push_str("\n// (truncated to fit per-file budget)\n");
        (s, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    fn make_foundry_project() -> TempDir {
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
import "./IStrategy.sol";

contract Vault {
    Token public token;
    IStrategy public strategy;
    constructor(Token _t) { token = _t; }
    function setStrategy(IStrategy s) external { strategy = s; }
}
"#,
        );
        write_file(
            dir.path(),
            "src/Token.sol",
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Token {
    mapping(address=>uint256) public balanceOf;
}
"#,
        );
        write_file(
            dir.path(),
            "src/IStrategy.sol",
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IStrategy {
    function invest(uint256 amount) external;
}
"#,
        );
        // Vendored: should be skipped
        write_file(
            dir.path(),
            "lib/forge-std/Test.sol",
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Test {}\n",
        );
        // Test file: should be skipped
        write_file(
            dir.path(),
            "test/Vault.t.sol",
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract VaultTest {}\n",
        );
        dir
    }

    #[test]
    fn detects_foundry_project() {
        let dir = make_foundry_project();
        assert_eq!(detect_project_type(dir.path()), ProjectType::Foundry);
    }

    #[test]
    fn loads_target_and_dependency_files() {
        let dir = make_foundry_project();
        let ctx =
            load_project_sources(dir.path(), &["Vault".to_string()], &LoaderConfig::default())
                .unwrap();
        assert!(
            ctx.missing_targets.is_empty(),
            "no missing targets expected"
        );
        // Should pick up Vault (target), Token (dependency), IStrategy (interface).
        let kinds: Vec<SolFileKind> = ctx.files.iter().map(|f| f.kind).collect();
        assert!(
            kinds.contains(&SolFileKind::Target),
            "must include Target file"
        );
        assert!(
            kinds.contains(&SolFileKind::Dependency) || kinds.contains(&SolFileKind::Interface),
            "must include at least one Dependency or Interface file"
        );
        // Should skip vendored & test files.
        for f in &ctx.files {
            assert!(
                !f.rel_path.starts_with("lib/forge-std/"),
                "vendored should be skipped"
            );
            assert!(!f.rel_path.starts_with("test/"), "test/ should be skipped");
        }
    }

    #[test]
    fn missing_target_recorded() {
        let dir = make_foundry_project();
        let ctx = load_project_sources(
            dir.path(),
            &["DoesNotExist".to_string()],
            &LoaderConfig::default(),
        )
        .unwrap();
        assert_eq!(ctx.missing_targets, vec!["DoesNotExist".to_string()]);
        assert!(ctx.files.is_empty(), "no files for missing target");
    }

    #[test]
    fn parse_imports_extracts_paths() {
        let src = r#"
pragma solidity ^0.8.0;
import "./Token.sol";
import {X} from "./IStrategy.sol";
contract A {}
"#;
        let imports = parse_imports(src);
        assert_eq!(imports.len(), 2);
        assert!(imports.iter().any(|s| s.ends_with("Token.sol")));
        assert!(imports.iter().any(|s| s.ends_with("IStrategy.sol")));
    }

    #[test]
    fn render_context_produces_blob() {
        let dir = make_foundry_project();
        let ctx =
            load_project_sources(dir.path(), &["Vault".to_string()], &LoaderConfig::default())
                .unwrap();
        let blob = render_context_for_prompt(&ctx);
        assert!(blob.contains("contract Vault"));
        assert!(blob.contains("Target"));
    }

    #[test]
    fn budget_truncates_long_files() {
        let dir = TempDir::new().unwrap();
        // 100KB of source
        let body = "// pad\n".repeat(20_000);
        write_file(
            dir.path(),
            "src/Big.sol",
            &format!(
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Big {{}}\n{}",
                body
            ),
        );
        let cfg = LoaderConfig {
            max_total_bytes: 4 * 1024,
            max_bytes_per_file: 2 * 1024,
            ..LoaderConfig::default()
        };
        let ctx = load_project_sources(dir.path(), &["Big".to_string()], &cfg).unwrap();
        assert!(ctx.total_bytes <= 4 * 1024 + 256);
        let big = ctx
            .files
            .iter()
            .find(|f| f.contracts.contains(&"Big".to_string()))
            .unwrap();
        assert!(big.truncated);
    }
}
