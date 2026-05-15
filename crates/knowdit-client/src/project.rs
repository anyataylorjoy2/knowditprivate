//! Project file discovery for Knowledge Mapper.
//!
//! Identifies the "primary" Solidity files in a project — i.e., the ones an auditor
//! would actually want context for — while skipping noise like test fixtures, mocks,
//! vendored OpenZeppelin, and generated artifacts.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// A discovered Solidity file with metadata for prioritisation.
#[derive(Debug, Clone)]
pub struct ProjectFile {
    pub path: PathBuf,
    pub kind: FileKind,
    pub byte_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Top-level contract that an auditor would focus on.
    Primary,
    /// Library / interface — useful as context, less interesting on its own.
    Library,
    /// Test, mock, script, or vendored code — skip for Knowledge Mapper.
    Skip,
}

/// Patterns that, if present in the relative path, mark a file as Skip.
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
    "/dependencies/",
    "/vendor/",
];

/// File-name fragments that indicate this is a library / interface (still useful, less critical).
const LIBRARY_PATTERNS: &[&str] = &["Library", "Interface", "Errors", "Constants", "Events"];

/// Discover primary Solidity files for a project rooted at `root`.
///
/// Returns up to `max_files` paths ordered by likely relevance (largest non-library
/// contracts first). Empty `Vec` if no `.sol` files found.
pub fn discover_project_files(
    root: impl AsRef<Path>,
    max_files: usize,
) -> std::io::Result<Vec<ProjectFile>> {
    let root = root.as_ref();
    let mut files = Vec::new();
    let mut visited = HashSet::new();
    walk(root, root, &mut files, &mut visited)?;

    // Filter to Primary + Library; rank Primary first, then by size.
    files.retain(|f| f.kind != FileKind::Skip);
    files.sort_by(|a, b| {
        // Primary before Library
        let kind_cmp = (a.kind != FileKind::Primary).cmp(&(b.kind != FileKind::Primary));
        if kind_cmp != std::cmp::Ordering::Equal {
            kind_cmp
        } else {
            // Larger files first within the same kind
            b.byte_size.cmp(&a.byte_size)
        }
    });
    if files.len() > max_files {
        files.truncate(max_files);
    }
    Ok(files)
}

fn walk(
    root: &Path,
    dir: &Path,
    out: &mut Vec<ProjectFile>,
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
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk(root, &path, out, visited)?;
        } else if file_type.is_file() && path.extension().map(|e| e == "sol").unwrap_or(false) {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let kind = classify(&rel);
            let byte_size = entry.metadata()?.len();
            out.push(ProjectFile {
                path: path.clone(),
                kind,
                byte_size,
            });
        }
    }
    Ok(())
}

fn classify(rel_path: &str) -> FileKind {
    let with_slashes = format!("/{}", rel_path);
    let lower = with_slashes.to_lowercase();

    for skip in SKIP_DIR_PATTERNS {
        if lower.contains(*skip) {
            return FileKind::Skip;
        }
    }

    let file_name = rel_path.rsplit('/').next().unwrap_or("");
    if file_name.starts_with("Mock") || file_name.starts_with("Test") {
        return FileKind::Skip;
    }
    if file_name.ends_with(".t.sol") || file_name.ends_with(".s.sol") {
        return FileKind::Skip;
    }
    for lib_pat in LIBRARY_PATTERNS {
        if file_name.contains(lib_pat) {
            return FileKind::Library;
        }
    }
    if file_name.starts_with("I")
        && file_name
            .chars()
            .nth(1)
            .map(|c| c.is_uppercase())
            .unwrap_or(false)
    {
        // Heuristic: `IFooBar.sol` → interface
        return FileKind::Library;
    }

    FileKind::Primary
}

/// Read up to `max_bytes` of each file in `files`, concatenated with separators.
/// Useful for feeding to an LLM with a single bounded prompt.
pub fn read_concatenated(files: &[ProjectFile], max_bytes_per_file: usize) -> String {
    let mut out = String::new();
    for f in files {
        let display = f.path.display();
        match std::fs::read_to_string(&f.path) {
            Ok(s) => {
                let truncated = if s.len() > max_bytes_per_file {
                    &s[..max_bytes_per_file]
                } else {
                    &s
                };
                out.push_str(&format!("\n// ===== FILE: {} =====\n", display));
                out.push_str(truncated);
                if s.len() > max_bytes_per_file {
                    out.push_str("\n// (truncated)\n");
                }
            }
            Err(e) => {
                out.push_str(&format!("\n// failed to read {}: {}\n", display, e));
            }
        }
    }
    out
}
