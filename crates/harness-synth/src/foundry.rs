//! Helpers for detecting / wrapping Foundry projects.

use std::path::{Path, PathBuf};

/// Returns true if the given path looks like a Foundry project root.
pub fn is_foundry_project(root: impl AsRef<Path>) -> bool {
    let r = root.as_ref();
    r.join("foundry.toml").exists()
}

/// Returns true if the project uses Hardhat (heuristic).
pub fn is_hardhat_project(root: impl AsRef<Path>) -> bool {
    let r = root.as_ref();
    r.join("hardhat.config.ts").exists()
        || r.join("hardhat.config.js").exists()
        || r.join("hardhat.config.cjs").exists()
}

/// Where to drop generated test files. Defaults to <root>/test/.
pub fn default_test_dir(root: impl AsRef<Path>) -> PathBuf {
    let r = root.as_ref();
    if is_foundry_project(r) {
        r.join("test")
    } else {
        r.join("knowdit-fuzz/test")
    }
}

/// Minimal foundry.toml content for auto-wrapped projects.
pub const MINIMAL_FOUNDRY_TOML: &str = r#"[profile.default]
src = "../contracts"
test = "test"
solc = "0.8.20"
optimizer = true
optimizer_runs = 200
"#;
