//! Fuzz Executor agent — runs Foundry harnesses and parses results.
//!
//! Key design: Foundry compiles ALL `.sol` files in `test/` before running
//! any test. A single broken harness will cascade-fail every other harness.
//! To prevent this, `execute()` cleans up previous Knowdit harnesses from
//! the `test/` directory before writing the new one, and removes the harness
//! after execution if it caused a compilation failure.

use agent_core::{AgentResult, FuzzExecutor, FuzzHarness, FuzzOutcome, FuzzResult};
use async_trait::async_trait;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Foundry-backed fuzz executor.
pub struct FoundryExecutor {
    /// Path to forge binary. Defaults to "forge".
    pub forge_bin: String,
    /// Number of fuzz runs to request.
    pub runs: u32,
}

impl FoundryExecutor {
    pub fn new() -> Self {
        Self {
            forge_bin: "forge".to_string(),
            runs: 1000,
        }
    }
}

impl Default for FoundryExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FuzzExecutor for FoundryExecutor {
    async fn execute(
        &self,
        harness: &FuzzHarness,
        project_root: &str,
        timeout_secs: u64,
    ) -> AgentResult<FuzzResult> {
        let root = std::path::Path::new(project_root);

        // Clean up previous Knowdit harnesses from test/ to prevent
        // cascade compilation failures. Forge compiles ALL .sol files
        // in test/ before running any test, so a single broken import
        // will cause every harness to fail.
        cleanup_knowdit_harnesses(root).await;

        // Write harness to disk before running forge test
        let harness_path = root.join(&harness.file_path);
        if let Some(parent) = harness_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&harness_path, &harness.source).await?;

        let mut cmd = Command::new(&self.forge_bin);
        cmd.arg("test")
            .arg("--match-test")
            .arg(&harness.test_name)
            .arg("--fuzz-runs")
            .arg(self.runs.to_string())
            .arg("-vv")
            .current_dir(project_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn()?;
        let output =
            match timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await {
                Ok(res) => res?,
                Err(_) => {
                    // Remove harness on timeout so it doesn't break future runs
                    let _ = tokio::fs::remove_file(&harness_path).await;
                    return Ok(FuzzResult {
                        harness_id: harness.spec_id.clone(),
                        outcome: FuzzOutcome::HarnessFailure {
                            reason: format!("Timed out after {}s", timeout_secs),
                        },
                        coverage: 0.0,
                        raw_output: String::new(),
                    });
                }
            };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}\n{}", stdout, stderr);

        let outcome = parse_forge_output(&combined);

        // If compilation failed, remove the harness from disk so it doesn't
        // break subsequent harness executions.
        if matches!(outcome, FuzzOutcome::HarnessFailure { .. }) {
            let _ = tokio::fs::remove_file(&harness_path).await;
        }

        Ok(FuzzResult {
            harness_id: harness.spec_id.clone(),
            outcome,
            coverage: 0.0, // TODO: parse coverage if requested
            raw_output: combined,
        })
    }
}

/// Remove all `Knowdit_*.t.sol` files from the project's `test/` directory.
/// This prevents cascade compilation failures where one broken harness
/// causes Forge to fail compiling all other test files.
async fn cleanup_knowdit_harnesses(project_root: &std::path::Path) {
    let test_dir = project_root.join("test");
    let Ok(mut entries) = tokio::fs::read_dir(&test_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name() else {
            continue;
        };
        let name = name.to_string_lossy();
        if name.starts_with("Knowdit_") && name.ends_with(".t.sol") {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
}

/// Crude parser for `forge test` output. Returns the appropriate `FuzzOutcome`.
fn parse_forge_output(text: &str) -> FuzzOutcome {
    let lower = text.to_lowercase();
    if lower.contains("counterexample")
        || lower.contains("invariant violated")
        || lower.contains("[fail. reason:")
    {
        FuzzOutcome::Violation {
            trace: text.to_string(),
            state_changes: Vec::new(),
        }
    } else if lower.contains("compilation error")
        || lower.contains("compiler run failed")
        || (lower.contains("error (") && lower.contains("sol"))
        || lower.contains("typeerror")
    {
        FuzzOutcome::HarnessFailure {
            reason: "Compilation error".to_string(),
        }
    } else if lower.contains("[pass]")
        || lower.contains("test result: ok")
        || lower.contains("suite result: ok")
        || text.contains("[PASS]")
    {
        FuzzOutcome::NoViolation
    } else {
        FuzzOutcome::HarnessFailure {
            reason: "Unknown forge output".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_compilation_error() {
        // Forge output when a harness has broken imports
        let output = "Compiler run failed:\nError (6275): Source \"src/Morpho.sol\" not found\nError: Compilation failed";
        let result = parse_forge_output(output);
        assert!(matches!(result, FuzzOutcome::HarnessFailure { .. }));
    }

    #[test]
    fn test_parse_pass() {
        let output =
            "[PASS] test_invariant_foo() (gas: 1234)\nSuite result: ok. 1 passed; 0 failed";
        let result = parse_forge_output(output);
        assert!(matches!(result, FuzzOutcome::NoViolation));
    }

    #[test]
    fn test_parse_violation() {
        let output =
            "[FAIL. Reason: Revert] test_invariant_foo() (gas: 5678)\nSuite result: FAILED";
        let result = parse_forge_output(output);
        assert!(matches!(result, FuzzOutcome::Violation { .. }));
    }
}
