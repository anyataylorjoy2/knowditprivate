//! Harness Synthesizer agent.
//!
//! Turns an `AuditSpec` into a Foundry test contract that:
//! - sets up the project (`setUp()`)
//! - has handlers wrapping external entry points
//! - encodes pre/post-vuln invariants as require/assert oracles
//!
//! For non-Foundry projects, we generate a minimal Foundry wrapper around the existing source.

pub mod foundry;
pub mod synthesizer;

pub use synthesizer::LlmHarnessSynthesizer;
