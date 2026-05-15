use serde::{Deserialize, Serialize};

/// SWC (Smart Contract Weakness Classification) registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwcEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub severity: SwcSeverity,
    pub patterns: Vec<SwcPattern>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwcSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// A detection pattern for an SWC entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwcPattern {
    /// Function has external call and then state write (reentrancy).
    ExternalCallBeforeStateWrite,
    /// Function uses block.timestamp or block.number for critical logic.
    BlockTimestampDependence,
    /// Missing zero-address check on address parameter.
    MissingZeroAddressCheck,
    /// Strict equality (==) used with dynamic value.
    StrictEquality,
    /// Division before multiplication (precision loss).
    DivideBeforeMultiply,
    /// Low-level call (call, delegatecall, staticcall) without proper handling.
    LowLevelCall,
    /// Function modifies state but lacks access control modifier.
    MissingAccessControl,
    /// Unprotected function that could be called by anyone.
    UnprotectedFunction,
    /// Oracle price manipulation pattern.
    OracleManipulation,
    /// Flash loan vulnerability pattern (no reentrancy guard + state-dependent).
    FlashLoanVulnerable,
    /// Assert or require on a dynamic value that can be manipulated externally.
    AssertOnDynamicValue,
    /// Custom regex-based pattern.
    CustomRegex {
        pattern: String,
        description: String,
    },
}

/// Built-in SWC registry.
pub fn swc_registry() -> Vec<SwcEntry> {
    vec![
        SwcEntry {
            id: "SWC-107".to_string(),
            title: "Reentrancy".to_string(),
            description: "External call before state update can lead to reentrancy attacks"
                .to_string(),
            impact: "Funds can be drained via recursive calls".to_string(),
            severity: SwcSeverity::High,
            patterns: vec![SwcPattern::ExternalCallBeforeStateWrite],
        },
        SwcEntry {
            id: "SWC-116".to_string(),
            title: "Block Timestamp Dependence".to_string(),
            description: "Use of block.timestamp in critical logic".to_string(),
            impact: "Miner can manipulate timestamp".to_string(),
            severity: SwcSeverity::Medium,
            patterns: vec![SwcPattern::BlockTimestampDependence],
        },
        SwcEntry {
            id: "SWC-131".to_string(),
            title: "Missing Zero Address Validation".to_string(),
            description: "Address parameters not validated against zero address".to_string(),
            impact: "Funds can be lost to zero address".to_string(),
            severity: SwcSeverity::Low,
            patterns: vec![SwcPattern::MissingZeroAddressCheck],
        },
        SwcEntry {
            id: "SWC-132".to_string(),
            title: "Unexpected Ether Balance".to_string(),
            description: "Contract balance can be manipulated".to_string(),
            impact: "Logic dependent on balance can be bypassed".to_string(),
            severity: SwcSeverity::Medium,
            patterns: vec![SwcPattern::StrictEquality],
        },
        SwcEntry {
            id: "SWC-101".to_string(),
            title: "Divide Before Multiply".to_string(),
            description: "Division performed before multiplication leading to precision loss"
                .to_string(),
            impact: "Precision loss in calculations".to_string(),
            severity: SwcSeverity::Low,
            patterns: vec![SwcPattern::DivideBeforeMultiply],
        },
        SwcEntry {
            id: "SWC-110".to_string(),
            title: "Assert Violation".to_string(),
            description: "Use of assert for conditions that can be triggered by user input"
                .to_string(),
            impact: "Transaction can consume all gas".to_string(),
            severity: SwcSeverity::Medium,
            patterns: vec![SwcPattern::StrictEquality],
        },
        SwcEntry {
            id: "SWC-112".to_string(),
            title: "Delegatecall to Untrusted Callee".to_string(),
            description: "Delegatecall to user-controlled address".to_string(),
            impact: "Complete contract takeover".to_string(),
            severity: SwcSeverity::Critical,
            patterns: vec![SwcPattern::LowLevelCall],
        },
        SwcEntry {
            id: "SWC-106".to_string(),
            title: "Unprotected SELFDESTRUCT".to_string(),
            description: "Self-destruct can be called by anyone".to_string(),
            impact: "Contract can be destroyed".to_string(),
            severity: SwcSeverity::Critical,
            patterns: vec![SwcPattern::MissingAccessControl],
        },
        SwcEntry {
            id: "SWC-115".to_string(),
            title: "Authorization through tx.origin".to_string(),
            description: "Use of tx.origin for authorization".to_string(),
            impact: "Phishing attacks can bypass authorization".to_string(),
            severity: SwcSeverity::Medium,
            patterns: vec![SwcPattern::CustomRegex {
                pattern: r"tx\.origin".to_string(),
                description: "tx.origin usage".to_string(),
            }],
        },
        SwcEntry {
            id: "SWC-136".to_string(),
            title: "Unencrypted Private Data".to_string(),
            description: "Sensitive data stored on-chain without encryption".to_string(),
            impact: "Data is publicly readable".to_string(),
            severity: SwcSeverity::Medium,
            patterns: vec![SwcPattern::CustomRegex {
                pattern: r"private\s+(string|bytes)".to_string(),
                description: "Private string/bytes storage".to_string(),
            }],
        },
        SwcEntry {
            id: "SWC-110".to_string(),
            title: "Assert on Dynamic Value".to_string(),
            description: "assert/require depends on externally manipulable value".to_string(),
            impact: "Assertion can be violated by direct token transfer or oracle manipulation"
                .to_string(),
            severity: SwcSeverity::High,
            patterns: vec![SwcPattern::AssertOnDynamicValue],
        },
    ]
}
