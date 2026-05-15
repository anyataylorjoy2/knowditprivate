use crate::contract_semantics::*;
use sol_ast::ast::{Mutability, Visibility};
use std::collections::HashMap;

/// Analysis result for access control in a contract.
#[derive(Debug, Clone, Default)]
pub struct AccessControlAnalysis {
    /// Functions that are marked as privileged (have owner/auth modifiers).
    pub privileged_functions: Vec<String>,
    /// Functions that are external/public but have NO access control.
    pub unprotected_functions: Vec<String>,
    /// Functions that perform sensitive operations (state changes on critical vars).
    pub sensitive_functions: Vec<String>,
    /// Mapping from function name to the access control it uses.
    pub function_access_map: HashMap<String, AccessControlKind>,
    /// Potential missing access control: sensitive function without protection.
    pub missing_access_control: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControlKind {
    None,
    OnlyOwner,
    RoleBased,
    CustomModifier,
    RequireCheck,
}

impl AccessControlAnalysis {
    pub fn analyze_contract(contract: &ContractSemantics) -> Self {
        let mut analysis = AccessControlAnalysis::default();

        // Identify privileged functions
        for func in &contract.functions {
            let access = classify_access_control(func);
            analysis
                .function_access_map
                .insert(func.name.clone(), access.clone());
            match access {
                AccessControlKind::OnlyOwner
                | AccessControlKind::RoleBased
                | AccessControlKind::CustomModifier => {
                    analysis.privileged_functions.push(func.name.clone());
                }
                AccessControlKind::RequireCheck => {
                    // Partial protection
                }
                AccessControlKind::None => {
                    if func.visibility == Visibility::External
                        || func.visibility == Visibility::Public
                    {
                        analysis.unprotected_functions.push(func.name.clone());
                    }
                }
            }
        }

        // Identify sensitive functions: those that write critical state
        for func in &contract.functions {
            if !func.state_writes.is_empty() {
                analysis.sensitive_functions.push(func.name.clone());
            }
        }

        // Detect missing access control on sensitive functions
        let public_interface_names = [
            "deposit",
            "flash",
            "stake",
            "unstake",
            "harvest",
            "swap",
            "addliquidity",
            "removeliquidity",
        ];
        for func_name in &analysis.sensitive_functions {
            if let Some(access) = analysis.function_access_map.get(func_name) {
                if *access == AccessControlKind::None {
                    // Check if this is actually a getter or harmless
                    if let Some(func) = contract.function_by_name(func_name) {
                        if func.mutability == Mutability::View
                            || func.mutability == Mutability::Pure
                        {
                            continue;
                        }
                        let name_lower = func_name.to_lowercase();
                        if public_interface_names
                            .iter()
                            .any(|p| name_lower.contains(p))
                        {
                            continue;
                        }
                        analysis.missing_access_control.push(func_name.clone());
                    }
                }
            }
        }

        analysis
    }

    /// Analyze multiple contracts together (cross-contract inheritance).
    pub fn analyze_system(
        contracts: &[ContractSemantics],
    ) -> HashMap<String, AccessControlAnalysis> {
        let mut result = HashMap::new();
        for contract in contracts {
            let analysis = Self::analyze_contract(contract);
            result.insert(contract.name.clone(), analysis);
        }
        result
    }
}

fn classify_access_control(func: &FunctionSemantics) -> AccessControlKind {
    let has_require = false;
    let mut has_owner_check = false;

    for modifier in &func.modifiers {
        let m = modifier.to_lowercase();
        if m.contains("onlyowner") || m.contains("only_owner") {
            return AccessControlKind::OnlyOwner;
        }
        if m.contains("only") || m.contains("role") || m.contains("auth") {
            return AccessControlKind::RoleBased;
        }
        if m != "nonreentrant" && !m.contains("reentrancy") && !m.is_empty() {
            // Any other modifier that isn't reentrancy guard
            return AccessControlKind::CustomModifier;
        }
    }

    // Check function body for require(msg.sender == owner) or similar
    // This is a heuristic based on doc/naming
    if let Some(doc) = &func.doc {
        let d = doc.to_lowercase();
        if d.contains("only owner") || d.contains("only the owner") {
            has_owner_check = true;
        }
    }

    if has_owner_check {
        return AccessControlKind::OnlyOwner;
    }

    if func.name.to_lowercase().starts_with("set") || func.name.to_lowercase().starts_with("update")
    {
        // These often should be protected
        if func.modifiers.is_empty() {
            // Potentially missing
        }
    }

    if has_require {
        return AccessControlKind::RequireCheck;
    }

    AccessControlKind::None
}

/// A detected access control gap with location info.
#[derive(Debug, Clone)]
pub struct AccessControlGap {
    pub function_name: String,
    pub description: String,
    pub line: Option<usize>,
}

/// Detect access control gaps based on naming conventions and doc comments.
pub fn detect_access_control_gaps(contract: &ContractSemantics) -> Vec<AccessControlGap> {
    let analysis = AccessControlAnalysis::analyze_contract(contract);
    let mut gaps = Vec::new();

    for func in &contract.functions {
        // Skip view/pure functions
        if func.mutability == Mutability::View || func.mutability == Mutability::Pure {
            continue;
        }

        // Skip internal/private functions
        if func.visibility != Visibility::Public && func.visibility != Visibility::External {
            continue;
        }

        // Check if doc claims access control but implementation lacks it
        if let Some(doc) = &func.doc {
            let d = doc.to_lowercase();
            if (d.contains("only owner")
                || d.contains("only the owner")
                || d.contains("privileged"))
                && !func.is_privileged()
            {
                gaps.push(AccessControlGap {
                    function_name: func.name.clone(),
                    description: format!(
                        "{}: doc claims access control but no modifier found",
                        func.name
                    ),
                    line: Some(func.line),
                });
            }
        }

        // Functions named set/update/delete/withdraw/liquidate should probably be protected
        let sensitive_prefixes = [
            "set",
            "update",
            "delete",
            "withdraw",
            "liquidate",
            "borrow",
            "repay",
            "claim",
        ];
        let public_interface_names = [
            "deposit",
            "flash",
            "stake",
            "unstake",
            "harvest",
            "swap",
            "addliquidity",
            "removeliquidity",
        ];
        let name_lower = func.name.to_lowercase();
        let is_public_interface = public_interface_names
            .iter()
            .any(|p| name_lower.contains(p));
        if !is_public_interface
            && sensitive_prefixes.iter().any(|p| name_lower.starts_with(p))
            && !func.is_privileged()
        {
            // Check if it's a setter for a state var (common pattern)
            if !func.state_writes.is_empty() {
                gaps.push(AccessControlGap {
                    function_name: func.name.clone(),
                    description: format!(
                        "{}: sensitive state-mutating function without access control",
                        func.name
                    ),
                    line: Some(func.line),
                });
            }
        }
    }

    for f in &analysis.missing_access_control {
        if let Some(func) = contract.function_by_name(f) {
            gaps.push(AccessControlGap {
                function_name: f.clone(),
                description: format!("{}: writes state but has no access control", f),
                line: Some(func.line),
            });
        }
    }

    gaps
}
