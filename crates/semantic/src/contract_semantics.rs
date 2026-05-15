use serde::{Deserialize, Serialize};
use sol_ast::ast::*;

/// Semantic information for a contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractSemantics {
    pub name: String,
    pub kind: ContractKind,
    pub base_contracts: Vec<String>,
    pub functions: Vec<FunctionSemantics>,
    pub state_vars: Vec<StateVarSemantic>,
    pub inherits_from: Vec<String>,
    pub is_abstract: bool,
}

/// Semantic information for a function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionSemantics {
    pub name: String,
    pub contract: String,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub modifiers: Vec<String>,
    pub params: Vec<ParamSemantic>,
    pub external_calls: Vec<ExternalCallSemantic>,
    pub state_reads: Vec<String>,
    pub state_writes: Vec<String>,
    pub assertions: Vec<String>,
    pub has_reentrancy_guard: bool,
    pub is_payable: bool,
    pub doc: Option<String>,
    pub line: usize,
}

/// Semantic information for a state variable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateVarSemantic {
    pub name: String,
    pub ty: String,
    pub visibility: Visibility,
    pub is_immutable: bool,
    pub is_constant: bool,
    pub line: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamSemantic {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalCallSemantic {
    pub target_expr: String,
    pub method_name: String,
    pub is_value_transfer: bool,
    pub is_delegatecall: bool,
    pub is_staticcall: bool,
    pub line: usize,
}

impl ContractSemantics {
    pub fn from_ast(contract: &ContractDef) -> Self {
        ContractSemantics {
            name: contract.name.clone(),
            kind: contract.kind,
            base_contracts: contract.base_contracts.clone(),
            functions: contract
                .functions
                .iter()
                .map(|f| FunctionSemantics::from_ast(f, &contract.name))
                .collect(),
            state_vars: contract
                .state_vars
                .iter()
                .map(StateVarSemantic::from_ast)
                .collect(),
            inherits_from: contract.base_contracts.clone(),
            is_abstract: contract.kind == ContractKind::Abstract,
        }
    }

    /// Get all external/public functions.
    pub fn external_functions(&self) -> Vec<&FunctionSemantics> {
        self.functions
            .iter()
            .filter(|f| f.visibility == Visibility::External || f.visibility == Visibility::Public)
            .collect()
    }

    /// Get all functions that modify state.
    pub fn state_mutating_functions(&self) -> Vec<&FunctionSemantics> {
        self.functions
            .iter()
            .filter(|f| !f.state_writes.is_empty())
            .collect()
    }

    /// Get function by name.
    pub fn function_by_name(&self, name: &str) -> Option<&FunctionSemantics> {
        self.functions.iter().find(|f| f.name == name)
    }
}

impl FunctionSemantics {
    pub fn from_ast(func: &FunctionDef, contract_name: &str) -> Self {
        FunctionSemantics {
            name: func.name.clone(),
            contract: contract_name.to_string(),
            visibility: func.visibility,
            mutability: func.mutability,
            modifiers: func.modifiers.clone(),
            params: func
                .params
                .iter()
                .map(|p| ParamSemantic {
                    name: p.name.clone(),
                    ty: p.ty.clone(),
                })
                .collect(),
            external_calls: Vec::new(), // populated by extractor
            state_reads: Vec::new(),
            state_writes: Vec::new(),
            assertions: Vec::new(),
            has_reentrancy_guard: func
                .modifiers
                .iter()
                .any(|m| m.to_lowercase().contains("reentrancyguard")),
            is_payable: func.mutability == Mutability::Payable,
            doc: func.doc.clone(),
            line: func.line,
        }
    }

    pub fn is_external_call_before_state_update(&self) -> bool {
        // Heuristic: if there's an external call and the function writes state
        !self.external_calls.is_empty() && !self.state_writes.is_empty()
    }

    pub fn is_privileged(&self) -> bool {
        self.modifiers.iter().any(|m| {
            let m = m.to_lowercase();
            m.contains("onlyowner") || m.contains("only") || m.contains("auth")
        })
    }

    pub fn has_access_control(&self) -> bool {
        self.is_privileged()
            || self.modifiers.iter().any(|m| {
                let m = m.to_lowercase();
                m.contains("require") || m.contains("check")
            })
    }
}

impl StateVarSemantic {
    pub fn from_ast(var: &StateVar) -> Self {
        StateVarSemantic {
            name: var.name.clone(),
            ty: var.ty.clone(),
            visibility: var.visibility,
            is_immutable: var.mutability == Some(Mutability::View),
            is_constant: var.mutability == Some(Mutability::View),
            line: var.line,
        }
    }
}

/// A collection of semantic info for all contracts in a source unit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceSemantics {
    pub contracts: Vec<ContractSemantics>,
    pub file_path: String,
}

impl SourceSemantics {
    pub fn new(file_path: impl Into<String>) -> Self {
        Self {
            contracts: Vec::new(),
            file_path: file_path.into(),
        }
    }

    pub fn add_contract(&mut self, contract: ContractSemantics) {
        self.contracts.push(contract);
    }

    pub fn all_functions(&self) -> Vec<&FunctionSemantics> {
        self.contracts
            .iter()
            .flat_map(|c| c.functions.iter())
            .collect()
    }

    pub fn find_function(&self, contract: &str, name: &str) -> Option<&FunctionSemantics> {
        self.contracts
            .iter()
            .find(|c| c.name == contract)
            .and_then(|c| c.function_by_name(name))
    }
}
