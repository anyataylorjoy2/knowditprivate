use serde::{Deserialize, Serialize};
use solang_parser::pt;

/// A parsed Solidity source unit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsedUnit {
    pub contracts: Vec<ContractDef>,
    pub imports: Vec<String>,
    pub pragma: Option<String>,
    pub source: String,
}

/// A contract definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractDef {
    pub name: String,
    pub kind: ContractKind,
    pub base_contracts: Vec<String>,
    pub functions: Vec<FunctionDef>,
    pub state_vars: Vec<StateVar>,
    pub events: Vec<EventDef>,
    pub errors: Vec<ErrorDef>,
    pub line: usize,
    pub doc: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
    Abstract,
}

impl Default for ContractKind {
    fn default() -> Self {
        ContractKind::Contract
    }
}

/// A function definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub modifiers: Vec<String>,
    pub params: Vec<Param>,
    pub returns: Vec<Param>,
    pub body: Option<String>, // raw body text, if available
    pub line: usize,
    pub doc: Option<String>,
    pub is_virtual: bool,
    pub is_override: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Visibility {
    #[default]
    Internal,
    External,
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Mutability {
    #[default]
    Mutable,
    View,
    Pure,
    Payable,
}

/// A state variable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateVar {
    pub name: String,
    pub ty: String,
    pub visibility: Visibility,
    pub mutability: Option<Mutability>,
    pub initial_value: Option<String>,
    pub line: usize,
}

/// An event definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventDef {
    pub name: String,
    pub params: Vec<Param>,
    pub line: usize,
}

/// A custom error definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorDef {
    pub name: String,
    pub params: Vec<Param>,
    pub line: usize,
}

/// A parameter (function arg or return).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub ty: String,
    pub data_location: Option<String>,
    pub line: usize,
}

/// An external call found in a function body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalCall {
    pub target: String, // expression as string, e.g., "pool.sendValue(...)"
    pub is_value_transfer: bool,
    pub is_delegatecall: bool,
    pub is_staticcall: bool,
    pub line: usize,
}

impl ParsedUnit {
    pub fn from_source_unit(unit: pt::SourceUnit) -> Self {
        let mut parsed = ParsedUnit::default();
        for part in &unit.0 {
            match part {
                pt::SourceUnitPart::ContractDefinition(def) => {
                    parsed.contracts.push(ContractDef::from_pt(def));
                }
                pt::SourceUnitPart::PragmaDirective(pragma) => {
                    parsed.pragma = Some(format!("{:?}", pragma));
                }
                pt::SourceUnitPart::ImportDirective(import) => {
                    let path = match import {
                        pt::Import::Plain(path, _) | pt::Import::GlobalSymbol(path, _, _) => {
                            format!("{:?}", path)
                        }
                        pt::Import::Rename(path, _, _) => format!("{:?}", path),
                    };
                    parsed.imports.push(path);
                }
                _ => {}
            }
        }
        parsed
    }
}

impl ContractDef {
    pub fn from_pt(def: &pt::ContractDefinition) -> Self {
        let mut contract = ContractDef {
            name: def
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            kind: match def.ty {
                pt::ContractTy::Contract(_) => ContractKind::Contract,
                pt::ContractTy::Interface(_) => ContractKind::Interface,
                pt::ContractTy::Library(_) => ContractKind::Library,
                pt::ContractTy::Abstract(_) => ContractKind::Abstract,
            },
            line: def.loc.offset(),
            ..Default::default()
        };

        // Base contracts
        for base in &def.base {
            contract.base_contracts.push(
                base.name
                    .identifiers
                    .last()
                    .map(|i| i.name.clone())
                    .unwrap_or_default(),
            );
        }

        // Parts
        for part in &def.parts {
            match part {
                pt::ContractPart::FunctionDefinition(func) => {
                    contract.functions.push(FunctionDef::from_pt(func));
                }
                pt::ContractPart::VariableDefinition(var) => {
                    contract.state_vars.push(StateVar::from_pt(var));
                }
                pt::ContractPart::EventDefinition(ev) => {
                    contract.events.push(EventDef::from_pt(ev));
                }
                pt::ContractPart::ErrorDefinition(err) => {
                    contract.errors.push(ErrorDef::from_pt(err));
                }
                _ => {}
            }
        }

        contract
    }
}

impl FunctionDef {
    pub fn from_pt(func: &pt::FunctionDefinition) -> Self {
        let name = match &func.ty {
            pt::FunctionTy::Function | pt::FunctionTy::Fallback | pt::FunctionTy::Receive => func
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            pt::FunctionTy::Constructor => "constructor".to_string(),
            pt::FunctionTy::Modifier => func
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
        };

        let mut visibility = Visibility::Internal;
        let mut mutability = Mutability::Mutable;
        let mut modifiers = Vec::new();

        for attr in &func.attributes {
            match attr {
                pt::FunctionAttribute::Visibility(v) => {
                    visibility = match v {
                        pt::Visibility::Internal(_) => Visibility::Internal,
                        pt::Visibility::External(_) => Visibility::External,
                        pt::Visibility::Public(_) => Visibility::Public,
                        pt::Visibility::Private(_) => Visibility::Private,
                    };
                }
                pt::FunctionAttribute::Mutability(m) => {
                    mutability = match m {
                        pt::Mutability::View(_) => Mutability::View,
                        pt::Mutability::Pure(_) => Mutability::Pure,
                        pt::Mutability::Payable(_) => Mutability::Payable,
                        pt::Mutability::Constant(_) => Mutability::View,
                    };
                }
                pt::FunctionAttribute::BaseOrModifier(_, base) => {
                    modifiers.push(
                        base.name
                            .identifiers
                            .last()
                            .map(|i| i.name.clone())
                            .unwrap_or_default(),
                    );
                }
                _ => {}
            }
        }

        let params = func
            .params
            .iter()
            .filter_map(|(_, p)| p.as_ref().map(Param::from_pt))
            .collect();
        let returns = func
            .returns
            .iter()
            .filter_map(|(_, p)| p.as_ref().map(Param::from_pt))
            .collect();

        FunctionDef {
            name,
            visibility,
            mutability,
            modifiers,
            params,
            returns,
            line: func.loc.offset(),
            is_virtual: func
                .attributes
                .iter()
                .any(|a| matches!(a, pt::FunctionAttribute::Virtual(_))),
            is_override: func
                .attributes
                .iter()
                .any(|a| matches!(a, pt::FunctionAttribute::Override(_, _))),
            ..Default::default()
        }
    }
}

impl StateVar {
    pub fn from_pt(var: &pt::VariableDefinition) -> Self {
        let mut visibility = Visibility::Internal;
        let mut mutability = None;

        for attr in &var.attrs {
            match attr {
                pt::VariableAttribute::Visibility(v) => {
                    visibility = match v {
                        pt::Visibility::Internal(_) => Visibility::Internal,
                        pt::Visibility::External(_) => Visibility::External,
                        pt::Visibility::Public(_) => Visibility::Public,
                        pt::Visibility::Private(_) => Visibility::Private,
                    };
                }
                pt::VariableAttribute::Constant(_) => {
                    mutability = Some(Mutability::View);
                }
                pt::VariableAttribute::Immutable(_) => {
                    mutability = Some(Mutability::View);
                }
                pt::VariableAttribute::Override(_, _) => {}
                pt::VariableAttribute::StorageType(_) => {}
            }
        }

        StateVar {
            name: var
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            ty: format!("{:?}", var.ty),
            visibility,
            mutability,
            initial_value: var.initializer.as_ref().map(|e| format!("{:?}", e)),
            line: var.loc.offset(),
        }
    }
}

impl EventDef {
    pub fn from_pt(ev: &pt::EventDefinition) -> Self {
        EventDef {
            name: ev.name.as_ref().map(|n| n.name.clone()).unwrap_or_default(),
            params: ev.fields.iter().map(Param::from_event_field).collect(),
            line: ev.loc.offset(),
        }
    }
}

impl ErrorDef {
    pub fn from_pt(err: &pt::ErrorDefinition) -> Self {
        ErrorDef {
            name: err
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            params: err.fields.iter().map(Param::from_error_param).collect(),
            line: err.loc.offset(),
        }
    }
}

impl Param {
    pub fn from_pt(param: &pt::Parameter) -> Self {
        Param {
            name: param
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            ty: format!("{:?}", param.ty),
            data_location: param.storage.as_ref().map(|l| format!("{:?}", l)),
            line: param.loc.offset(),
        }
    }

    pub fn from_event_field(field: &pt::EventParameter) -> Self {
        Param {
            name: field
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            ty: format!("{:?}", field.ty),
            data_location: None,
            line: field.loc.offset(),
        }
    }

    pub fn from_error_param(field: &pt::ErrorParameter) -> Self {
        Param {
            name: field
                .name
                .as_ref()
                .map(|n| n.name.clone())
                .unwrap_or_default(),
            ty: format!("{:?}", field.ty),
            data_location: None,
            line: field.loc.offset(),
        }
    }
}

/// Helper to get start offset from a pt::Loc.
pub trait LocExt {
    fn offset(&self) -> usize;
}

impl LocExt for solang_parser::pt::Loc {
    fn offset(&self) -> usize {
        match self {
            pt::Loc::File(_, start, _) => *start,
            _ => 0,
        }
    }
}
