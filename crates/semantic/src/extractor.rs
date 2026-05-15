use crate::contract_semantics::*;
use sol_ast::LocExt;
use sol_ast::ast::{ContractKind, Mutability, Visibility};
use solang_parser::helpers::CodeLocation;
use solang_parser::pt;

/// Extract full semantics from a parsed Solidity unit.
pub fn extract_semantics(unit: &sol_ast::ast::ParsedUnit, file_path: &str) -> SourceSemantics {
    let mut source = SourceSemantics::new(file_path);
    for contract in &unit.contracts {
        let mut sem = ContractSemantics::from_ast(contract);
        // Enrich function semantics with external calls and state access analysis
        for func in &mut sem.functions {
            if let Some(ast_func) = contract.functions.iter().find(|f| f.name == func.name) {
                func.has_reentrancy_guard = ast_func.modifiers.iter().any(|m| {
                    m.to_lowercase().contains("nonreentrant")
                        || m.to_lowercase().contains("reentrancyguard")
                });
            }
        }
        source.add_contract(sem);
    }
    source
}

/// Extract semantics from raw solang parser output (keeps AST for body analysis).
pub fn extract_semantics_raw(source_unit: &pt::SourceUnit, file_path: &str) -> SourceSemantics {
    let mut source = SourceSemantics::new(file_path);
    for part in &source_unit.0 {
        if let pt::SourceUnitPart::ContractDefinition(def) = part {
            let contract_sem = extract_contract_semantics(def);
            source.add_contract(contract_sem);
        }
    }
    source
}

fn extract_contract_semantics(def: &pt::ContractDefinition) -> ContractSemantics {
    let kind = match def.ty {
        pt::ContractTy::Contract(_) => ContractKind::Contract,
        pt::ContractTy::Interface(_) => ContractKind::Interface,
        pt::ContractTy::Library(_) => ContractKind::Library,
        pt::ContractTy::Abstract(_) => ContractKind::Abstract,
        _ => ContractKind::Contract,
    };

    let mut contract = ContractSemantics {
        name: def
            .name
            .as_ref()
            .map(|n| n.name.clone())
            .unwrap_or_default(),
        kind,
        base_contracts: def
            .base
            .iter()
            .map(|b| {
                b.name
                    .identifiers
                    .last()
                    .map(|i| i.name.clone())
                    .unwrap_or_default()
            })
            .collect(),
        inherits_from: def
            .base
            .iter()
            .map(|b| {
                b.name
                    .identifiers
                    .last()
                    .map(|i| i.name.clone())
                    .unwrap_or_default()
            })
            .collect(),
        is_abstract: kind == ContractKind::Abstract,
        ..Default::default()
    };

    for part in &def.parts {
        match part {
            pt::ContractPart::FunctionDefinition(func) => {
                let mut func_sem = extract_function_semantics(func, &contract.name);
                if let Some(pt::Statement::Block { statements, .. }) = func.body.as_ref() {
                    func_sem.external_calls = analyze_external_calls(statements);
                    func_sem.state_writes = analyze_state_writes(statements, &contract.state_vars);
                    func_sem.state_reads = analyze_state_reads(statements, &contract.state_vars);
                    func_sem.assertions = analyze_assertions(statements);
                }
                contract.functions.push(func_sem);
            }
            pt::ContractPart::VariableDefinition(var) => {
                contract.state_vars.push(extract_state_var(var));
            }
            _ => {}
        }
    }

    contract
}

fn extract_function_semantics(
    func: &pt::FunctionDefinition,
    contract_name: &str,
) -> FunctionSemantics {
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

    let has_reentrancy_guard = modifiers.iter().any(|m| {
        m.to_lowercase().contains("nonreentrant") || m.to_lowercase().contains("reentrancyguard")
    });

    FunctionSemantics {
        name,
        contract: contract_name.to_string(),
        visibility,
        mutability,
        modifiers,
        has_reentrancy_guard,
        is_payable: mutability == Mutability::Payable,
        line: func.loc.offset(),
        ..Default::default()
    }
}

fn extract_state_var(var: &pt::VariableDefinition) -> StateVarSemantic {
    let mut visibility = Visibility::Internal;
    let mut is_immutable = false;
    let mut is_constant = false;

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
            pt::VariableAttribute::Immutable(_) => is_immutable = true,
            pt::VariableAttribute::Constant(_) => is_constant = true,
            _ => {}
        }
    }

    StateVarSemantic {
        name: var
            .name
            .as_ref()
            .map(|n| n.name.clone())
            .unwrap_or_default(),
        ty: format!("{:?}", var.ty),
        visibility,
        is_immutable,
        is_constant,
        line: var.loc.offset(),
    }
}

fn analyze_external_calls(stmts: &[pt::Statement]) -> Vec<ExternalCallSemantic> {
    let mut calls = Vec::new();
    for stmt in stmts {
        find_calls_in_stmt(stmt, &mut calls);
    }
    calls
}

fn analyze_assertions(stmts: &[pt::Statement]) -> Vec<String> {
    let mut asserts = Vec::new();
    for stmt in stmts {
        find_asserts_in_stmt(stmt, &mut asserts);
    }
    asserts
}

fn find_asserts_in_stmt(stmt: &pt::Statement, asserts: &mut Vec<String>) {
    match stmt {
        pt::Statement::Expression(_, expr)
        | pt::Statement::VariableDefinition(_, _, Some(expr)) => {
            find_asserts_in_expr(expr, asserts);
        }
        pt::Statement::Emit(_, expr) => match expr {
            pt::Expression::FunctionCall(_, _, args) => {
                for arg in args {
                    find_asserts_in_expr(arg, asserts);
                }
            }
            pt::Expression::NamedFunctionCall(_, _, args) => {
                for arg in args {
                    find_asserts_in_expr(&arg.expr, asserts);
                }
            }
            _ => find_asserts_in_expr(expr, asserts),
        },
        pt::Statement::Return(_, Some(expr)) => {
            find_asserts_in_expr(expr, asserts);
        }
        pt::Statement::If(_, _, then_stmt, else_stmt) => {
            find_asserts_in_stmt(then_stmt, asserts);
            if let Some(else_stmt) = else_stmt {
                find_asserts_in_stmt(else_stmt, asserts);
            }
        }
        pt::Statement::While(_, _, body) | pt::Statement::DoWhile(_, body, _) => {
            find_asserts_in_stmt(body, asserts);
        }
        pt::Statement::For(_, init, cond, post, body) => {
            if let Some(init) = init {
                find_asserts_in_stmt(init, asserts);
            }
            if let Some(cond) = cond {
                find_asserts_in_expr(cond, asserts);
            }
            if let Some(post) = post {
                find_asserts_in_expr(post, asserts);
            }
            if let Some(body) = body {
                find_asserts_in_stmt(body, asserts);
            }
        }
        pt::Statement::Block { statements, .. } => {
            for s in statements {
                find_asserts_in_stmt(s, asserts);
            }
        }
        pt::Statement::Try(_, _, _, catch_clauses) => {
            for catch in catch_clauses {
                match catch {
                    pt::CatchClause::Simple(_, _, stmt) | pt::CatchClause::Named(_, _, _, stmt) => {
                        find_asserts_in_stmt(stmt, asserts);
                    }
                }
            }
        }
        _ => {}
    }
}

fn find_asserts_in_expr(expr: &pt::Expression, asserts: &mut Vec<String>) {
    match expr {
        pt::Expression::FunctionCall(_, func, args) => {
            let s = format!("{:?}", func).to_lowercase();
            if s.contains("assert") || s.contains("require") {
                asserts.push(format!("{:?}", expr));
            }
            for arg in args {
                find_asserts_in_expr(arg, asserts);
            }
        }
        pt::Expression::NamedFunctionCall(_, func, args) => {
            let s = format!("{:?}", func).to_lowercase();
            if s.contains("assert") || s.contains("require") {
                asserts.push(format!("{:?}", expr));
            }
            for arg in args {
                find_asserts_in_expr(&arg.expr, asserts);
            }
        }
        pt::Expression::MemberAccess(_, base, _) => {
            find_asserts_in_expr(base, asserts);
        }
        pt::Expression::Assign(_, lhs, rhs)
        | pt::Expression::AssignOr(_, lhs, rhs)
        | pt::Expression::AssignAnd(_, lhs, rhs)
        | pt::Expression::AssignXor(_, lhs, rhs)
        | pt::Expression::AssignShiftLeft(_, lhs, rhs)
        | pt::Expression::AssignShiftRight(_, lhs, rhs)
        | pt::Expression::AssignAdd(_, lhs, rhs)
        | pt::Expression::AssignSubtract(_, lhs, rhs)
        | pt::Expression::AssignMultiply(_, lhs, rhs)
        | pt::Expression::AssignDivide(_, lhs, rhs)
        | pt::Expression::AssignModulo(_, lhs, rhs)
        | pt::Expression::Or(_, lhs, rhs)
        | pt::Expression::And(_, lhs, rhs)
        | pt::Expression::Equal(_, lhs, rhs)
        | pt::Expression::NotEqual(_, lhs, rhs)
        | pt::Expression::Less(_, lhs, rhs)
        | pt::Expression::More(_, lhs, rhs)
        | pt::Expression::LessEqual(_, lhs, rhs)
        | pt::Expression::MoreEqual(_, lhs, rhs)
        | pt::Expression::Add(_, lhs, rhs)
        | pt::Expression::Subtract(_, lhs, rhs)
        | pt::Expression::Multiply(_, lhs, rhs)
        | pt::Expression::Divide(_, lhs, rhs)
        | pt::Expression::Power(_, lhs, rhs)
        | pt::Expression::Modulo(_, lhs, rhs)
        | pt::Expression::BitwiseAnd(_, lhs, rhs)
        | pt::Expression::BitwiseOr(_, lhs, rhs)
        | pt::Expression::BitwiseXor(_, lhs, rhs)
        | pt::Expression::ShiftLeft(_, lhs, rhs)
        | pt::Expression::ShiftRight(_, lhs, rhs) => {
            find_asserts_in_expr(lhs, asserts);
            find_asserts_in_expr(rhs, asserts);
        }
        pt::Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            find_asserts_in_expr(cond, asserts);
            find_asserts_in_expr(then_expr, asserts);
            find_asserts_in_expr(else_expr, asserts);
        }
        pt::Expression::ArraySubscript(_, base, index) => {
            find_asserts_in_expr(base, asserts);
            if let Some(index) = index {
                find_asserts_in_expr(index, asserts);
            }
        }
        pt::Expression::ArraySlice(_, base, start, end) => {
            find_asserts_in_expr(base, asserts);
            if let Some(start) = start {
                find_asserts_in_expr(start, asserts);
            }
            if let Some(end) = end {
                find_asserts_in_expr(end, asserts);
            }
        }
        pt::Expression::New(_, expr) => {
            find_asserts_in_expr(expr, asserts);
        }
        pt::Expression::Parenthesis(_, expr)
        | pt::Expression::PostIncrement(_, expr)
        | pt::Expression::PostDecrement(_, expr)
        | pt::Expression::PreIncrement(_, expr)
        | pt::Expression::PreDecrement(_, expr)
        | pt::Expression::UnaryPlus(_, expr)
        | pt::Expression::Negate(_, expr)
        | pt::Expression::Not(_, expr)
        | pt::Expression::BitwiseNot(_, expr)
        | pt::Expression::Delete(_, expr) => {
            find_asserts_in_expr(expr, asserts);
        }
        _ => {}
    }
}

fn find_calls_in_stmt(stmt: &pt::Statement, calls: &mut Vec<ExternalCallSemantic>) {
    match stmt {
        pt::Statement::Expression(_, expr)
        | pt::Statement::VariableDefinition(_, _, Some(expr)) => {
            find_calls_in_expr(expr, calls);
        }
        pt::Statement::Emit(_, expr) => {
            // Event emissions are NOT external calls; only recurse into arguments
            match expr {
                pt::Expression::FunctionCall(_, _, args) => {
                    for arg in args {
                        find_calls_in_expr(arg, calls);
                    }
                }
                pt::Expression::NamedFunctionCall(_, _, args) => {
                    for arg in args {
                        find_calls_in_expr(&arg.expr, calls);
                    }
                }
                _ => find_calls_in_expr(expr, calls),
            }
        }
        pt::Statement::Return(_, Some(expr)) => {
            find_calls_in_expr(expr, calls);
        }
        pt::Statement::If(_, _, then_stmt, else_stmt) => {
            find_calls_in_stmt(then_stmt, calls);
            if let Some(else_stmt) = else_stmt {
                find_calls_in_stmt(else_stmt, calls);
            }
        }
        pt::Statement::While(_, _, body) | pt::Statement::DoWhile(_, body, _) => {
            find_calls_in_stmt(body, calls);
        }
        pt::Statement::For(_, init, cond, post, body) => {
            if let Some(init) = init {
                find_calls_in_stmt(init, calls);
            }
            if let Some(cond) = cond {
                find_calls_in_expr(cond, calls);
            }
            if let Some(post) = post {
                find_calls_in_expr(post, calls);
            }
            if let Some(body) = body {
                find_calls_in_stmt(body, calls);
            }
        }
        pt::Statement::Block { statements, .. } => {
            for s in statements {
                find_calls_in_stmt(s, calls);
            }
        }
        pt::Statement::Try(_, _, _, catch_clauses) => {
            for catch in catch_clauses {
                match catch {
                    pt::CatchClause::Simple(_, _, stmt) | pt::CatchClause::Named(_, _, _, stmt) => {
                        find_calls_in_stmt(stmt, calls);
                    }
                }
            }
        }
        _ => {}
    }
}

fn find_calls_in_expr(expr: &pt::Expression, calls: &mut Vec<ExternalCallSemantic>) {
    match expr {
        pt::Expression::FunctionCall(_, func, args) => {
            let (target_str, method_name) = extract_target(func);
            let m = method_name.to_lowercase();
            let s = format!("{:?}", func);
            calls.push(ExternalCallSemantic {
                target_expr: target_str.clone(),
                method_name,
                is_value_transfer: m == "call"
                    || m == "send"
                    || m == "transfer"
                    || m.contains("value"),
                is_delegatecall: m == "delegatecall",
                is_staticcall: m == "staticcall",
                line: expr.loc().offset(),
            });
            for arg in args {
                find_calls_in_expr(arg, calls);
            }
        }
        pt::Expression::NamedFunctionCall(_, func, args) => {
            let s = format!("{:?}", func);
            let m = s.to_lowercase();
            calls.push(ExternalCallSemantic {
                target_expr: s.clone(),
                method_name: String::new(),
                is_value_transfer: m.contains("value") || m.contains("send"),
                is_delegatecall: m.contains("delegatecall"),
                is_staticcall: m.contains("staticcall"),
                line: expr.loc().offset(),
            });
            for arg in args {
                find_calls_in_expr(&arg.expr, calls);
            }
        }
        pt::Expression::MemberAccess(_, base, _) => {
            find_calls_in_expr(base, calls);
        }
        pt::Expression::Assign(_, lhs, rhs)
        | pt::Expression::AssignOr(_, lhs, rhs)
        | pt::Expression::AssignAnd(_, lhs, rhs)
        | pt::Expression::AssignXor(_, lhs, rhs)
        | pt::Expression::AssignShiftLeft(_, lhs, rhs)
        | pt::Expression::AssignShiftRight(_, lhs, rhs)
        | pt::Expression::AssignAdd(_, lhs, rhs)
        | pt::Expression::AssignSubtract(_, lhs, rhs)
        | pt::Expression::AssignMultiply(_, lhs, rhs)
        | pt::Expression::AssignDivide(_, lhs, rhs)
        | pt::Expression::AssignModulo(_, lhs, rhs)
        | pt::Expression::Or(_, lhs, rhs)
        | pt::Expression::And(_, lhs, rhs)
        | pt::Expression::Equal(_, lhs, rhs)
        | pt::Expression::NotEqual(_, lhs, rhs)
        | pt::Expression::Less(_, lhs, rhs)
        | pt::Expression::More(_, lhs, rhs)
        | pt::Expression::LessEqual(_, lhs, rhs)
        | pt::Expression::MoreEqual(_, lhs, rhs)
        | pt::Expression::Add(_, lhs, rhs)
        | pt::Expression::Subtract(_, lhs, rhs)
        | pt::Expression::Multiply(_, lhs, rhs)
        | pt::Expression::Divide(_, lhs, rhs)
        | pt::Expression::Power(_, lhs, rhs)
        | pt::Expression::Modulo(_, lhs, rhs)
        | pt::Expression::BitwiseAnd(_, lhs, rhs)
        | pt::Expression::BitwiseOr(_, lhs, rhs)
        | pt::Expression::BitwiseXor(_, lhs, rhs)
        | pt::Expression::ShiftLeft(_, lhs, rhs)
        | pt::Expression::ShiftRight(_, lhs, rhs) => {
            find_calls_in_expr(lhs, calls);
            find_calls_in_expr(rhs, calls);
        }
        pt::Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            find_calls_in_expr(cond, calls);
            find_calls_in_expr(then_expr, calls);
            find_calls_in_expr(else_expr, calls);
        }
        pt::Expression::ArraySubscript(_, base, index) => {
            find_calls_in_expr(base, calls);
            if let Some(index) = index {
                find_calls_in_expr(index, calls);
            }
        }
        pt::Expression::ArraySlice(_, base, start, end) => {
            find_calls_in_expr(base, calls);
            if let Some(start) = start {
                find_calls_in_expr(start, calls);
            }
            if let Some(end) = end {
                find_calls_in_expr(end, calls);
            }
        }
        pt::Expression::New(_, expr) => {
            find_calls_in_expr(expr, calls);
        }
        pt::Expression::Parenthesis(_, expr)
        | pt::Expression::PostIncrement(_, expr)
        | pt::Expression::PostDecrement(_, expr)
        | pt::Expression::PreIncrement(_, expr)
        | pt::Expression::PreDecrement(_, expr)
        | pt::Expression::UnaryPlus(_, expr)
        | pt::Expression::Negate(_, expr)
        | pt::Expression::Not(_, expr)
        | pt::Expression::BitwiseNot(_, expr)
        | pt::Expression::Delete(_, expr) => {
            find_calls_in_expr(expr, calls);
        }
        _ => {}
    }
}

fn extract_target(func: &pt::Expression) -> (String, String) {
    let full = format!("{:?}", func);
    if let pt::Expression::MemberAccess(_, base, id) = func {
        let base_str = format!("{:?}", base);
        (base_str, id.name.clone())
    } else {
        (full, String::new())
    }
}

fn analyze_state_writes(stmts: &[pt::Statement], state_vars: &[StateVarSemantic]) -> Vec<String> {
    let mut writes = Vec::new();
    let var_names: Vec<_> = state_vars.iter().map(|v| v.name.as_str()).collect();
    for stmt in stmts {
        find_writes_in_stmt(stmt, &var_names, &mut writes);
    }
    writes.sort();
    writes.dedup();
    writes
}

fn find_writes_in_stmt(stmt: &pt::Statement, var_names: &[&str], writes: &mut Vec<String>) {
    match stmt {
        pt::Statement::Expression(_, pt::Expression::Assign(_, lhs, rhs)) => {
            if let pt::Expression::Variable(id) = lhs.as_ref() {
                if var_names.contains(&id.name.as_str()) {
                    writes.push(id.name.clone());
                }
            }
            find_writes_in_expr(rhs, var_names, writes);
        }
        pt::Statement::VariableDefinition(_, _, Some(expr)) => {
            find_writes_in_expr(expr, var_names, writes);
        }
        pt::Statement::If(_, _, then_stmt, else_stmt) => {
            find_writes_in_stmt(then_stmt, var_names, writes);
            if let Some(else_stmt) = else_stmt {
                find_writes_in_stmt(else_stmt, var_names, writes);
            }
        }
        pt::Statement::While(_, _, body) | pt::Statement::DoWhile(_, body, _) => {
            find_writes_in_stmt(body, var_names, writes);
        }
        pt::Statement::For(_, init, _, _, body) => {
            if let Some(init) = init {
                find_writes_in_stmt(init, var_names, writes);
            }
            if let Some(body) = body {
                find_writes_in_stmt(body, var_names, writes);
            }
        }
        pt::Statement::Block { statements, .. } => {
            for s in statements {
                find_writes_in_stmt(s, var_names, writes);
            }
        }
        pt::Statement::Try(_, _, _, catch_clauses) => {
            for catch in catch_clauses {
                match catch {
                    pt::CatchClause::Simple(_, _, stmt) | pt::CatchClause::Named(_, _, _, stmt) => {
                        find_writes_in_stmt(stmt, var_names, writes);
                    }
                }
            }
        }
        _ => {}
    }
}

fn find_writes_in_expr(expr: &pt::Expression, var_names: &[&str], writes: &mut Vec<String>) {
    match expr {
        pt::Expression::Assign(_, lhs, rhs) => {
            if let pt::Expression::Variable(id) = lhs.as_ref() {
                if var_names.contains(&id.name.as_str()) {
                    writes.push(id.name.clone());
                }
            }
            find_writes_in_expr(rhs, var_names, writes);
        }
        pt::Expression::AssignOr(_, lhs, rhs)
        | pt::Expression::AssignAnd(_, lhs, rhs)
        | pt::Expression::AssignXor(_, lhs, rhs)
        | pt::Expression::AssignShiftLeft(_, lhs, rhs)
        | pt::Expression::AssignShiftRight(_, lhs, rhs)
        | pt::Expression::AssignAdd(_, lhs, rhs)
        | pt::Expression::AssignSubtract(_, lhs, rhs)
        | pt::Expression::AssignMultiply(_, lhs, rhs)
        | pt::Expression::AssignDivide(_, lhs, rhs)
        | pt::Expression::AssignModulo(_, lhs, rhs) => {
            if let pt::Expression::Variable(id) = lhs.as_ref() {
                if var_names.contains(&id.name.as_str()) {
                    writes.push(id.name.clone());
                }
            }
            find_writes_in_expr(rhs, var_names, writes);
        }
        pt::Expression::PreIncrement(_, e)
        | pt::Expression::PostIncrement(_, e)
        | pt::Expression::PreDecrement(_, e)
        | pt::Expression::PostDecrement(_, e) => {
            if let pt::Expression::Variable(id) = e.as_ref() {
                if var_names.contains(&id.name.as_str()) {
                    writes.push(id.name.clone());
                }
            }
        }
        pt::Expression::FunctionCall(_, _, args) => {
            for arg in args {
                find_writes_in_expr(arg, var_names, writes);
            }
        }
        pt::Expression::NamedFunctionCall(_, _, args) => {
            for arg in args {
                find_writes_in_expr(&arg.expr, var_names, writes);
            }
        }
        pt::Expression::MemberAccess(_, base, _) => {
            find_writes_in_expr(base, var_names, writes);
        }
        pt::Expression::Or(_, lhs, rhs)
        | pt::Expression::And(_, lhs, rhs)
        | pt::Expression::Equal(_, lhs, rhs)
        | pt::Expression::NotEqual(_, lhs, rhs)
        | pt::Expression::Less(_, lhs, rhs)
        | pt::Expression::More(_, lhs, rhs)
        | pt::Expression::LessEqual(_, lhs, rhs)
        | pt::Expression::MoreEqual(_, lhs, rhs)
        | pt::Expression::Add(_, lhs, rhs)
        | pt::Expression::Subtract(_, lhs, rhs)
        | pt::Expression::Multiply(_, lhs, rhs)
        | pt::Expression::Divide(_, lhs, rhs)
        | pt::Expression::Power(_, lhs, rhs)
        | pt::Expression::Modulo(_, lhs, rhs)
        | pt::Expression::BitwiseAnd(_, lhs, rhs)
        | pt::Expression::BitwiseOr(_, lhs, rhs)
        | pt::Expression::BitwiseXor(_, lhs, rhs)
        | pt::Expression::ShiftLeft(_, lhs, rhs)
        | pt::Expression::ShiftRight(_, lhs, rhs) => {
            find_writes_in_expr(lhs, var_names, writes);
            find_writes_in_expr(rhs, var_names, writes);
        }
        pt::Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            find_writes_in_expr(cond, var_names, writes);
            find_writes_in_expr(then_expr, var_names, writes);
            find_writes_in_expr(else_expr, var_names, writes);
        }
        pt::Expression::ArraySubscript(_, base, index) => {
            find_writes_in_expr(base, var_names, writes);
            if let Some(index) = index {
                find_writes_in_expr(index, var_names, writes);
            }
        }
        pt::Expression::ArraySlice(_, base, start, end) => {
            find_writes_in_expr(base, var_names, writes);
            if let Some(start) = start {
                find_writes_in_expr(start, var_names, writes);
            }
            if let Some(end) = end {
                find_writes_in_expr(end, var_names, writes);
            }
        }
        pt::Expression::New(_, expr) => {
            find_writes_in_expr(expr, var_names, writes);
        }
        pt::Expression::Parenthesis(_, expr)
        | pt::Expression::UnaryPlus(_, expr)
        | pt::Expression::Negate(_, expr)
        | pt::Expression::Not(_, expr)
        | pt::Expression::BitwiseNot(_, expr)
        | pt::Expression::Delete(_, expr) => {
            find_writes_in_expr(expr, var_names, writes);
        }
        _ => {}
    }
}

fn analyze_state_reads(stmts: &[pt::Statement], state_vars: &[StateVarSemantic]) -> Vec<String> {
    let mut reads = Vec::new();
    let var_names: Vec<_> = state_vars.iter().map(|v| v.name.as_str()).collect();
    for stmt in stmts {
        find_reads_in_stmt(stmt, &var_names, &mut reads);
    }
    reads.sort();
    reads.dedup();
    reads
}

fn find_reads_in_stmt(stmt: &pt::Statement, var_names: &[&str], reads: &mut Vec<String>) {
    match stmt {
        pt::Statement::Expression(_, expr)
        | pt::Statement::Emit(_, expr)
        | pt::Statement::VariableDefinition(_, _, Some(expr)) => {
            find_reads_in_expr(expr, var_names, reads);
        }
        pt::Statement::Return(_, Some(expr)) => {
            find_reads_in_expr(expr, var_names, reads);
        }
        pt::Statement::If(_, cond, then_stmt, else_stmt) => {
            find_reads_in_expr(cond, var_names, reads);
            find_reads_in_stmt(then_stmt, var_names, reads);
            if let Some(else_stmt) = else_stmt {
                find_reads_in_stmt(else_stmt, var_names, reads);
            }
        }
        pt::Statement::While(_, cond, body) => {
            find_reads_in_expr(cond, var_names, reads);
            find_reads_in_stmt(body, var_names, reads);
        }
        pt::Statement::DoWhile(_, body, cond) => {
            find_reads_in_expr(cond, var_names, reads);
            find_reads_in_stmt(body, var_names, reads);
        }
        pt::Statement::For(_, init, cond, post, body) => {
            if let Some(init) = init {
                find_reads_in_stmt(init, var_names, reads);
            }
            if let Some(cond) = cond {
                find_reads_in_expr(cond, var_names, reads);
            }
            if let Some(post) = post {
                find_reads_in_expr(post, var_names, reads);
            }
            if let Some(body) = body {
                find_reads_in_stmt(body, var_names, reads);
            }
        }
        pt::Statement::Block { statements, .. } => {
            for s in statements {
                find_reads_in_stmt(s, var_names, reads);
            }
        }
        pt::Statement::Try(_, _, _, catch_clauses) => {
            for catch in catch_clauses {
                match catch {
                    pt::CatchClause::Simple(_, _, stmt) | pt::CatchClause::Named(_, _, _, stmt) => {
                        find_reads_in_stmt(stmt, var_names, reads);
                    }
                }
            }
        }
        _ => {}
    }
}

fn find_reads_in_expr(expr: &pt::Expression, var_names: &[&str], reads: &mut Vec<String>) {
    match expr {
        pt::Expression::Variable(id) => {
            if var_names.contains(&id.name.as_str()) {
                reads.push(id.name.clone());
            }
        }
        pt::Expression::FunctionCall(_, _, args) => {
            for arg in args {
                find_reads_in_expr(arg, var_names, reads);
            }
        }
        pt::Expression::NamedFunctionCall(_, _, args) => {
            for arg in args {
                find_reads_in_expr(&arg.expr, var_names, reads);
            }
        }
        pt::Expression::MemberAccess(_, base, _) => {
            find_reads_in_expr(base, var_names, reads);
        }
        pt::Expression::Assign(_, _, rhs)
        | pt::Expression::AssignOr(_, _, rhs)
        | pt::Expression::AssignAnd(_, _, rhs)
        | pt::Expression::AssignXor(_, _, rhs)
        | pt::Expression::AssignShiftLeft(_, _, rhs)
        | pt::Expression::AssignShiftRight(_, _, rhs)
        | pt::Expression::AssignAdd(_, _, rhs)
        | pt::Expression::AssignSubtract(_, _, rhs)
        | pt::Expression::AssignMultiply(_, _, rhs)
        | pt::Expression::AssignDivide(_, _, rhs)
        | pt::Expression::AssignModulo(_, _, rhs) => {
            find_reads_in_expr(rhs, var_names, reads);
        }
        pt::Expression::Or(_, lhs, rhs)
        | pt::Expression::And(_, lhs, rhs)
        | pt::Expression::Equal(_, lhs, rhs)
        | pt::Expression::NotEqual(_, lhs, rhs)
        | pt::Expression::Less(_, lhs, rhs)
        | pt::Expression::More(_, lhs, rhs)
        | pt::Expression::LessEqual(_, lhs, rhs)
        | pt::Expression::MoreEqual(_, lhs, rhs)
        | pt::Expression::Add(_, lhs, rhs)
        | pt::Expression::Subtract(_, lhs, rhs)
        | pt::Expression::Multiply(_, lhs, rhs)
        | pt::Expression::Divide(_, lhs, rhs)
        | pt::Expression::Power(_, lhs, rhs)
        | pt::Expression::Modulo(_, lhs, rhs)
        | pt::Expression::BitwiseAnd(_, lhs, rhs)
        | pt::Expression::BitwiseOr(_, lhs, rhs)
        | pt::Expression::BitwiseXor(_, lhs, rhs)
        | pt::Expression::ShiftLeft(_, lhs, rhs)
        | pt::Expression::ShiftRight(_, lhs, rhs) => {
            find_reads_in_expr(lhs, var_names, reads);
            find_reads_in_expr(rhs, var_names, reads);
        }
        pt::Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            find_reads_in_expr(cond, var_names, reads);
            find_reads_in_expr(then_expr, var_names, reads);
            find_reads_in_expr(else_expr, var_names, reads);
        }
        pt::Expression::ArraySubscript(_, base, index) => {
            find_reads_in_expr(base, var_names, reads);
            if let Some(index) = index {
                find_reads_in_expr(index, var_names, reads);
            }
        }
        pt::Expression::ArraySlice(_, base, start, end) => {
            find_reads_in_expr(base, var_names, reads);
            if let Some(start) = start {
                find_reads_in_expr(start, var_names, reads);
            }
            if let Some(end) = end {
                find_reads_in_expr(end, var_names, reads);
            }
        }
        pt::Expression::New(_, expr) => {
            find_reads_in_expr(expr, var_names, reads);
        }
        pt::Expression::List(_, exprs) => {
            for (_, opt_param) in exprs {
                if let Some(param) = opt_param {
                    if let Some(name) = &param.name {
                        if var_names.contains(&name.name.as_str()) {
                            reads.push(name.name.clone());
                        }
                    }
                }
            }
        }
        pt::Expression::Parenthesis(_, expr)
        | pt::Expression::PostIncrement(_, expr)
        | pt::Expression::PostDecrement(_, expr)
        | pt::Expression::PreIncrement(_, expr)
        | pt::Expression::PreDecrement(_, expr)
        | pt::Expression::UnaryPlus(_, expr)
        | pt::Expression::Negate(_, expr)
        | pt::Expression::Not(_, expr)
        | pt::Expression::BitwiseNot(_, expr)
        | pt::Expression::Delete(_, expr) => {
            find_reads_in_expr(expr, var_names, reads);
        }
        _ => {}
    }
}
