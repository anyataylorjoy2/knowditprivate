use crate::ast::*;
use solang_parser::helpers::CodeLocation;
use solang_parser::pt;

/// Extract all external calls from a function's statement list.
pub fn extract_external_calls(stmts: &[pt::Statement]) -> Vec<ExternalCall> {
    let mut calls = Vec::new();
    for stmt in stmts {
        extract_from_statement(stmt, &mut calls);
    }
    calls
}

fn extract_from_statement(stmt: &pt::Statement, calls: &mut Vec<ExternalCall>) {
    match stmt {
        pt::Statement::Expression(_, expr)
        | pt::Statement::Emit(_, expr)
        | pt::Statement::VariableDefinition(_, _, Some(expr)) => {
            extract_from_expr(expr, calls);
        }
        pt::Statement::Return(_, Some(expr)) => {
            extract_from_expr(expr, calls);
        }
        pt::Statement::If(_, _, then_stmt, else_stmt) => {
            extract_from_statement(then_stmt, calls);
            if let Some(else_stmt) = else_stmt {
                extract_from_statement(else_stmt, calls);
            }
        }
        pt::Statement::While(_, _, body) | pt::Statement::DoWhile(_, body, _) => {
            extract_from_statement(body, calls);
        }
        pt::Statement::For(_, init, cond, post, body) => {
            if let Some(init) = init {
                extract_from_statement(init, calls);
            }
            if let Some(cond) = cond {
                extract_from_expr(cond, calls);
            }
            if let Some(post) = post {
                extract_from_expr(post, calls);
            }
            if let Some(body) = body {
                extract_from_statement(body, calls);
            }
        }
        pt::Statement::Block { statements, .. } => {
            for s in statements {
                extract_from_statement(s, calls);
            }
        }
        pt::Statement::Try(_, _, _, catch_clauses) => {
            for catch in catch_clauses {
                match catch {
                    pt::CatchClause::Simple(_, _, stmt) | pt::CatchClause::Named(_, _, _, stmt) => {
                        extract_from_statement(stmt, calls);
                    }
                }
            }
        }
        _ => {}
    }
}

fn extract_from_expr(expr: &pt::Expression, calls: &mut Vec<ExternalCall>) {
    match expr {
        pt::Expression::FunctionCall(_, func, args) => {
            let (target_str, is_delegate, is_static) = analyze_call_target(func);
            let is_value = target_str.contains("value")
                || target_str.contains("send")
                || target_str.contains("transfer")
                || target_str.contains("call");

            calls.push(ExternalCall {
                target: target_str,
                is_value_transfer: is_value,
                is_delegatecall: is_delegate,
                is_staticcall: is_static,
                line: expr.loc().offset(),
            });

            for arg in args {
                extract_from_expr(arg, calls);
            }
        }
        pt::Expression::NamedFunctionCall(_, func, args) => {
            let s = format!("{:?}", func);
            calls.push(ExternalCall {
                target: s.clone(),
                is_value_transfer: s.contains("value") || s.contains("send"),
                is_delegatecall: s.contains("delegatecall"),
                is_staticcall: s.contains("staticcall"),
                line: expr.loc().offset(),
            });
            for arg in args {
                extract_from_expr(&arg.expr, calls);
            }
        }
        pt::Expression::MemberAccess(_, base, _) => {
            extract_from_expr(base, calls);
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
            extract_from_expr(lhs, calls);
            extract_from_expr(rhs, calls);
        }
        pt::Expression::ConditionalOperator(_, cond, then_expr, else_expr) => {
            extract_from_expr(cond, calls);
            extract_from_expr(then_expr, calls);
            extract_from_expr(else_expr, calls);
        }
        pt::Expression::ArraySubscript(_, base, index) => {
            extract_from_expr(base, calls);
            if let Some(index) = index {
                extract_from_expr(index, calls);
            }
        }
        pt::Expression::ArraySlice(_, base, start, end) => {
            extract_from_expr(base, calls);
            if let Some(start) = start {
                extract_from_expr(start, calls);
            }
            if let Some(end) = end {
                extract_from_expr(end, calls);
            }
        }
        pt::Expression::New(_, expr) => {
            extract_from_expr(expr, calls);
        }
        pt::Expression::List(_, _) => {}
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
            extract_from_expr(expr, calls);
        }
        _ => {}
    }
}

fn analyze_call_target(func: &pt::Expression) -> (String, bool, bool) {
    let s = format!("{:?}", func);
    let is_delegate = s.contains("delegatecall");
    let is_static = s.contains("staticcall");
    (s, is_delegate, is_static)
}

/// Extract modifier names from a function definition.
pub fn extract_modifiers(func: &pt::FunctionDefinition) -> Vec<String> {
    func.attributes
        .iter()
        .filter_map(|attr| {
            if let pt::FunctionAttribute::BaseOrModifier(_, base) = attr {
                Some(
                    base.name
                        .identifiers
                        .last()
                        .map(|i| i.name.clone())
                        .unwrap_or_default(),
                )
            } else {
                None
            }
        })
        .collect()
}

/// Check if a function body contains any state variable assignment.
pub fn has_state_mutation(stmts: &[pt::Statement]) -> bool {
    stmts.iter().any(|stmt| match stmt {
        pt::Statement::Expression(_, pt::Expression::Assign(_, lhs, _)) => is_state_access(lhs),
        pt::Statement::VariableDefinition(_, _, Some(pt::Expression::Assign(_, lhs, _))) => {
            is_state_access(lhs)
        }
        _ => false,
    })
}

fn is_state_access(expr: &pt::Expression) -> bool {
    matches!(expr, pt::Expression::Variable(pt::Identifier { .. }))
}
