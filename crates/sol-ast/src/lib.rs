pub mod ast;
pub mod extract;
pub mod visitor;

pub use ast::*;
pub use extract::*;
pub use visitor::*;

use solang_parser::pt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("parse failed: {0}")]
    Solang(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parse a Solidity source string into our internal AST representation.
pub fn parse_source(source: &str) -> Result<ParsedUnit, ParseError> {
    let source_unit = solang_parser::parse(source, 0)
        .map_err(|diags| {
            let msg = diags
                .iter()
                .map(|d| format!("{:?}", d))
                .collect::<Vec<_>>()
                .join("; ");
            ParseError::Solang(msg)
        })?
        .0;

    Ok(ParsedUnit::from_source_unit(source_unit))
}

/// Parse a Solidity file into our internal AST representation.
pub fn parse_file(path: &std::path::Path) -> Result<ParsedUnit, ParseError> {
    let source = std::fs::read_to_string(path)?;
    parse_source(&source)
}
