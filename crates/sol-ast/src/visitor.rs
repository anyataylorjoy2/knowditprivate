use solang_parser::pt;

/// A visitor trait for traversing Solidity AST nodes.
pub trait AstVisitor {
    fn visit_source_unit(&mut self, unit: &pt::SourceUnit) {
        for part in &unit.0 {
            self.visit_source_unit_part(part);
        }
    }

    fn visit_source_unit_part(&mut self, part: &pt::SourceUnitPart) {
        match part {
            pt::SourceUnitPart::ContractDefinition(def) => self.visit_contract(def),
            _ => {}
        }
    }

    fn visit_contract(&mut self, def: &pt::ContractDefinition) {
        for part in &def.parts {
            match part {
                pt::ContractPart::FunctionDefinition(func) => self.visit_function(func),
                pt::ContractPart::VariableDefinition(var) => self.visit_state_var(var),
                _ => {}
            }
        }
    }

    fn visit_function(&mut self, _func: &pt::FunctionDefinition) {}
    fn visit_state_var(&mut self, _var: &pt::VariableDefinition) {}
}
