use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// A directed call graph for functions within and across contracts.
pub struct CallGraph {
    pub graph: DiGraph<FunctionNode, CallEdge>,
    pub node_map: HashMap<String, NodeIndex>,
}

#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub contract: String,
    pub name: String,
    pub is_external: bool,
    pub is_payable: bool,
    pub has_reentrancy_guard: bool,
}

#[derive(Debug, Clone)]
pub struct CallEdge {
    pub is_external: bool, // true if cross-contract call
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    pub fn add_function(
        &mut self,
        contract: &str,
        name: &str,
        is_external: bool,
        is_payable: bool,
        has_reentrancy_guard: bool,
    ) -> NodeIndex {
        let key = format!("{}.{}", contract, name);
        if let Some(&idx) = self.node_map.get(&key) {
            return idx;
        }
        let idx = self.graph.add_node(FunctionNode {
            contract: contract.to_string(),
            name: name.to_string(),
            is_external,
            is_payable,
            has_reentrancy_guard,
        });
        self.node_map.insert(key, idx);
        idx
    }

    pub fn add_call(
        &mut self,
        from_contract: &str,
        from_func: &str,
        to_contract: &str,
        to_func: &str,
        is_external: bool,
    ) {
        let from_key = format!("{}.{}", from_contract, from_func);
        let to_key = format!("{}.{}", to_contract, to_func);
        let from_idx = self.node_map.get(&from_key).copied();
        let to_idx = self.node_map.get(&to_key).copied();
        if let (Some(from), Some(to)) = (from_idx, to_idx) {
            self.graph.add_edge(from, to, CallEdge { is_external });
        }
    }

    /// Find all functions reachable from a given function.
    pub fn reachable_from(&self, contract: &str, func: &str) -> Vec<&FunctionNode> {
        let key = format!("{}.{}", contract, func);
        let Some(&start) = self.node_map.get(&key) else {
            return Vec::new();
        };

        let mut reachable = Vec::new();
        let mut dfs = petgraph::visit::Dfs::new(&self.graph, start);
        while let Some(node) = dfs.next(&self.graph) {
            if node != start {
                reachable.push(self.graph.node_weight(node).unwrap());
            }
        }
        reachable
    }

    /// Find functions that call a given function (callers).
    pub fn callers_of(&self, contract: &str, func: &str) -> Vec<&FunctionNode> {
        let key = format!("{}.{}", contract, func);
        let Some(&target) = self.node_map.get(&key) else {
            return Vec::new();
        };

        let mut callers = Vec::new();
        for node in self.graph.node_indices() {
            if petgraph::algo::has_path_connecting(&self.graph, node, target, None) {
                if node != target {
                    callers.push(self.graph.node_weight(node).unwrap());
                }
            }
        }
        callers
    }

    /// Detect potential reentrancy paths: external call leading back to state-mutating function.
    pub fn reentrancy_paths(&self) -> Vec<(&FunctionNode, &FunctionNode)> {
        let mut paths = Vec::new();
        for edge in self.graph.edge_indices() {
            let (from, to) = self.graph.edge_endpoints(edge).unwrap();
            let from_node = self.graph.node_weight(from).unwrap();
            let edge_weight = self.graph.edge_weight(edge).unwrap();
            if edge_weight.is_external && !from_node.has_reentrancy_guard {
                paths.push((from_node, self.graph.node_weight(to).unwrap()));
            }
        }
        paths
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}
