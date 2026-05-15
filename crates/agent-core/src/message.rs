use crate::finding::Finding;
use serde::{Deserialize, Serialize};

/// Message passed between agents in the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    /// Request to analyze a set of Solidity files.
    AnalyzeRequest {
        files: Vec<String>,
        source_dir: String,
    },
    /// A batch of findings from an agent.
    FindingsBatch {
        agent: String,
        findings: Vec<Finding>,
    },
    /// Request for semantic information about a contract/function.
    SemanticQuery {
        contract: String,
        function: Option<String>,
    },
    /// Response with semantic information.
    SemanticResponse {
        contract: String,
        functions: Vec<String>,
        state_vars: Vec<String>,
        modifiers: Vec<String>,
    },
    /// Signal that an agent has completed its work.
    Completed { agent: String },
    /// Signal an error in an agent.
    Error { agent: String, error: String },
}

/// Trait for agents that can process messages.
#[async_trait::async_trait]
pub trait Agent: Send + Sync {
    fn name(&self) -> &'static str;

    async fn process(
        &self,
        msg: AgentMessage,
    ) -> Result<Vec<AgentMessage>, Box<dyn std::error::Error + Send + Sync>>;
}
