//! Multi-provider LLM client (OpenAI / Anthropic / Ollama / OpenRouter).
//!
//! Returns clean assistant text, properly parsed from each provider's response shape.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: LlmProvider,
    pub api_key: String,
    pub model: String,
    pub base_url: String,
    pub max_tokens: u32,
    pub temperature: f32,
    /// Optional system prompt prefixed to every request.
    #[serde(default)]
    pub system_prompt: Option<String>,
}

impl LlmConfig {
    /// Build from environment variables. Returns None if no provider is configured.
    pub fn from_env() -> Option<Self> {
        let provider = std::env::var("SOL_AGENT_LLM_PROVIDER")
            .ok()
            .and_then(|s| LlmProvider::parse(&s))?;
        let api_key = std::env::var("SOL_AGENT_LLM_API_KEY").unwrap_or_default();
        let model = std::env::var("SOL_AGENT_LLM_MODEL").ok()?;
        let base_url = std::env::var("SOL_AGENT_LLM_BASE_URL")
            .unwrap_or_else(|_| provider.default_base_url().to_string());
        let max_tokens = std::env::var("SOL_AGENT_LLM_MAX_TOKENS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024);
        let temperature = std::env::var("SOL_AGENT_LLM_TEMPERATURE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.2);
        Some(Self {
            provider,
            api_key,
            model,
            base_url,
            max_tokens,
            temperature,
            system_prompt: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
    Ollama,
    OpenRouter,
    Codex,
}

impl LlmProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "openai" | "open-ai" => Some(Self::OpenAi),
            "anthropic" | "claude" => Some(Self::Anthropic),
            "ollama" | "local" => Some(Self::Ollama),
            "openrouter" => Some(Self::OpenRouter),
            "codex" | "api-x" => Some(Self::Codex),
            _ => None,
        }
    }

    pub fn default_base_url(&self) -> &'static str {
        match self {
            Self::OpenAi => "https://api.openai.com",
            Self::Anthropic => "https://api.anthropic.com",
            Self::Ollama => "http://localhost:11434",
            Self::OpenRouter => "https://openrouter.ai/api",
            Self::Codex => "http://127.0.0.1:8000",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("LLM API error: status={status} body={body}")]
    ApiError { status: u16, body: String },
    #[error("Missing content in LLM response")]
    MissingContent,
    #[error("LLM is disabled (no API key/model configured)")]
    Disabled,
}

#[derive(Clone)]
pub struct LlmClient {
    pub config: LlmConfig,
    pub http: reqwest::Client,
}

impl LlmClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client build"),
            config,
        }
    }

    /// Returns true if the client appears to be properly configured.
    pub fn is_enabled(&self) -> bool {
        !self.config.model.is_empty()
            && match self.config.provider {
                LlmProvider::Ollama | LlmProvider::Codex => true, // Ollama and Codex don't need API key
                _ => !self.config.api_key.is_empty(),
            }
    }

    /// Single-shot completion. Returns clean assistant text.
    pub async fn complete(&self, prompt: &str) -> Result<String, LlmError> {
        if !self.is_enabled() {
            return Err(LlmError::Disabled);
        }
        match self.config.provider {
            LlmProvider::OpenAi | LlmProvider::OpenRouter | LlmProvider::Codex => {
                self.openai_compatible_complete(prompt).await
            }
            LlmProvider::Anthropic => self.anthropic_complete(prompt).await,
            LlmProvider::Ollama => self.ollama_complete(prompt).await,
        }
    }

    /// Chat-style completion. Useful when the caller wants explicit system + user content.
    pub async fn chat(&self, system: Option<&str>, user: &str) -> Result<String, LlmError> {
        if !self.is_enabled() {
            return Err(LlmError::Disabled);
        }
        match self.config.provider {
            LlmProvider::OpenAi | LlmProvider::OpenRouter | LlmProvider::Codex => {
                self.openai_compatible_chat(system, user).await
            }
            LlmProvider::Anthropic => self.anthropic_chat(system, user).await,
            LlmProvider::Ollama => self.ollama_chat(system, user).await,
        }
    }

    async fn openai_compatible_complete(&self, prompt: &str) -> Result<String, LlmError> {
        self.openai_compatible_chat(self.config.system_prompt.as_deref(), prompt)
            .await
    }

    async fn openai_compatible_chat(
        &self,
        system: Option<&str>,
        user: &str,
    ) -> Result<String, LlmError> {
        // Allow override for harness synthesis which needs more tokens
        let max_tokens = if std::env::var("HARNESS_SYNTHESIS").is_ok() {
            std::env::var("SOL_AGENT_LLM_MAX_TOKENS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1536) // Harness needs more tokens than spec
        } else {
            self.config.max_tokens
        };
        #[derive(Serialize)]
        struct ChatRequest<'a> {
            model: &'a str,
            messages: Vec<Message<'a>>,
            max_tokens: u32,
            temperature: f32,
        }
        #[derive(Serialize)]
        struct Message<'a> {
            role: &'a str,
            content: &'a str,
        }

        let mut messages = Vec::with_capacity(2);
        if let Some(sys) = system {
            messages.push(Message {
                role: "system",
                content: sys,
            });
        }
        messages.push(Message {
            role: "user",
            content: user,
        });

        let url = format!("{}/v1/chat/completions", self.config.base_url);
        let res = self
            .http
            .post(&url)
            .bearer_auth(&self.config.api_key)
            .json(&ChatRequest {
                model: &self.config.model,
                messages,
                max_tokens,
                temperature: self.config.temperature,
            })
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                body: text,
            });
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        v.pointer("/choices/0/message/content")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or(LlmError::MissingContent)
    }

    async fn anthropic_complete(&self, prompt: &str) -> Result<String, LlmError> {
        self.anthropic_chat(self.config.system_prompt.as_deref(), prompt)
            .await
    }

    async fn anthropic_chat(&self, system: Option<&str>, user: &str) -> Result<String, LlmError> {
        #[derive(Serialize)]
        struct Request<'a> {
            model: &'a str,
            max_tokens: u32,
            temperature: f32,
            #[serde(skip_serializing_if = "Option::is_none")]
            system: Option<&'a str>,
            messages: Vec<Message<'a>>,
        }
        #[derive(Serialize)]
        struct Message<'a> {
            role: &'a str,
            content: &'a str,
        }

        let url = format!("{}/v1/messages", self.config.base_url);
        let res = self
            .http
            .post(&url)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&Request {
                model: &self.config.model,
                max_tokens: self.config.max_tokens,
                temperature: self.config.temperature,
                system,
                messages: vec![Message {
                    role: "user",
                    content: user,
                }],
            })
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                body: text,
            });
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        // Anthropic returns { content: [ { type: "text", text: "..." }, ... ] }
        v.pointer("/content/0/text")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or(LlmError::MissingContent)
    }

    async fn ollama_complete(&self, prompt: &str) -> Result<String, LlmError> {
        self.ollama_chat(self.config.system_prompt.as_deref(), prompt)
            .await
    }

    async fn ollama_chat(&self, system: Option<&str>, user: &str) -> Result<String, LlmError> {
        #[derive(Serialize)]
        struct Request<'a> {
            model: &'a str,
            messages: Vec<Message<'a>>,
            stream: bool,
            options: Options,
        }
        #[derive(Serialize)]
        struct Message<'a> {
            role: &'a str,
            content: &'a str,
        }
        #[derive(Serialize)]
        struct Options {
            num_predict: u32,
            temperature: f32,
        }

        let mut messages = Vec::with_capacity(2);
        if let Some(sys) = system {
            messages.push(Message {
                role: "system",
                content: sys,
            });
        }
        messages.push(Message {
            role: "user",
            content: user,
        });

        let url = format!("{}/api/chat", self.config.base_url);
        let res = self
            .http
            .post(&url)
            .json(&Request {
                model: &self.config.model,
                messages,
                stream: false,
                options: Options {
                    num_predict: self.config.max_tokens,
                    temperature: self.config.temperature,
                },
            })
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(LlmError::ApiError {
                status: status.as_u16(),
                body: text,
            });
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        // Ollama returns { message: { content: "..." } }
        v.pointer("/message/content")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or(LlmError::MissingContent)
    }
}
