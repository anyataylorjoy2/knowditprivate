use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use orchestrator::fallback::StaticFirstPass;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "sol-agent")]
#[command(about = "Agentic smart contract vulnerability detection (Knowdit-style)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Minimum confidence threshold (0.0 - 1.0)
    #[arg(short, long, global = true, default_value = "0.5")]
    confidence: f64,
}

#[derive(Subcommand)]
enum Commands {
    /// Static-only first-pass on a Solidity file or directory.
    Analyze {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Knowledge Mapper only — extract DeFi semantics and query Knowdit KG.
    /// Useful for testing the mapper without running the full pipeline.
    Mapper {
        /// Path to project root.
        path: PathBuf,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Skip cache; force fresh queries.
        #[arg(long)]
        no_cache: bool,
        /// Max semantic-vulnerability pairs to keep.
        #[arg(long, default_value = "30")]
        max_pairs: usize,
    },
    /// Full Knowdit agentic pipeline (Mapper -> Spec -> Harness -> Fuzz -> Reflector).
    Audit {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Max semantic-vulnerability pairs to process.
        #[arg(long, default_value = "10")]
        max_pairs: usize,
        /// Skip the mapper phase and load business + semantics + pairs from
        /// a previously generated `sol-agent mapper --output mapper.json`.
        /// Useful to resume after an audit was interrupted (e.g. LLM quota).
        #[arg(long)]
        from_mapper: Option<PathBuf>,
        /// Path where the orchestrator should periodically checkpoint
        /// partial findings + diagnostics. Defaults to `<output>.partial.json`
        /// if `--output` is provided. Pass an explicit path to override, or
        /// `--no-checkpoint` to disable.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Disable the per-pair (spec + harness) artifact cache. By default
        /// the cache is on so re-runs resume from disk without LLM calls.
        #[arg(long)]
        no_pair_cache: bool,
        /// Disable mid-run checkpoint writing.
        #[arg(long)]
        no_checkpoint: bool,
    },
    /// Fetch verified Solidity source code from Etherscan v2 (multichain).
    ///
    /// Reconstructs the multi-file project and writes a ready-to-build Foundry
    /// project (foundry.toml + remappings.txt + sources). Useful for auditing
    /// deployed contracts (Immunefi-style targets) without manually copying source.
    Fetch {
        /// Chain name or chain id (e.g. "eth", "1", "base", "8453", "42161").
        chain: String,
        /// Contract address (0x-prefixed).
        address: String,
        /// Output directory for the generated Foundry project.
        #[arg(short, long)]
        output: PathBuf,
        /// Allow overwriting a non-empty output directory.
        #[arg(long)]
        overwrite: bool,
        /// Skip writing metadata.json next to foundry.toml.
        #[arg(long)]
        no_metadata: bool,
        /// Etherscan API key (overrides SOL_AGENT_ETHERSCAN_API_KEY env var).
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Run benchmark against known vulnerable contracts.
    Benchmark {
        #[arg(short, long)]
        fixtures: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { path, output } => {
            analyze_command(path, output, cli.confidence).await?;
        }
        Commands::Mapper {
            path,
            output,
            no_cache,
            max_pairs,
        } => {
            mapper_command(path, output, no_cache, max_pairs).await?;
        }
        Commands::Audit {
            path,
            output,
            max_pairs,
            from_mapper,
            checkpoint,
            no_pair_cache,
            no_checkpoint,
        } => {
            audit_command(
                path,
                output,
                cli.confidence,
                max_pairs,
                from_mapper,
                checkpoint,
                no_pair_cache,
                no_checkpoint,
            )
            .await?;
        }
        Commands::Fetch {
            chain,
            address,
            output,
            overwrite,
            no_metadata,
            api_key,
        } => {
            fetch_command(chain, address, output, overwrite, no_metadata, api_key).await?;
        }
        Commands::Benchmark { fixtures } => {
            benchmark_command(fixtures).await?;
        }
    }

    Ok(())
}

async fn fetch_command(
    chain: String,
    address: String,
    output: PathBuf,
    overwrite: bool,
    no_metadata: bool,
    api_key: Option<String>,
) -> Result<()> {
    let chain = etherscan_fetcher::Chain::parse(&chain)
        .with_context(|| format!("Unknown chain: {}", chain))?;

    let api_key = api_key.or_else(|| std::env::var("SOL_AGENT_ETHERSCAN_API_KEY").ok());
    if api_key.is_none() {
        warn!(
            "No Etherscan API key configured (set --api-key or SOL_AGENT_ETHERSCAN_API_KEY). \
             Falling back to public rate limit (~1 req/sec)."
        );
    }

    info!(
        "[etherscan-fetch] chain={} ({}) address={} output={:?}",
        chain.name(),
        chain.chain_id(),
        address,
        output,
    );

    let client = etherscan_fetcher::EtherscanClient::new(api_key);
    let bundle = client
        .fetch_contract(chain, &address)
        .await
        .map_err(|e| anyhow::anyhow!("Etherscan fetch failed: {}", e))?;

    info!(
        "Reconstructed {} file(s) for primary contract '{}'",
        bundle.files.len(),
        bundle.primary_contract,
    );
    if let Some(proxy) = &bundle.proxy {
        warn!(
            "Contract is flagged as a proxy. Implementation: {} \
             (re-run `sol-agent fetch` against this address for the logic contract)",
            proxy.implementation_address
        );
    }

    let opts = etherscan_fetcher::FetchOptions {
        overwrite,
        write_metadata: !no_metadata,
    };
    let path = etherscan_fetcher::write_foundry_project(&bundle, &output, &opts)
        .map_err(|e| anyhow::anyhow!("Failed to write Foundry project: {}", e))?;

    println!("Wrote Foundry project to: {}", path.display());
    println!(
        "  primary contract: {} ({} files, solc {})",
        bundle.primary_contract,
        bundle.files.len(),
        bundle.metadata.compiler_semver,
    );
    println!("Try: cd {} && forge build", path.display());
    Ok(())
}

async fn analyze_command(
    path: PathBuf,
    output: Option<PathBuf>,
    min_confidence: f64,
) -> Result<()> {
    info!("[static-first-pass] Analyzing: {:?}", path);

    let mut files = Vec::new();
    if path.is_dir() {
        collect_sol_files(&path, &mut files)?;
    } else if path.extension().map(|e| e == "sol").unwrap_or(false) {
        files.push(path.clone());
    }

    if files.is_empty() {
        warn!("No Solidity files found in {:?}", path);
        return Ok(());
    }

    let scanner = StaticFirstPass::new(min_confidence);
    let mut all_findings = Vec::new();

    for file in &files {
        info!("Parsing: {:?}", file);
        let source = std::fs::read_to_string(file)
            .with_context(|| format!("Failed to read {}", file.display()))?;

        let (source_unit, _) = solang_parser::parse(&source, 0)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {:?}", file.display(), e))?;

        let semantics =
            semantic::extractor::extract_semantics_raw(&source_unit, &file.to_string_lossy());

        let report = scanner.analyze(&semantics);
        all_findings.extend(report.findings);
    }

    let mut report = agent_core::Report::new(path.to_string_lossy());
    report.findings = all_findings;

    let json = report.to_json()?;

    if let Some(out) = output {
        std::fs::write(&out, json)
            .with_context(|| format!("Failed to write output to {}", out.display()))?;
        info!("Report written to: {:?}", out);
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Build a Knowdit mapper from environment configuration.
///
/// LLM is required for semantic extraction. Returns Err if LLM env vars are missing.
fn build_mapper(no_cache: bool, max_pairs: Option<usize>) -> Result<knowdit_client::KnowditMapper> {
    let kn_config = knowdit_client::KnowditConfig::default();
    let knowdit_client = Arc::new(knowdit_client::KnowditClient::new(kn_config));

    let llm_config = agent_llm::LlmConfig::from_env().ok_or_else(|| {
        anyhow::anyhow!(
            "LLM is required for the Knowledge Mapper. Set SOL_AGENT_LLM_PROVIDER, \
             SOL_AGENT_LLM_API_KEY, and SOL_AGENT_LLM_MODEL environment variables. \
             Example: SOL_AGENT_LLM_PROVIDER=openai \
             SOL_AGENT_LLM_MODEL=gpt-4o-mini SOL_AGENT_LLM_API_KEY=sk-..."
        )
    })?;
    let llm_client = agent_llm::LlmClient::new(llm_config);
    let extractor: Arc<dyn knowdit_client::SemanticExtractor> =
        Arc::new(knowdit_client::LlmSemanticExtractor::new(llm_client.clone()));

    let mut mapper = knowdit_client::KnowditMapper::new(knowdit_client, extractor)
        .with_llm(llm_client);
    if no_cache {
        mapper = mapper.with_cache(None);
    }
    if let Some(n) = max_pairs {
        mapper = mapper.with_max_pairs(n);
    }
    Ok(mapper)
}

async fn mapper_command(
    path: PathBuf,
    output: Option<PathBuf>,
    no_cache: bool,
    max_pairs: usize,
) -> Result<()> {
    info!("[knowledge-mapper] Project: {:?}", path);

    let mapper = build_mapper(no_cache, Some(max_pairs))?;

    let project_str = path.to_string_lossy().to_string();
    let (business, semantics, pairs) = knowdit_client::mapper::run_and_cache(&mapper, &project_str)
        .await
        .map_err(|e| anyhow::anyhow!("Knowledge Mapper failed: {}", e))?;

    let dump = serde_json::json!({
        "project": project_str,
        "business_types": business.iter().map(|b| b.as_str()).collect::<Vec<_>>(),
        "semantics": semantics,
        "pairs": pairs,
        "summary": {
            "num_semantics": semantics.len(),
            "num_pairs": pairs.len(),
        }
    });
    let json = serde_json::to_string_pretty(&dump)?;

    if let Some(out) = output {
        std::fs::write(&out, json)
            .with_context(|| format!("Failed to write output to {}", out.display()))?;
        info!("Mapper output written to: {:?}", out);
    } else {
        println!("{}", json);
    }

    Ok(())
}

async fn audit_command(
    path: PathBuf,
    output: Option<PathBuf>,
    min_confidence: f64,
    max_pairs: usize,
    from_mapper: Option<PathBuf>,
    checkpoint: Option<PathBuf>,
    no_pair_cache: bool,
    no_checkpoint: bool,
) -> Result<()> {
    info!("[knowdit-pipeline] Auditing project: {:?}", path);

    let mapper: Arc<dyn agent_core::KnowledgeMapper> =
        Arc::new(build_mapper(false, Some(max_pairs))?);

    let llm_config = agent_llm::LlmConfig::from_env();
    let llm_client = llm_config.map(agent_llm::LlmClient::new);

    let spec_gen: Arc<dyn agent_core::SpecificationGenerator> = match &llm_client {
        Some(client) => Arc::new(spec_gen::LlmSpecGenerator::new(client.clone())),
        None => Arc::new(spec_gen::LlmSpecGenerator::default()),
    };
    let harness_synth: Arc<dyn agent_core::HarnessSynthesizer> = match &llm_client {
        Some(client) => Arc::new(harness_synth::LlmHarnessSynthesizer::new(client.clone())),
        None => Arc::new(harness_synth::LlmHarnessSynthesizer::default()),
    };
    let fuzz_exec: Arc<dyn agent_core::FuzzExecutor> = Arc::new(fuzz_exec::FoundryExecutor::new());
    let reflector: Arc<dyn agent_core::FindingReflector> = match &llm_client {
        Some(client) => {
            let scope = reflector::Code4renaScope::from_env();
            Arc::new(reflector::LlmReflector::new(Some(client.clone())).with_scope(scope))
        }
        None => Arc::new(reflector::LlmReflector::new(None)),
    };

    let config = agent_core::PipelineConfig {
        project_path: path.to_string_lossy().to_string(),
        max_pairs,
        min_confidence,
        ..Default::default()
    };

    let mut orch = orchestrator::KnowditOrchestrator::new(
        mapper,
        spec_gen,
        harness_synth,
        fuzz_exec,
        reflector,
        config,
    );

    if let Some(mapper_path) = from_mapper.as_ref() {
        let prelude = load_mapper_prelude(mapper_path).with_context(|| {
            format!(
                "Failed to load --from-mapper file: {}",
                mapper_path.display()
            )
        })?;
        info!(
            "Resuming with {} pairs / {} semantics from {}",
            prelude.2.len(),
            prelude.1.len(),
            mapper_path.display(),
        );
        orch = orch.with_mapper_prelude(prelude);
    }

    if !no_pair_cache {
        let cache = Arc::new(knowdit_client::PairArtifactCache::default_path());
        orch = orch.with_pair_artifact_cache(cache);
    }

    if !no_checkpoint {
        let chk_path = checkpoint.or_else(|| {
            output
                .as_ref()
                .map(|p| p.with_extension("partial.json"))
        });
        if let Some(p) = chk_path {
            info!("Mid-run checkpoint will be written to: {}", p.display());
            orch = orch.with_checkpoint_path(p);
        }
    }

    let report = orch
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("pipeline failed: {}", e))?;
    if report.checkpointed {
        warn!(
            "Audit aborted mid-run ({}). Partial report includes {} findings; \
             run again with --from-mapper to resume from the cached pairs.",
            report.checkpoint_reason.as_deref().unwrap_or("unknown reason"),
            report.findings.len()
        );
    }
    let json = report.to_json()?;

    if let Some(out) = output {
        std::fs::write(&out, json)
            .with_context(|| format!("Failed to write output to {}", out.display()))?;
        info!("Report written to: {:?}", out);
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Load `(business, semantics, pairs)` from a `sol-agent mapper --output` JSON file.
fn load_mapper_prelude(path: &std::path::Path) -> Result<orchestrator::MapperPrelude> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read mapper file {}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| "parse mapper JSON")?;
    let business: Vec<agent_core::BusinessType> = v
        .get("business_types")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().and_then(parse_business_type))
                .collect()
        })
        .unwrap_or_default();
    let semantics: Vec<agent_core::DefiSemantic> = serde_json::from_value(
        v.get("semantics").cloned().unwrap_or(serde_json::Value::Null),
    )
    .with_context(|| "parse semantics array")?;
    let pairs: Vec<agent_core::SemanticVulnPair> =
        serde_json::from_value(v.get("pairs").cloned().unwrap_or(serde_json::Value::Null))
            .with_context(|| "parse pairs array")?;
    if pairs.is_empty() {
        anyhow::bail!("mapper file has no pairs");
    }
    Ok((business, semantics, pairs))
}

fn parse_business_type(s: &str) -> Option<agent_core::BusinessType> {
    use agent_core::BusinessType;
    let candidates = [
        BusinessType::Lending,
        BusinessType::Dexes,
        BusinessType::Yield,
        BusinessType::Services,
        BusinessType::Derivatives,
        BusinessType::YieldAggregator,
        BusinessType::RealWorldAssets,
        BusinessType::Stablecoins,
        BusinessType::Indexes,
        BusinessType::Insurance,
        BusinessType::NftMarketplace,
        BusinessType::NftLending,
        BusinessType::CrossChain,
        BusinessType::Others,
    ];
    candidates.into_iter().find(|c| c.as_str() == s)
}

async fn benchmark_command(_fixtures: Option<PathBuf>) -> Result<()> {
    info!("Running benchmark...");
    println!("Benchmark mode not yet fully implemented. Use analyze command for now.");
    Ok(())
}

fn collect_sol_files(dir: &std::path::Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_sol_files(&path, files)?;
        } else if path.extension().map(|e| e == "sol").unwrap_or(false) {
            files.push(path);
        }
    }
    Ok(())
}
