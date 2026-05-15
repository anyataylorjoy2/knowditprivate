# sol-agent

Agentic smart contract vulnerability detection for personal bug bounty use on Code4rena, Sherlock, Cantina, and Immunefi.

## Goal

Tool ini dibangun untuk satu tujuan: **menghasilkan finding berkualitas bounty dengan false positive serendah mungkin**, bukan sekedar memamerkan banyak findings. Target output:

- High-severity findings yang siap di-PoC dengan Foundry
- Outcome berbasis violated invariant (bukan rule matching syntactic)
- Cocok dijadikan triage filter untuk audit manual yang lebih dalam

## Referensi Utama

**Knowdit** (arXiv:2603.26270, Kong et al., 2026) — *"Agentic Smart Contract Vulnerability Detection with Auditing Knowledge Summarization"*

Hasil paper:
- 14/14 high-severity + 77% medium-severity terdeteksi pada 12 Code4rena project
- Hanya **2 false positives** total
- 12 high + 10 medium zero-day pada 6 real-world project (saved $400M+ TVL)

Tool ini adalah implementasi Rust dari arsitektur paper, dengan satu twist: kita pakai **public Knowdit Knowledge Graph API** mereka (`https://knowdit-kg.abort.rs/solidity`) sebagai backend KG sehingga tidak perlu rebuild dari nol.

## Arsitektur

Knowdit memisahkan auditing jadi dua fase:

**Fase 1 (offline, sudah disediakan via public API):** Auditing Knowledge Graph
- DeFi Space: Solidity projects ↔ business types ↔ DeFi semantics (mekanisme ekonomi)
- Vulnerability Space: audit findings ↔ attack types ↔ vulnerability patterns
- Connection: `may introduce` antara semantic ↔ pattern

**Fase 2 (online, kita implementasi):** Multi-agent auditing loop dengan shared Working Memory

```
                                    ┌────────────────────────────────────┐
                                    │      Knowdit KG (HTTP API)         │
                                    │  https://knowdit-kg.abort.rs       │
                                    └─────────────┬──────────────────────┘
                                                  │
   ┌──────────────────┐                           │ POST /v1/query
   │ Solidity project │ ──── parse ────►          ▼
   │  /targets/*      │              ┌────────────────────────────────┐
   └──────────────────┘              │     [1] Knowledge Mapper       │
                                     │  (knowdit-client + semantic)   │
                                     │  → SemanticVulnPair[]          │
                                     └────────────────┬───────────────┘
                                                      │
                                                      ▼
                                     ┌────────────────────────────────┐
                                     │   [2] Specification Generator  │
                                     │   (LLM, spec-gen crate)        │
                                     │   → AuditSpec(initial,         │
                                     │      preVuln, postVuln states) │
                                     └────────────────┬───────────────┘
                                                      │
                                                      ▼
                                     ┌────────────────────────────────┐
                                     │   [3] Harness Synthesizer      │
                                     │   (LLM, harness-synth crate)   │
                                     │   → FuzzHarness (Foundry test) │
                                     └────────────────┬───────────────┘
                                                      │
                                                      ▼
                                     ┌────────────────────────────────┐
                                     │   [4] Fuzz Executor            │
                                     │   (fuzz-exec, forge subprocess)│
                                     │   → FuzzResult                 │
                                     └────────────────┬───────────────┘
                                                      │
                                                      ▼
                                     ┌────────────────────────────────┐
                                     │   [5] Finding Reflector        │
                                     │   (LLM, reflector crate)       │
                                     │   classify:                    │
                                     │   • Confirmed  → report        │
                                     │   • OutOfScope → drop          │
                                     │   • ExpectedBehavior → drop    │
                                     │   • Problematic → regenerate   │
                                     └────────────────┬───────────────┘
                                                      │
                                                      ▼
                                          ┌──────────────────────┐
                                          │   Working Memory     │
                                          │  (shared state,      │
                                          │   feedback, coverage)│
                                          └──────────────────────┘
```

Orchestrator (`KnowditOrchestrator`) loop ini per `SemanticVulnPair` dengan retry pada Problematic verdict.

## Status Saat Ini

Workspace **compile clean**, pipeline **end-to-end dengan LLM agents**, dan ada integration test yang membuktikan loop reflect→retry bekerja. Status komponen:

| Komponen | Crate | Status |
|----------|-------|--------|
| Solidity parser wrapper | `sol-ast` | Ready (solang-parser 0.3.5) |
| Semantic extractor | `semantic` | Ready (call graph, state writes, assertions) |
| Static first-pass | `patterns` + `verifier` + `orchestrator::fallback` | Ready (legacy heuristics, dipakai via `analyze`) |
| Knowdit API HTTP client | `knowdit-client` | Ready (session, query, pagination, rate limit) |
| Knowledge Mapper agent | `knowdit-client::mapper` | **Ready** (heuristic classifier + LLM extractor + Knowdit KG query + cache) |
| Specification Generator | `spec-gen` | **Ready** (LLM prompt → JSON AuditSpec with invariants, **multi-contract** support with source loader) |
| Harness Synthesizer | `harness-synth` | **Ready** (LLM prompt → Foundry test contract + deterministic fallback, **multi-contract** setUp) |
| Fuzz Executor | `fuzz-exec` | Ready (forge test subprocess + parser) |
| Finding Reflector | `reflector` | **Ready** (LLM nuanced verdict with deterministic fallback) |
| Orchestrator | `orchestrator` | Ready (coordinator + retry loop on Problematic) |
| Working Memory | `agent-core::pipeline` | Ready (types, multi-contract AuditSpec) |
| Etherscan Fetcher | `etherscan-fetcher` | **Ready** (v2 multichain API, 3 source formats, Foundry project gen) |
| CLI | `cli` | Ready (`analyze`, `mapper`, `audit`, `fetch`, `benchmark`) |
| Benchmark framework | `benchmark` | Ready (mapper + audit benchmark scripts) |

## Cara Pakai

### Build

```bash
cargo build --release
```

### Static-only first-pass (cheap, tanpa LLM/Foundry)

```bash
./target/release/sol-agent analyze /path/to/Contract.sol
./target/release/sol-agent analyze /path/to/Contract.sol --output report.json
```

### Knowledge Mapper only (butuh LLM)

**Opsi 1: Menggunakan Codex CLI via api-x (rekomendasi untuk local)**

```bash
# Start api-x server (di background)
api-x --host 127.0.0.1 --port 8000 --ephemeral --no-resume-last &

# Configure auditor
export SOL_AGENT_LLM_PROVIDER=codex
export SOL_AGENT_LLM_MODEL=codex-session
export SOL_AGENT_LLM_BASE_URL=http://127.0.0.1:8000

./target/release/sol-agent mapper /path/to/project
./target/release/sol-agent mapper /path/to/project --output mapper.json
```

**Opsi 2: Menggunakan OpenAI / Anthropic**

```bash
export SOL_AGENT_LLM_PROVIDER=openai
export SOL_AGENT_LLM_MODEL=gpt-4o-mini
export SOL_AGENT_LLM_API_KEY=sk-...
./target/release/sol-agent mapper /path/to/project
./target/release/sol-agent mapper /path/to/project --output mapper.json
```

### Full Knowdit agentic pipeline (butuh LLM + Foundry)

**Opsi 1: Menggunakan Codex CLI via api-x**

```bash
api-x --host 127.0.0.1 --port 8000 --ephemeral --no-resume-last &
export SOL_AGENT_LLM_PROVIDER=codex
export SOL_AGENT_LLM_MODEL=codex-session
export SOL_AGENT_LLM_BASE_URL=http://127.0.0.1:8000

./target/release/sol-agent audit /path/to/project
```

**Opsi 2: Menggunakan OpenAI / Anthropic**

```bash
export SOL_AGENT_LLM_PROVIDER=openai
export SOL_AGENT_LLM_MODEL=gpt-4o-mini
export SOL_AGENT_LLM_API_KEY=sk-...
./target/release/sol-agent audit /path/to/project
```

**Key flags:**
- `--max-pairs <N>`: Max semantic-vulnerability pairs to process (default: 10). Increase for larger projects.
- `--output <FILE>`: Write JSON report to file instead of stdout.
- `-c, --confidence <0.0-1.0>`: Minimum confidence threshold (default: 0.5).

### Fetch deployed contract from Etherscan (Immunefi workflow)

```bash
# Fetch contract source + generate Foundry project
./target/release/sol-agent fetch eth 0xContractAddress -o ./fetched-project

# With API key (or set SOL_AGENT_ETHERSCAN_API_KEY env var)
./target/release/sol-agent fetch base 0xContractAddress -o ./fetched-project --api-key YOUR_KEY

# Overwrite existing directory
./target/release/sol-agent fetch eth 0xContractAddress -o ./fetched-project --overwrite

# Then audit the fetched project
./target/release/sol-agent audit ./fetched-project --max-pairs 10
```

Supported chains: `eth`/`1`, `optimism`/`10`, `bsc`/`56`, `polygon`/`137`, `arbitrum`/`42161`, `base`/`8453`, `avalanche`/`43114`, or any chain ID.

> The pipeline will generate AuditSpecs, synthesize Foundry harnesses, run `forge test`, and reflect results into confirmed findings.

### Benchmark

```bash
./target/release/sol-agent analyze contract.sol --output report.json
./target/release/benchmark report.json benchmark/ground_truth/contract.json
# atau suite mode:
python3 benchmark/run_suite.py /tmp/contracts
```

### Code4rena Scope Rules

Untuk audit Code4rena, anda dapat mengaktifkan scope rules untuk memfilter out-of-scope findings:

```bash
# Aktifkan scope enforcement
export SOL_AGENT_ENFORCE_SCOPE=true

# Daftar contract yang out-of-scope (comma-separated)
export SOL_AGENT_OUT_OF_SCOPE_CONTRACTS=OldContract,DeprecatedContract

# Daftar function yang out-of-scope (format: Contract.function, comma-separated)
export SOL_AGENT_OUT_OF_SCOPE_FUNCTIONS=OldContract.dangerousFunction,DeprecatedContract.oldMethod

# Daftar known issues dari audit sebelumnya (comma-separated)
export SOL_AGENT_KNOWN_ISSUES="setPassword missing auth,access control bypass"

# Jalankan audit dengan scope rules aktif
./target/release/sol-agent audit /path/to/project
```

Scope rules ini akan otomatis menandai findings sebagai `OutOfScope` jika:
- Contract berada dalam daftar `SOL_AGENT_OUT_OF_SCOPE_CONTRACTS`
- Function berada dalam daftar `SOL_AGENT_OUT_OF_SCOPE_FUNCTIONS`
- Finding description mengandung pattern dari `SOL_AGENT_KNOWN_ISSUES`

Ini sesuai dengan [Code4rena judging criteria](https://docs.code4rena.com/competitions/judging-criteria) yang menentukan bahwa findings pada code/issue yang explicitly out-of-scope harus ditolak.

## Konteks Penting

### Kenapa pakai Knowdit's public API daripada bangun KG sendiri?

Knowdit paper authors sudah expose KG mereka (>1000 vulnerability links per semantic) sebagai HTTP API gratis (1 req/sec). Membangun KG sendiri butuh ratusan LLM call extraction + maintenance. Pakai API mereka:

- **$0 LLM cost** untuk KG layer
- KG yang sudah curated dari banyak audit historis
- Bisa fokus budget LLM ($50/bulan) ke 4 agent online (Spec Gen, Harness Synth, Reflector)

### Static-first-pass vs Audit pipeline

`analyze` command keeps existing pattern-based detector sebagai cheap first-pass triage. Berguna untuk:
- Skim banyak file cepat (no API/LLM cost)
- Filter project sebelum invest budget LLM via `audit`
- Sanity check baseline static rules masih jalan

`audit` command adalah primary workflow Knowdit-style begitu agent diimplementasi.

### Target Bounty Platforms

- **Code4rena/Sherlock/Cantina contests**: Foundry-ready, source available, structured findings → match perfect dengan Knowdit architecture
- **Immunefi**: deployed contracts → gunakan `sol-agent fetch` untuk auto-fetch source dari Etherscan, lalu `sol-agent audit` untuk full pipeline

### Budget Realistik

LLM budget ~$50/bulan dengan strategi tier routing:
- **Bulk tasks** (Knowledge Mapper queries, Finding Reflector): GPT-4o-mini / Claude Haiku — $0.10-0.30 per project
- **Creative tasks** (Spec Generator, Harness Synthesizer): GPT-4o / Claude Sonnet — $0.50-1.50 per project
- Per project total: ~$0.60-$2 → ~25-50 project/bulan

## Roadmap (Realistic, Solo Part-Time)

- [x] Architecture design (4-agent + WorkingMemory + retry loop)
- [x] Crate skeletons + stub agents + end-to-end compile + integration test
- [x] Static-only first-pass via `analyze` command
- [x] Knowledge Mapper full integration (heuristic classifier + LLM semantic extractor + Knowdit API queries + JSON cache)
- [x] Specification Generator LLM prompts + JSON parser
- [x] Harness Synthesizer LLM prompts + Foundry fallback scaffold
- [x] Finding Reflector LLM validation + deterministic fallback
- [x] **Mapper benchmark on 7 representative DeFi projects**: 71.43% precision, 88.24% recall, 78.95% F1 (optimal max-pairs=3)
- [x] **End-to-end audit pipeline**: Full pipeline berjalan dengan sukses pada PasswordStore (3 findings confirmed, 4.3 menit duration)
- [x] **Code4rena scope rules**: Implementasi filtering out-of-scope findings (contracts, functions, known issues)
- [x] **Multi-contract support**: AuditSpec refactor (target_contracts: Vec), source loader (BFS import graph), harness synth (multi-contract setUp)
- [x] **Etherscan fetcher**: v2 multichain API, 3 source formats, Foundry project generation, `sol-agent fetch` CLI
- [x] **Lambo.win audit benchmark**: 50% precision, 14.29% recall on 14 ground-truth findings (4H+10M). Correctly found H-01 (cashIn msg.value bug)
- [x] **Semantic diversity improvement**: Per-contract extraction + KG filtering + pair budgeting → mapper recall improved from 14.29% to 78.57% at mapper level (15 unique semantics vs 1)
- [x] **Mapper test fix**: Updated relevance assertion for `contract_name_relevance()` multiplier
- [x] **Multi-contract test backfill**: Added spec-gen source-blob wiring and harness-synth fallback deployment ordering tests; all 45 workspace tests passing
- [ ] **Full audit with improved mapper**: Re-run Lambo.win audit pipeline with diverse mapper pairs to measure audit-level recall improvement (pending Codex quota reset)
- [ ] **Prompt tuning**: Based on false positive analysis dari lebih banyak real-world audits
- [ ] **Parallel fuzzing**: Concurrent harness execution for faster audit runs

## Known Issues & Root Causes

### KG Vocabulary Matching (Paper Section 3.3.2)

**Implementation Status:** Fully implemented per paper specification (2-step LLM matching)

**Root Causes of Failures:**

1. **KG API Rate Limiting**
   - Error: "token creation limit reached for IP 20.214.152.21"
   - Impact: All KG queries failed with "Response missing token field"
   - Workaround: Pipeline fell back to coverage gap filler (synthetic pairs)
   - Frequency: Occurs during high-volume testing (multiple consecutive audits)

2. **Composite Semantic Names in KG Vocabulary**
   - Issue: KG API returns semantic names like "AMM, RFQ, Auction, Bridge-Integrated, Adapter-Based, ..."
   - Problem: These are composite descriptions, not canonical names
   - Impact: LLM matched to these but parsing failed due to commas
   - Fix: Filter KG vocabulary to exclude names containing commas
   - Result: Improved from 0/43 matched to 17/37 matched (still low)

3. **KG API Response Decoding Errors**
   - Issue: After matching, all KG queries failed with "HTTP error: error decoding response body"
   - Suspected cause: Matched names containing spaces and parentheses (e.g., "Lending Market Net Position Valuation (Lending)")
   - Attempted fix: Strip category suffix from matched names
   - Result: Still failed, KG API appeared to be having intermittent issues
   - Status: KG API recovers after rate limit resets, but stability is inconsistent

4. **Codex Quota Exhaustion (Recurring)**
   - Error: "You've hit your usage limit... try again at 7:28 AM"
   - Frequency: Occurs during audit runs after ~20-30 minutes of LLM calls
   - Impact: Pipeline cannot complete end-to-end audits
   - Root cause: High LLM call volume (~54 calls per audit: 8 for mapper + 45 for downstream)
   - Mitigation: Wait for quota reset (occurs daily at 7:28 AM UTC)

**Why Skipping Vocabulary Matching is Not Viable:**

- **Recall Impact:** Skipping vocabulary matching causes KG queries to use LLM-extracted names directly
- **Name Mismatch:** LLM-extracted names often don't match KG canonical names (e.g., "debt constrained transfers" vs "incorrect-amount-minting")
- **Zero Recall:** Without matching, KG queries return empty or irrelevant results, leading to 0% recall

**Current Trade-offs:**

- **Per Paper (Current Implementation):** High recall potential but blocked by LLM vocabulary matching failures (0/35 match rate) and Codex quota exhaustion
- **Skip Matching:** Efficient (save 1 LLM call) but causes low/zero recall due to name mismatch
- **Heuristic Matching (Not Implemented):** String similarity or embedding-based matching could be faster and more reliable than LLM, but requires additional implementation

**Recommendation:**

Consider implementing heuristic vocabulary matching using:
- String similarity (Levenshtein distance, fuzzy matching)
- Keyword extraction and overlap matching
- Sentence embedding similarity (sentence-transformers)

This would be faster than LLM calls and more reliable than the current approach, while maintaining acceptable recall rates.

## Struktur Workspace

```
crates/
├── sol-ast/             # solang-parser wrapper + LocExt
├── semantic/            # call graph, state writes, assertions
├── patterns/            # legacy SWC heuristics (cheap first-pass)
├── verifier/            # 3-layer static validation
├── knowledge/           # legacy flat finding store (deprecated, kept for compat)
├── agent-core/          # types: Finding, Report, Pipeline types, Agent traits, multi-contract AuditSpec
├── agent-llm/           # LLM client (OpenAI/Anthropic/Ollama/Codex)
├── knowdit-client/      # HTTP client to https://knowdit-kg.abort.rs + KnowledgeMapper impl
├── spec-gen/            # Specification Generator agent (multi-contract source loader + LLM prompt)
├── harness-synth/       # Harness Synthesizer agent (multi-contract setUp + Foundry fallback)
├── fuzz-exec/           # Foundry runner + result parser
├── reflector/           # Finding Reflector agent (LLM verdict + Code4rena scope)
├── etherscan-fetcher/   # Etherscan v2 multichain API client + source reconstruction + Foundry gen
├── orchestrator/        # KnowditOrchestrator + StaticFirstPass fallback
├── benchmark/           # precision/recall evaluation (mapper + audit benchmarks)
└── cli/                 # sol-agent binary (analyze | mapper | audit | fetch | benchmark)
```

## Lisensi

MIT OR Apache-2.0

> Catatan: Knowdit (paper) dilisensikan CC BY-NC-ND 4.0. Reference implementation `knowdit-kg` Rust crate dilisensikan GPL-2.0. Tool ini **tidak** depend pada GPL crate, hanya pada public HTTP API mereka — sehingga lisensi MIT/Apache tetap berlaku.
