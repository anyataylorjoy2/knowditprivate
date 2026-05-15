//! Heuristic business-type classifier.
//!
//! Avoids LLM calls for obvious projects: matches imports, base contracts,
//! function names, and state variable names against keyword tables.
//!
//! Returns a Vec<(BusinessType, score)> sorted by score descending. If the top
//! score is below a threshold, the caller should fall back to LLM classification.

use crate::project::{ProjectFile, read_concatenated};
use agent_core::BusinessType;
use std::collections::HashMap;

/// Result of heuristic classification.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub types: Vec<(BusinessType, f64)>,
    /// True if the classifier is confident; false if the caller should ask an LLM.
    pub confident: bool,
}

const CONFIDENCE_THRESHOLD: f64 = 4.0;

/// Run heuristic classification on a project, given pre-discovered files.
pub fn classify_heuristic(files: &[ProjectFile]) -> ClassificationResult {
    // Read up to 32 KB per file to keep it cheap.
    let combined = read_concatenated(files, 32 * 1024).to_lowercase();
    let mut scores: HashMap<BusinessType, f64> = HashMap::new();

    for rule in business_rules() {
        for kw in rule.keywords {
            let weight = rule.weight;
            let mut count = 0;
            let kw_lower = kw.to_lowercase();
            for _ in combined.match_indices(&kw_lower) {
                count += 1;
            }
            if count > 0 {
                *scores.entry(rule.btype).or_default() += weight * (count as f64).sqrt();
            }
        }
    }

    let mut sorted: Vec<(BusinessType, f64)> = scores.into_iter().collect();
    sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let confident = sorted
        .first()
        .map(|(_, s)| *s >= CONFIDENCE_THRESHOLD)
        .unwrap_or(false);

    ClassificationResult {
        types: sorted,
        confident,
    }
}

struct Rule {
    btype: BusinessType,
    keywords: &'static [&'static str],
    weight: f64,
}

/// Keyword tables. Conservative on weight — a single match isn't enough.
fn business_rules() -> Vec<Rule> {
    vec![
        Rule {
            btype: BusinessType::Lending,
            keywords: &[
                "borrow",
                "repay",
                "collateral",
                "liquidate",
                "lendingpool",
                "ctoken",
                "atoken",
                "comptroller",
                "vtoken",
                "debt",
                "ltv",
                "healthfactor",
                "interestratemodel",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::Dexes,
            keywords: &[
                "swap",
                "amountin",
                "amountout",
                "addliquidity",
                "removeliquidity",
                "uniswapv2",
                "uniswapv3",
                "uniswapv4",
                "curve",
                "balancer",
                "sushiswap",
                "pancakeswap",
                "reserves",
                "tickmath",
                "sqrtpricex96",
                "getreserves",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::Yield,
            keywords: &[
                "stake",
                "unstake",
                "reward",
                "rewardspershare",
                "harvest",
                "claim",
                "ratepertoken",
                "accruedrewards",
                "epoch",
                "votingescrow",
                "vebo",
                "veboost",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::Derivatives,
            keywords: &[
                "perpetual",
                "futures",
                "option",
                "synthetic",
                "leverage",
                "fundingrate",
                "perp",
                "longposition",
                "shortposition",
                "openinterest",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::YieldAggregator,
            keywords: &[
                "vault",
                "strategy",
                "shares",
                "totalassets",
                "deposit",
                "withdraw",
                "previewdeposit",
                "previewwithdraw",
                "convertToShares",
                "ierc4626",
            ],
            weight: 0.8,
        },
        Rule {
            btype: BusinessType::Stablecoins,
            keywords: &[
                "stablecoin",
                "peg",
                "rebase",
                "dai",
                "usdc",
                "usdt",
                "frax",
                "lusd",
                "minter",
                "psm",
                "savingsdai",
                "susd",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::Insurance,
            keywords: &[
                "coverage",
                "claim",
                "policy",
                "premium",
                "underwriter",
                "underwriting",
                "insurance",
                "depeg",
                "cover",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::NftMarketplace,
            keywords: &[
                "auction",
                "bid",
                "buynow",
                "listing",
                "saleorder",
                "erc721",
                "erc1155",
                "tokenid",
                "minprice",
                "highestbidder",
                "fulfillorder",
                "marketplace",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::NftLending,
            keywords: &[
                "loan",
                "borrower",
                "nftcollateral",
                "nftloan",
                "redeem",
                "foreclose",
            ],
            weight: 0.8,
        },
        Rule {
            btype: BusinessType::CrossChain,
            keywords: &[
                "bridge",
                "wormhole",
                "layerzero",
                "axelar",
                "ccip",
                "messageid",
                "remoteexecute",
                "lzendpoint",
                "interchain",
                "burnandmint",
                "lockandmint",
                "nonceused",
                "messagereceived",
            ],
            weight: 1.0,
        },
        Rule {
            btype: BusinessType::Services,
            keywords: &[
                "oracle",
                "chainlink",
                "pyth",
                "tellor",
                "automate",
                "keeper",
                "vrf",
                "randomness",
                "pricefeed",
                "updatedat",
            ],
            weight: 0.8,
        },
        Rule {
            btype: BusinessType::RealWorldAssets,
            keywords: &[
                "rwa",
                "treasurybill",
                "tbill",
                "realestate",
                "kyc",
                "regd",
                "qualifiedinvestor",
                "offchainasset",
            ],
            weight: 1.2,
        },
        Rule {
            btype: BusinessType::Indexes,
            keywords: &[
                "index",
                "basket",
                "weightedportfolio",
                "rebalance",
                "indextoken",
                "settokenset",
            ],
            weight: 1.0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_corpus_falls_through() {
        let res = classify_heuristic(&[]);
        assert!(!res.confident);
        assert!(res.types.is_empty());
    }
}
