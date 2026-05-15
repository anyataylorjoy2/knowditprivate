use crate::{HistoricalFinding, KnowledgeBase};
use std::fs;
use std::path::Path;

pub struct KnowledgeDb {
    path: String,
}

impl KnowledgeDb {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn load(&self) -> Result<KnowledgeBase, Box<dyn std::error::Error>> {
        let mut kb = KnowledgeBase::new();
        if Path::new(&self.path).exists() {
            let data = fs::read_to_string(&self.path)?;
            let findings: Vec<HistoricalFinding> = serde_json::from_str(&data)?;
            for f in findings {
                kb.add(f);
            }
        }
        Ok(kb)
    }

    pub fn save(&self, kb: &KnowledgeBase) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_string_pretty(&kb.findings)?;
        fs::write(&self.path, data)?;
        Ok(())
    }

    /// Import all JSON artifacts from a directory into a knowledge base.
    pub fn import_directory(&self, dir: &str) -> Result<KnowledgeBase, Box<dyn std::error::Error>> {
        let mut kb = self.load().unwrap_or_else(|_| KnowledgeBase::new());
        if Path::new(dir).is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    let data = fs::read_to_string(&path)?;
                    let _ = kb.import_from_json(&data);
                }
            }
        }
        Ok(kb)
    }
}
