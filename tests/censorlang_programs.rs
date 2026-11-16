//! Every CensorLang program shipped in the repository must pass the load-time
//! checks under the configuration it is shipped with.

use censorlab::config::Config;
use censorlab::program::check::ModelSignatures;
use censorlab::program::program::Program;
use std::path::PathBuf;

#[test]
fn shipped_censorlang_programs_load() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut configs = Vec::new();
    for dir in ["experiments", "demos"] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            for name in ["censor_lang.toml", "censor.toml"] {
                let path = entry.path().join(name);
                if path.is_file() {
                    configs.push(path);
                }
            }
        }
    }
    let mut loaded = 0;
    for path in configs {
        let config = Config::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if !matches!(config.execution.mode, censorlab::transport::ExecutionMode::CensorLang) {
            continue;
        }
        let script = config.execution.script.clone().expect("CensorLang config without script");
        let models: ModelSignatures = config.models.keys().map(|n| (n.clone(), None)).collect();
        Program::load(script.clone(), &config.execution.censorlang, Some(&models))
            .unwrap_or_else(|e| panic!("{}: {e}", script.display()));
        loaded += 1;
    }
    // experiments/0[1-6] each ship one
    assert!(loaded >= 6, "only {loaded} CensorLang programs found");
}
