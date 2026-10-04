//! Nightfall Node Kit self-verification primitives.
//!
//! This crate is intentionally non-consensus-active. It does not validate
//! blocks, does not parse wallet secrets, and does not mutate the datadir.
//! Its job is to produce a small, reviewable self-verification report for
//! users who want to understand whether their local setup is independently
//! verifiable and operationally safe.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warn,
    Fail,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Severity::Ok => 0,
            Severity::Warn => 1,
            Severity::Fail => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
    pub remediation: String,
}

impl Finding {
    fn new(
        code: &'static str,
        severity: Severity,
        summary: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            summary: summary.into(),
            detail: detail.into(),
            remediation: remediation.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeKitConfig {
    pub datadir: PathBuf,
    pub network: String,
    pub rpc_bind: Option<String>,
    pub strict: bool,
}

impl NodeKitConfig {
    pub fn new(datadir: impl Into<PathBuf>, network: impl Into<String>) -> Self {
        Self {
            datadir: datadir.into(),
            network: network.into(),
            rpc_bind: None,
            strict: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn worst_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max_by_key(|s| s.rank())
            .unwrap_or(Severity::Ok)
    }

    pub fn has_failures(&self) -> bool {
        self.worst_severity() == Severity::Fail
    }

    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Warn)
    }

    pub fn exit_code(&self, fail_on_warn: bool) -> i32 {
        if self.has_failures() || (fail_on_warn && self.has_warnings()) {
            2
        } else {
            0
        }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Nightfall Node Kit self-verification report\n");
        out.push_str("================================================\n");
        out.push_str(&format!("Overall: {}\n\n", self.worst_severity().as_str()));

        for finding in &self.findings {
            out.push_str(&format!(
                "[{}] {} — {}\n",
                finding.severity.as_str(),
                finding.code,
                finding.summary
            ));
            out.push_str(&format!("  detail: {}\n", finding.detail));
            out.push_str(&format!("  fix:    {}\n\n", finding.remediation));
        }

        out
    }

    pub fn to_json(&self) -> String {
        let findings = self
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"code\":\"{}\",\"severity\":\"{}\",\"summary\":\"{}\",\"detail\":\"{}\",\"remediation\":\"{}\"}}",
                    json_escape(f.code),
                    json_escape(f.severity.as_str()),
                    json_escape(&f.summary),
                    json_escape(&f.detail),
                    json_escape(&f.remediation)
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{{\"tool\":\"nightfall-node-kit\",\"overall\":\"{}\",\"findings\":[{}]}}",
            self.worst_severity().as_str(),
            findings
        )
    }
}

pub fn run_checks(config: &NodeKitConfig) -> Report {
    let mut findings = Vec::new();

    findings.push(check_network(&config.network));

    let datadir_finding = check_datadir(&config.datadir);
    let datadir_is_usable = datadir_finding.severity != Severity::Fail;
    findings.push(datadir_finding);

    findings.push(check_assumevalid_policy());
    findings.push(check_rpc_bind(config.rpc_bind.as_deref(), config.strict));

    if datadir_is_usable {
        findings.push(check_node_state_signal(&config.datadir));
        findings.push(check_wallet_backup_signal(&config.datadir));
    } else {
        findings.push(skip_node_state_signal_after_datadir_failure());
        findings.push(skip_wallet_backup_signal_after_datadir_failure());
    }

    Report { findings }
}

fn check_network(network: &str) -> Finding {
    match network {
        "mainnet" | "testnet" | "devnet" => Finding::new(
            "NK-NETWORK-OK",
            Severity::Ok,
            "recognized network selected",
            format!("network={network}"),
            "No action required.",
        ),
        other => Finding::new(
            "NK-NETWORK-UNKNOWN",
            Severity::Fail,
            "unknown network selected",
            format!("network={other} is not one of mainnet, testnet, devnet"),
            "Use --network mainnet, --network testnet, or --network devnet.",
        ),
    }
}

fn check_datadir(datadir: &Path) -> Finding {
    if !datadir.exists() {
        return Finding::new(
            "NK-DATADIR-MISSING",
            Severity::Fail,
            "datadir does not exist",
            "the configured datadir path was not found",
            "Start the node once, or pass the correct --datadir path.",
        );
    }

    if !datadir.is_dir() {
        return Finding::new(
            "NK-DATADIR-NOT-DIR",
            Severity::Fail,
            "datadir path is not a directory",
            "the configured datadir exists but is not a directory",
            "Pass a valid Nightfall datadir.",
        );
    }

    if looks_like_source_checkout(datadir) {
        return Finding::new(
            "NK-DATADIR-SOURCE-CHECKOUT",
            Severity::Fail,
            "datadir appears to be a Nightfall source checkout",
            "the path contains Cargo.toml plus Nightfall crate directories, so it is probably the repository, not node state",
            "Pass the actual node datadir instead of the source repository.",
        );
    }

    match fs::read_dir(datadir) {
        Ok(mut entries) => {
            if entries.next().is_none() {
                Finding::new(
                    "NK-DATADIR-EMPTY",
                    Severity::Warn,
                    "datadir is empty",
                    "the datadir exists but contains no visible state files",
                    "Start/sync the node before treating this setup as independently verified.",
                )
            } else {
                Finding::new(
                    "NK-DATADIR-READABLE",
                    Severity::Ok,
                    "datadir is present and readable",
                    "the datadir exists and contains files",
                    "No action required.",
                )
            }
        }
        Err(_) => Finding::new(
            "NK-DATADIR-UNREADABLE",
            Severity::Fail,
            "datadir cannot be read",
            "the process cannot list the datadir",
            "Check Android/Termux storage permissions and datadir ownership.",
        ),
    }
}

fn looks_like_source_checkout(datadir: &Path) -> bool {
    datadir.join("Cargo.toml").is_file()
        && datadir.join("crates").join("nightfall-consensus").is_dir()
        && datadir.join("crates").join("nightfall-wallet").is_dir()
}

fn check_assumevalid_policy() -> Finding {
    match env::var("NIGHTFALL_NO_ASSUME_VALID") {
        Ok(v) if v == "1" => Finding::new(
            "NK-ASSUMEVALID-DISABLED",
            Severity::Ok,
            "checkpoint trust shortcut disabled",
            "NIGHTFALL_NO_ASSUME_VALID=1 is set",
            "No action required for maximum local verification.",
        ),
        Ok(v) => Finding::new(
            "NK-ASSUMEVALID-NONSTANDARD",
            Severity::Warn,
            "checkpoint policy variable has a nonstandard value",
            format!("NIGHTFALL_NO_ASSUME_VALID is set to a nonstandard value of length {}", v.len()),
            "Set NIGHTFALL_NO_ASSUME_VALID=1 for full verification, or unset it to accept the compiled checkpoint shortcut.",
        ),
        Err(_) => Finding::new(
            "NK-ASSUMEVALID-ACTIVE",
            Severity::Warn,
            "compiled checkpoint shortcut may be active",
            "NIGHTFALL_NO_ASSUME_VALID is not set",
            "For maximum independent verification, run with NIGHTFALL_NO_ASSUME_VALID=1.",
        ),
    }
}

fn check_rpc_bind(rpc_bind: Option<&str>, strict: bool) -> Finding {
    let Some(bind) = rpc_bind else {
        return Finding::new(
            "NK-RPC-UNSPECIFIED",
            Severity::Warn,
            "RPC bind address not provided",
            "node-kit cannot determine whether RPC is loopback-only",
            "Pass --rpc-bind 127.0.0.1:17881 or the actual configured RPC bind address.",
        );
    };

    let public = bind.starts_with("0.0.0.0:")
        || bind.starts_with("[::]:")
        || bind.starts_with(":::")
        || bind == "0.0.0.0"
        || bind == "::";

    if public {
        Finding::new(
            "NK-RPC-PUBLIC-BIND",
            if strict {
                Severity::Fail
            } else {
                Severity::Warn
            },
            "RPC appears to bind publicly",
            "a public RPC bind can expose wallet/node control surface beyond localhost",
            "Bind RPC to 127.0.0.1 unless a hardened reverse proxy/firewall is deliberately used.",
        )
    } else if bind.starts_with("127.0.0.1:")
        || bind.starts_with("localhost:")
        || bind == "127.0.0.1"
    {
        Finding::new(
            "NK-RPC-LOOPBACK",
            Severity::Ok,
            "RPC appears loopback-only",
            "the supplied RPC bind address is local-only",
            "No action required.",
        )
    } else {
        Finding::new(
            "NK-RPC-CUSTOM-BIND",
            Severity::Warn,
            "RPC bind address is custom",
            "node-kit cannot prove whether this address is safely firewalled",
            "Prefer 127.0.0.1 unless this bind address is intentional and protected.",
        )
    }
}

fn skip_node_state_signal_after_datadir_failure() -> Finding {
    Finding::new(
        "NK-NODE-STATE-SKIPPED",
        Severity::Warn,
        "node-state scan skipped",
        "datadir validation failed, so node-kit did not inspect node-state signals",
        "Fix the datadir finding first, then rerun node-kit.",
    )
}

fn check_node_state_signal(datadir: &Path) -> Finding {
    let signals = collect_name_signals(datadir, 3);

    let has_node_state_signal = signals.iter().any(|name| {
        let n = name.to_ascii_lowercase();
        n == "chain-meta.json"
            || n.contains("chain-meta")
            || n.contains("compact-header")
            || n.contains("validation-record")
            || n.contains("validated")
            || n.contains("utxo")
            || n.contains("kernel")
            || n.contains("checkpoint")
            || n.contains("assumevalid")
            || n.contains("blocks")
            || n.contains("headers")
    });

    if has_node_state_signal {
        Finding::new(
            "NK-NODE-STATE-SIGNAL-PRESENT",
            Severity::Ok,
            "node-state filename signals found",
            "node-kit found Nightfall-like node-state filenames without parsing consensus data",
            "No action required.",
        )
    } else {
        Finding::new(
            "NK-NODE-STATE-NO-SIGNAL",
            Severity::Warn,
            "no node-state filename signal found",
            "the datadir is readable, but node-kit did not find common Nightfall node-state filenames",
            "Verify that this path is the actual node datadir and not a project, backup, or wallet-only directory.",
        )
    }
}

fn skip_wallet_backup_signal_after_datadir_failure() -> Finding {
    Finding::new(
        "NK-BACKUP-SKIPPED",
        Severity::Warn,
        "backup scan skipped",
        "datadir validation failed, so node-kit did not inspect backup signals",
        "Fix the datadir finding first, then rerun node-kit.",
    )
}

fn check_wallet_backup_signal(datadir: &Path) -> Finding {
    if !datadir.is_dir() {
        return Finding::new(
            "NK-BACKUP-SKIPPED",
            Severity::Warn,
            "backup scan skipped",
            "datadir is unavailable, so node-kit did not inspect backup signals",
            "Fix the datadir first, then rerun node-kit.",
        );
    }

    let signals = collect_name_signals(datadir, 3);
    let wallet_like = signals
        .iter()
        .filter(|name| {
            let n = name.to_ascii_lowercase();
            n.contains("wallet") || n.contains("vault") || n.contains("seed")
        })
        .count();

    let backup_like = signals
        .iter()
        .filter(|name| {
            let n = name.to_ascii_lowercase();
            n.contains("backup") || n.contains(".bak") || n.contains("recovery")
        })
        .count();

    match (wallet_like, backup_like) {
        (0, _) => Finding::new(
            "NK-BACKUP-NO-WALLET-SIGNAL",
            Severity::Warn,
            "no wallet/seed/vault filename signal found",
            "node-kit only inspected filenames and did not read secrets",
            "If this is a node-only datadir, no action is required; otherwise verify the wallet location.",
        ),
        (_, 0) => Finding::new(
            "NK-BACKUP-NO-BACKUP-SIGNAL",
            Severity::Warn,
            "wallet-like files found but no backup-like filename signal found",
            "node-kit did not read file contents and cannot prove backup existence",
            "Verify that seed/vault recovery material exists offline and is not only stored on this device.",
        ),
        (_, _) => Finding::new(
            "NK-BACKUP-SIGNAL-PRESENT",
            Severity::Ok,
            "wallet and backup filename signals found",
            "node-kit found wallet-like and backup-like names without reading their contents",
            "Still verify offline recovery manually before relying on the wallet.",
        ),
    }
}

fn collect_name_signals(root: &Path, max_depth: usize) -> Vec<String> {
    fn walk(path: &Path, depth: usize, max_depth: usize, out: &mut Vec<String>) {
        if depth > max_depth {
            return;
        }

        let Ok(entries) = fs::read_dir(path) else {
            return;
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            out.push(file_name);

            let child = entry.path();
            if child.is_dir() {
                walk(&child, depth + 1, max_depth, out);
            }
        }
    }

    let mut out = Vec::new();
    walk(root, 0, max_depth, &mut out);
    out
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = env::temp_dir().join(format!(
            "nightfall-node-kit-{name}-{}-{nanos}",
            std::process::id()
        ));

        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn unknown_network_fails() {
        let finding = check_network("wrongnet");
        assert_eq!(finding.severity, Severity::Fail);
        assert_eq!(finding.code, "NK-NETWORK-UNKNOWN");
    }

    #[test]
    fn missing_datadir_fails() {
        let path = env::temp_dir().join("nightfall-node-kit-definitely-missing");
        let finding = check_datadir(&path);
        assert_eq!(finding.severity, Severity::Fail);
        assert_eq!(finding.code, "NK-DATADIR-MISSING");
    }

    #[test]
    fn source_checkout_is_not_accepted_as_datadir() {
        let dir = temp_dir("source-checkout");
        fs::create_dir_all(dir.join("crates/nightfall-consensus")).unwrap();
        fs::create_dir_all(dir.join("crates/nightfall-wallet")).unwrap();
        File::create(dir.join("Cargo.toml")).unwrap();

        let finding = check_datadir(&dir);
        assert_eq!(finding.severity, Severity::Fail);
        assert_eq!(finding.code, "NK-DATADIR-SOURCE-CHECKOUT");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_rpc_warns_by_default_and_fails_in_strict_mode() {
        let warn = check_rpc_bind(Some("0.0.0.0:17881"), false);
        let fail = check_rpc_bind(Some("0.0.0.0:17881"), true);

        assert_eq!(warn.severity, Severity::Warn);
        assert_eq!(fail.severity, Severity::Fail);
    }

    #[test]
    fn loopback_rpc_is_ok() {
        let finding = check_rpc_bind(Some("127.0.0.1:17881"), false);
        assert_eq!(finding.severity, Severity::Ok);
        assert_eq!(finding.code, "NK-RPC-LOOPBACK");
    }

    #[test]
    fn backup_signal_is_filename_only() {
        let dir = temp_dir("backup-signal");
        File::create(dir.join("wallet.vault")).unwrap();
        File::create(dir.join("wallet.vault.backup")).unwrap();

        let finding = check_wallet_backup_signal(&dir);
        assert_eq!(finding.severity, Severity::Ok);
        assert_eq!(finding.code, "NK-BACKUP-SIGNAL-PRESENT");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn readable_directory_without_node_state_signal_warns() {
        let dir = temp_dir("no-node-state-signal");
        File::create(dir.join("random-note.txt")).unwrap();

        let finding = check_node_state_signal(&dir);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.code, "NK-NODE-STATE-NO-SIGNAL");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn readable_directory_with_node_state_signal_is_ok() {
        let dir = temp_dir("node-state-signal");
        File::create(dir.join("chain-meta.json")).unwrap();

        let finding = check_node_state_signal(&dir);
        assert_eq!(finding.severity, Severity::Ok);
        assert_eq!(finding.code, "NK-NODE-STATE-SIGNAL-PRESENT");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_datadir_skips_node_state_scan() {
        let dir = temp_dir("source-checkout-node-state-skip");
        fs::create_dir_all(dir.join("crates/nightfall-consensus")).unwrap();
        fs::create_dir_all(dir.join("crates/nightfall-wallet")).unwrap();
        File::create(dir.join("Cargo.toml")).unwrap();
        File::create(dir.join("chain-meta.json")).unwrap();

        let cfg = NodeKitConfig {
            datadir: dir.clone(),
            network: "mainnet".to_string(),
            rpc_bind: Some("127.0.0.1:17881".to_string()),
            strict: false,
        };

        let report = run_checks(&cfg);

        assert!(report.has_failures());
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "NK-DATADIR-SOURCE-CHECKOUT"));
        assert!(report.findings.iter().any(|f| {
            f.code == "NK-NODE-STATE-SKIPPED" && f.detail.contains("datadir validation failed")
        }));
        assert!(!report
            .findings
            .iter()
            .any(|f| f.code == "NK-NODE-STATE-SIGNAL-PRESENT"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_datadir_skips_backup_scan() {
        let dir = temp_dir("source-checkout-backup-skip");
        fs::create_dir_all(dir.join("crates/nightfall-consensus")).unwrap();
        fs::create_dir_all(dir.join("crates/nightfall-wallet")).unwrap();
        File::create(dir.join("Cargo.toml")).unwrap();
        File::create(dir.join("wallet.vault")).unwrap();
        File::create(dir.join("wallet.vault.backup")).unwrap();

        let cfg = NodeKitConfig {
            datadir: dir.clone(),
            network: "mainnet".to_string(),
            rpc_bind: Some("127.0.0.1:17881".to_string()),
            strict: false,
        };

        let report = run_checks(&cfg);

        assert!(report.has_failures());
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "NK-DATADIR-SOURCE-CHECKOUT"));
        assert!(report.findings.iter().any(|f| {
            f.code == "NK-BACKUP-SKIPPED" && f.detail.contains("datadir validation failed")
        }));
        assert!(!report
            .findings
            .iter()
            .any(|f| f.code == "NK-BACKUP-SIGNAL-PRESENT"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exit_code_can_treat_warnings_as_failures() {
        let warn_report = Report {
            findings: vec![Finding::new(
                "NK-WARN",
                Severity::Warn,
                "summary",
                "detail",
                "fix",
            )],
        };

        let fail_report = Report {
            findings: vec![Finding::new(
                "NK-FAIL",
                Severity::Fail,
                "summary",
                "detail",
                "fix",
            )],
        };

        let ok_report = Report {
            findings: vec![Finding::new(
                "NK-OK",
                Severity::Ok,
                "summary",
                "detail",
                "fix",
            )],
        };

        assert_eq!(ok_report.exit_code(false), 0);
        assert_eq!(ok_report.exit_code(true), 0);

        assert_eq!(warn_report.exit_code(false), 0);
        assert_eq!(warn_report.exit_code(true), 2);

        assert_eq!(fail_report.exit_code(false), 2);
        assert_eq!(fail_report.exit_code(true), 2);
    }

    #[test]
    fn report_json_contains_overall_status() {
        let report = Report {
            findings: vec![Finding::new(
                "NK-TEST",
                Severity::Warn,
                "summary",
                "detail",
                "fix",
            )],
        };

        let json = report.to_json();
        assert!(json.contains("\"overall\":\"WARN\""));
        assert!(json.contains("\"code\":\"NK-TEST\""));
    }

    #[test]
    fn run_checks_reports_failures_for_missing_datadir() {
        let cfg = NodeKitConfig {
            datadir: env::temp_dir().join("nightfall-node-kit-missing-run-checks"),
            network: "mainnet".to_string(),
            rpc_bind: Some("127.0.0.1:17881".to_string()),
            strict: false,
        };

        let report = run_checks(&cfg);
        assert!(report.has_failures());
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "NK-DATADIR-MISSING"));
    }
}
