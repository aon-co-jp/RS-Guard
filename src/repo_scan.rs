//! リポジトリ/依存関係の静的スキャン。
//!
//! チェックする2種類:
//! 1. `Cargo.toml`/`package.json`の依存パッケージ名を
//!    [`crate::blocklist`]と突き合わせる(既知の悪意あるパッケージ名の
//!    完全一致のみ、あいまい検索はしない——誤検知を避けるため)。
//! 2. ソースファイル・スクリプト内の疑わしいパターン(base64復号後の
//!    即時実行・`curl | bash`パイプライン・PowerShellの
//!    `-EncodedCommand`等)を正規表現で検出する。
//!
//! **正直な開示**: これは静的なパターンマッチであり、動的解析
//! (実際にコードを実行して振る舞いを見る)は行わない。難読化された
//! 悪意あるコードや、パターンに現れない新種の攻撃は検出できない。

use crate::blocklist;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// ブロックリストに載っている依存パッケージ名が見つかった。
    BlockedDependency,
    /// ソース内に疑わしいパターンが見つかった。
    SuspiciousPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file: PathBuf,
    pub kind: FindingKind,
    /// 検出内容の説明(パッケージ名、またはマッチしたパターンの種類)。
    pub detail: String,
}

/// `Cargo.toml`の`[dependencies]`等のセクションから依存名だけを雑に
/// 抜き出す(TOMLパーサへの依存を避けるため、`^name = `または
/// `^name.workspace`形式の行だけを見る簡易実装。ネストしたテーブル
/// 形式`[dependencies.foo]`もセクション見出しから拾う)。
fn extract_cargo_dep_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_deps_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps_section = trimmed.contains("dependencies");
            if let Some(rest) = trimmed.strip_prefix("[dependencies.").or_else(|| trimmed.strip_prefix("[dev-dependencies.")) {
                if let Some(name) = rest.strip_suffix(']') {
                    names.push(name.to_string());
                }
            }
            continue;
        }
        if in_deps_section {
            if let Some((name, _)) = trimmed.split_once('=') {
                let name = name.trim();
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

/// `package.json`の`dependencies`/`devDependencies`から依存名を抽出する
/// (`serde_json`でパースするので`Cargo.toml`よりは正確)。
fn extract_npm_dep_names(text: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(obj) = value.get(key).and_then(|v| v.as_object()) {
            names.extend(obj.keys().cloned());
        }
    }
    names
}

fn suspicious_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        ("curl-pipe-to-shell", Regex::new(r"curl[^\n|]*\|\s*(sh|bash|zsh)\b").unwrap()),
        ("wget-pipe-to-shell", Regex::new(r"wget[^\n|]*\|\s*(sh|bash|zsh)\b").unwrap()),
        ("base64-decode-then-exec", Regex::new(r"(base64\s+-d|atob\()[^\n]{0,80}(eval|exec|Invoke-Expression|iex\b)").unwrap()),
        ("eval-of-decoded-string", Regex::new(r"eval\s*\(\s*(atob|Buffer\.from)\(").unwrap()),
        ("powershell-encoded-command", Regex::new(r"(?i)-EncodedCommand\b").unwrap()),
        ("powershell-download-execute", Regex::new(r"(?i)(Invoke-WebRequest|iwr|curl)[^\n]{0,80}(Invoke-Expression|iex\b)").unwrap()),
        ("reverse-shell-nc", Regex::new(r"\bnc\s+-e\s+/bin/(sh|bash)\b").unwrap()),
    ]
}

/// 対象1ファイルをスキャンする(テキストとして読めない・巨大すぎる等は
/// 静かにスキップ、バイナリファイルの誤検知を避けるため)。
fn scan_file_contents(path: &Path, findings: &mut Vec<Finding>) {
    const MAX_SCAN_BYTES: u64 = 5 * 1024 * 1024;
    let Ok(meta) = std::fs::metadata(path) else { return };
    if meta.len() > MAX_SCAN_BYTES {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else { return };
    for (name, re) in suspicious_patterns() {
        if re.is_match(&text) {
            findings.push(Finding { file: path.to_path_buf(), kind: FindingKind::SuspiciousPattern, detail: name.to_string() });
        }
    }
}

/// 1プロジェクト(ディレクトリ)をスキャンする。`Cargo.toml`/`package.json`
/// の依存名チェックと、拡張子でフィルタしたソース/スクリプトファイルの
/// パターンチェックの両方を行う。
pub fn scan_project(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let npm_blocked = blocklist::npm_blocklist();
    let crates_blocked = blocklist::crates_io_blocklist();

    let scannable_exts = ["sh", "ps1", "bat", "cmd", "js", "ts", "py", "rb", "rs"];
    let exclude_dirs = ["node_modules", ".git", "target", "dist", "build"];

    for entry in walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        !e.file_type().is_dir() || !exclude_dirs.contains(&e.file_name().to_string_lossy().as_ref())
    }) {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy();

        if file_name == "Cargo.toml" {
            if let Ok(text) = std::fs::read_to_string(path) {
                for dep in extract_cargo_dep_names(&text) {
                    if crates_blocked.contains(dep.as_str()) {
                        findings.push(Finding {
                            file: path.to_path_buf(),
                            kind: FindingKind::BlockedDependency,
                            detail: format!("crates.io:{dep}"),
                        });
                    }
                }
            }
        } else if file_name == "package.json" {
            if let Ok(text) = std::fs::read_to_string(path) {
                for dep in extract_npm_dep_names(&text) {
                    if npm_blocked.contains(dep.as_str()) {
                        findings.push(Finding { file: path.to_path_buf(), kind: FindingKind::BlockedDependency, detail: format!("npm:{dep}") });
                    }
                }
            }
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if scannable_exts.contains(&ext) {
                scan_file_contents(path, &mut findings);
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_blocked_npm_dependency() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"dependencies": {"crossenv": "1.0.0", "left-pad": "1.0.0"}}"#).unwrap();
        let findings = scan_project(dir.path());
        assert!(findings.iter().any(|f| f.kind == FindingKind::BlockedDependency && f.detail == "npm:crossenv"));
        assert!(!findings.iter().any(|f| f.detail.contains("left-pad")));
    }

    #[test]
    fn detects_blocked_cargo_dependency() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n\n[dependencies]\nserdejson = \"1\"\nserde = \"1\"\n").unwrap();
        let findings = scan_project(dir.path());
        assert!(findings.iter().any(|f| f.kind == FindingKind::BlockedDependency && f.detail == "crates.io:serdejson"));
        assert!(!findings.iter().any(|f| f.detail.contains("crates.io:serde\"")));
    }

    #[test]
    fn detects_curl_pipe_to_shell() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("install.sh"), "curl -fsSL https://example.com/install.sh | bash\n").unwrap();
        let findings = scan_project(dir.path());
        assert!(findings.iter().any(|f| f.kind == FindingKind::SuspiciousPattern && f.detail == "curl-pipe-to-shell"));
    }

    #[test]
    fn detects_powershell_encoded_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("run.ps1"), "powershell -EncodedCommand SGVsbG8=\n").unwrap();
        let findings = scan_project(dir.path());
        assert!(findings.iter().any(|f| f.detail == "powershell-encoded-command"));
    }

    #[test]
    fn clean_project_has_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() { println!(\"hello\"); }\n").unwrap();
        assert!(scan_project(dir.path()).is_empty());
    }

    #[test]
    fn skips_excluded_directories() {
        let dir = tempfile::tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        fs::create_dir(&node_modules).unwrap();
        fs::write(node_modules.join("package.json"), r#"{"dependencies": {"crossenv": "1.0.0"}}"#).unwrap();
        assert!(scan_project(dir.path()).is_empty());
    }
}
