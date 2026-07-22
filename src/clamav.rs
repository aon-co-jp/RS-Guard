//! ClamAV(`clamscan`/`clamdscan`)への薄いラッパー。
//!
//! **設計方針**: RS-Guardはウイルス定義データベースを自前で持たず、
//! 独自の検知エンジンも実装しない(ユーザーへ「他のセキュリティアプリと
//! 一緒に使える」ことを明言した通り、既存の実績あるエンジンを呼び出す
//! だけにする——自作のシグネチャDBは更新が追いつかず誤った安心感を
//! 与えるリスクがあるため、あえて作らない判断)。`clamscan`が
//! インストールされていない環境では、インストールを検出できない旨を
//! 正直に返す(黙って「クリーン」とは報告しない)。

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamAvResult {
    pub infected_files: Vec<String>,
    pub scanned_files: u32,
    pub raw_summary: String,
}

#[derive(Debug)]
pub enum ClamAvError {
    /// `clamscan`/`clamdscan`のいずれもPATH上に見つからなかった。
    NotInstalled,
    /// 実行はできたが、想定外の終了コード/出力だった。
    ExecutionFailed(String),
}

impl std::fmt::Display for ClamAvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClamAvError::NotInstalled => write!(f, "ClamAV (clamscan/clamdscan) is not installed or not on PATH"),
            ClamAvError::ExecutionFailed(e) => write!(f, "ClamAV execution failed: {e}"),
        }
    }
}

/// `clamdscan`(デーモン経由、高速)を優先し、無ければ`clamscan`
/// (スタンドアロン、都度定義DBを読み込むため低速)にフォールバックする。
/// どちらも無ければ`NotInstalled`。
pub fn is_available() -> bool {
    find_binary().is_some()
}

fn find_binary() -> Option<&'static str> {
    ["clamdscan", "clamscan"].into_iter().find(|candidate| Command::new(candidate).arg("--version").output().is_ok())
}

/// **権限についての正直な注記**: Linux/macOSでパッケージをインストール
/// するコマンドは通常root権限が要る。RS-Guardは自分で`sudo`を付けたり
/// 権限昇格したりしない(黙って昇格すると何が起きているか分からなく
/// なるため)——rootで動いていなければコマンドは失敗し、その旨が
/// `InstallStepResult`に正直に出る。一般ユーザーが使う場合は
/// `sudo rs-guard doctor --install`のようにユーザー自身が明示的に
/// 昇格すること。
///
/// このOSで実行できそうなClamAV導入コマンド。**ユーザー環境を推測して
/// 提示するだけ**——`install_with`が実際に呼ぶまでは何も実行しない。
/// 検出できたパッケージマネージャ1つだけを返す(複数候補があっても
/// 最初に見つかったものを使う、`find_binary`と同じ「最初の1つ」方針)。
pub struct InstallPlan {
    /// 人間向けの説明(どのパッケージマネージャを使うか)。
    pub description: &'static str,
    /// 実行するコマンド列(複数行に分かれる場合がある、例:
    /// パッケージインストール→`freshclam`)。
    pub commands: Vec<Vec<&'static str>>,
}

/// このマシンで使えそうなパッケージマネージャを検出し、導入手順を返す。
/// 検出できなければ`None`(手動インストールの案内は呼び出し側`doctor`が
/// 表示する)。
pub fn detect_install_plan() -> Option<InstallPlan> {
    if cfg!(target_os = "windows") {
        if command_exists("choco") {
            return Some(InstallPlan { description: "winget/chocolatey (choco)", commands: vec![vec!["choco", "install", "clamav", "-y"]] });
        }
        if command_exists("winget") {
            return Some(InstallPlan {
                description: "winget",
                commands: vec![vec!["winget", "install", "--id", "ClamAV.ClamAV", "-e", "--source", "winget"]],
            });
        }
        return None;
    }
    if cfg!(target_os = "macos") {
        if command_exists("brew") {
            return Some(InstallPlan { description: "Homebrew", commands: vec![vec!["brew", "install", "clamav"]] });
        }
        return None;
    }
    // Linux系。
    if command_exists("apt-get") {
        return Some(InstallPlan {
            description: "APT (Debian/Ubuntu)",
            commands: vec![
                vec!["apt-get", "update"],
                vec!["apt-get", "install", "-y", "clamav", "clamav-daemon"],
                vec!["freshclam"],
            ],
        });
    }
    if command_exists("dnf") {
        return Some(InstallPlan {
            description: "DNF (RHEL/AlmaLinux/Fedora)",
            commands: vec![
                vec!["dnf", "install", "-y", "epel-release"],
                vec!["dnf", "install", "-y", "clamav", "clamav-update"],
                vec!["freshclam"],
            ],
        });
    }
    if command_exists("pacman") {
        return Some(InstallPlan {
            description: "pacman (Arch)",
            commands: vec![vec!["pacman", "-Sy", "--noconfirm", "clamav"], vec!["freshclam"]],
        });
    }
    None
}

fn command_exists(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok()
}

#[derive(Debug)]
pub struct InstallStepResult {
    pub command: String,
    pub success: bool,
    pub output_tail: String,
}

/// `plan`の各コマンドを**実際に**順に実行する。呼び出し元
/// (`rs-guard doctor --install`)が明示的に`--install`を付けたときだけ
/// 呼ばれる——検出しただけで黙って実行はしない。途中のコマンドが
/// 失敗しても後続は試す(例えば`freshclam`が失敗してもパッケージ自体は
/// 入っている場合があるため)。
pub fn install_with(plan: &InstallPlan) -> Vec<InstallStepResult> {
    plan.commands
        .iter()
        .map(|argv| {
            let command_str = argv.join(" ");
            match Command::new(argv[0]).args(&argv[1..]).output() {
                Ok(out) => {
                    let mut tail = String::from_utf8_lossy(&out.stdout).to_string();
                    tail.push_str(&String::from_utf8_lossy(&out.stderr));
                    let tail: String = tail.lines().rev().take(5).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
                    InstallStepResult { command: command_str, success: out.status.success(), output_tail: tail }
                }
                Err(e) => InstallStepResult { command: command_str, success: false, output_tail: e.to_string() },
            }
        })
        .collect()
}

pub fn scan_path(path: &Path) -> Result<ClamAvResult, ClamAvError> {
    let binary = find_binary().ok_or(ClamAvError::NotInstalled)?;
    let output = Command::new(binary)
        .arg("--infected")
        .arg("--no-summary")
        .arg(path)
        .output()
        .map_err(|e| ClamAvError::ExecutionFailed(e.to_string()))?;

    // clamscan終了コード: 0=感染無し, 1=感染あり(異常ではない), 2=エラー。
    let code = output.status.code().unwrap_or(-1);
    if code == 2 {
        return Err(ClamAvError::ExecutionFailed(String::from_utf8_lossy(&output.stderr).to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let infected_files: Vec<String> =
        stdout.lines().filter(|l| l.ends_with("FOUND")).map(|l| l.trim_end_matches("FOUND").trim().to_string()).collect();

    Ok(ClamAvResult { infected_files, scanned_files: stdout.lines().count() as u32, raw_summary: stdout.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_install_plan_finds_something_or_honestly_returns_none() {
        // このマシンに何らかのパッケージマネージャがあれば具体的な
        // コマンド列を返すこと、無ければNoneであることのどちらかを
        // 確認する(環境依存なので固定の期待値は置けない)。
        match detect_install_plan() {
            Some(plan) => assert!(!plan.commands.is_empty(), "a detected plan must contain at least one command"),
            None => eprintln!("no known package manager detected on this machine (honest None, not a failure)"),
        }
    }

    #[test]
    fn install_with_reports_failure_for_a_nonexistent_command() {
        let plan = InstallPlan { description: "test", commands: vec![vec!["this-binary-does-not-exist-anywhere"]] };
        let results = install_with(&plan);
        assert_eq!(results.len(), 1);
        assert!(!results[0].success, "a nonexistent command must be reported as failed, not silently skipped");
    }

    #[test]
    fn scan_path_without_clamav_installed_returns_not_installed() {
        if is_available() {
            eprintln!("skipping: ClamAV is actually installed on this machine, this test targets the absent case");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let err = scan_path(dir.path()).unwrap_err();
        assert!(matches!(err, ClamAvError::NotInstalled));
    }

    #[test]
    fn scan_path_with_clamav_installed_scans_a_clean_temp_dir() {
        if !is_available() {
            eprintln!("skipping: ClamAV is not installed on this machine");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("clean.txt"), b"hello world").unwrap();
        let result = scan_path(dir.path()).unwrap();
        assert!(result.infected_files.is_empty());
    }
}
