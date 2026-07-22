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
