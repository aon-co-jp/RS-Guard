use clap::{Parser, Subcommand};
use rs_guard::{clamav, repo_scan};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "rs-guard", version, about = "Supply-chain repo scanner + optional ClamAV integration (complements, does not replace, your existing antivirus)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 指定ディレクトリ配下(複数プロジェクトのルート、またはプロジェクト
    /// 単体)を、ブロックリスト依存名・疑わしいスクリプトパターンで
    /// スキャンする。
    ScanRepos {
        /// スキャン対象のルートディレクトリ。
        path: PathBuf,
        /// 検出結果をJSON形式で出力する(CI連携用)。
        #[arg(long)]
        json: bool,
    },
    /// ClamAVが実際にインストールされているかを確認する(定義DBの
    /// 有無やバージョンまでは検証しない、実行可否のみ)。
    Doctor,
    /// ClamAV(`clamdscan`/`clamscan`)へ処理を委譲してファイル/ディレクトリを
    /// スキャンする。ClamAV未導入の場合は正直にエラーを返す。
    ScanFile {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::ScanRepos { path, json } => run_scan_repos(&path, json),
        Command::Doctor => run_doctor(),
        Command::ScanFile { path, json } => run_scan_file(&path, json),
    }
}

fn run_scan_repos(path: &Path, json: bool) -> ExitCode {
    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::FAILURE;
    }
    let findings = repo_scan::scan_project(path);
    if json {
        println!("{}", serde_json::to_string_pretty(&findings).unwrap());
    } else if findings.is_empty() {
        println!("No known-blocked dependencies or suspicious script patterns found under {}.", path.display());
        println!("(Static pattern scan only — this does not replace a real antivirus or a live vulnerability database. See README.)");
    } else {
        println!("Found {} finding(s) under {}:\n", findings.len(), path.display());
        for f in &findings {
            println!("  [{:?}] {} — {}", f.kind, f.file.display(), f.detail);
        }
    }
    if findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn run_doctor() -> ExitCode {
    if clamav::is_available() {
        println!("ClamAV: available (clamdscan or clamscan found on PATH).");
        ExitCode::SUCCESS
    } else {
        println!("ClamAV: NOT found on PATH. Install it to enable `rs-guard scan-file`:");
        println!("  Windows: choco install clamav  (or download from https://www.clamav.net/downloads)");
        println!("  Debian/Ubuntu: sudo apt install clamav clamav-daemon && sudo freshclam");
        println!("  RHEL/AlmaLinux: sudo dnf install epel-release && sudo dnf install clamav clamav-update && sudo freshclam");
        ExitCode::from(1)
    }
}

fn run_scan_file(path: &Path, json: bool) -> ExitCode {
    match clamav::scan_path(path) {
        Ok(result) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else if result.infected_files.is_empty() {
                println!("ClamAV: no infected files found under {}.", path.display());
            } else {
                println!("ClamAV: {} infected file(s) found:", result.infected_files.len());
                for f in &result.infected_files {
                    println!("  {f}");
                }
            }
            if result.infected_files.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("run `rs-guard doctor` for installation guidance.");
            ExitCode::from(2)
        }
    }
}
