use clap::{Parser, Subcommand};
use rs_guard::{ai_classify, clamav, repo_scan};
use std::collections::HashSet;
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
        /// AI二次判定を有効にする。静的ルールに引っかからなかったファイルを
        /// aruaru-llmの`/v1/classify-security`へ送り、意味的類似度で
        /// 再評価する(訓練済み分類器ではなくヒューリスティック)。
        #[arg(long)]
        ai: bool,
        /// AI二次判定の接続先(aruaru-llm、または「分身の術」でそこへ
        /// 転送するRPoemゲートウェイ)。
        #[arg(long, default_value = "http://127.0.0.1:4600")]
        ai_url: String,
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
    /// 紹介・ダウンロード用の最小限のHTTPサーバー(`runo.tokyo/RS-Guard`
    /// での公開紹介ページ用)。ログイン制の実運用画面はこのプロセスでは
    /// なく`easy-web.tokyo`(open-easy-web)側に統合する(別リポジトリ)。
    Serve {
        #[arg(long, default_value_t = 8098)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::ScanRepos { path, json, ai, ai_url } => run_scan_repos(&path, json, ai, &ai_url).await,
        Command::Doctor => run_doctor(),
        Command::ScanFile { path, json } => run_scan_file(&path, json),
        Command::Serve { port } => {
            if let Err(e) = run_serve(port).await {
                eprintln!("server error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

async fn run_serve(port: u16) -> Result<(), std::io::Error> {
    use poem::{get, handler, listener::TcpListener, EndpointExt, Route, Server};

    #[handler]
    fn index() -> poem::web::Html<&'static str> {
        poem::web::Html(include_str!("../static/index.html"))
    }
    #[handler]
    fn healthz() -> &'static str {
        "ok"
    }
    #[handler]
    fn install_sh() -> poem::Response {
        poem::Response::builder()
            .header("content-type", "text/x-shellscript; charset=utf-8")
            .header("content-disposition", "attachment; filename=\"install.sh\"")
            .body(include_str!("../install.sh"))
    }
    #[handler]
    fn install_ps1() -> poem::Response {
        poem::Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .header("content-disposition", "attachment; filename=\"install.ps1\"")
            .body(include_str!("../install.ps1"))
    }

    let app = Route::new()
        .at("/", get(index))
        .at("/healthz", get(healthz))
        .at("/install.sh", get(install_sh))
        .at("/install.ps1", get(install_ps1))
        .with(poem::middleware::Tracing);

    tracing_subscriber::fmt::try_init().ok();
    tracing::info!("rs-guard intro/download server listening on 0.0.0.0:{port}");
    Server::new(TcpListener::bind(("0.0.0.0", port))).run(app).await
}

async fn run_scan_repos(path: &Path, json: bool, ai: bool, ai_url: &str) -> ExitCode {
    if !path.exists() {
        eprintln!("error: path does not exist: {}", path.display());
        return ExitCode::FAILURE;
    }
    let mut findings = repo_scan::scan_project(path);

    if ai {
        match run_ai_pass(path, ai_url, &findings).await {
            Ok(mut ai_findings) => findings.append(&mut ai_findings),
            Err(e) => {
                // AIが使えないことを黙って握りつぶさない——静的結果だけで
                // 判断している旨を明示し、終了コードでも成功と偽らない。
                eprintln!("warning: AI second opinion was skipped ({e}).");
                eprintln!("         Findings below are from STATIC RULES ONLY.");
            }
        }
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    }
    let findings = findings;
    if json {
        println!("{}", serde_json::to_string_pretty(&findings).unwrap());
    } else if findings.is_empty() {
        println!("No known-blocked dependencies or suspicious script patterns found under {}.", path.display());
        println!("(Static pattern scan only — this does not replace a real antivirus or a live vulnerability database. See README.)");
    } else {
        println!("Found {} finding(s) under {} (most severe first):\n", findings.len(), path.display());
        for f in &findings {
            println!("  [{:?}/{:?}] {} — {}", f.severity, f.kind, f.file.display(), f.detail);
        }
        println!("\n(Static pre-execution scan. This complements — does not replace — your antivirus/EDR.");
        println!(" It does not monitor or block running processes; that is your OS firewall/EDR's job.)");
    }
    if findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

/// AI二次判定パス。**静的ルールが何も検出しなかったファイルだけ**を
/// aruaru-llmへ送る(既に検出済みのファイルを再送しても情報が増えず、
/// 送信量とレイテンシが増えるだけのため)。サービスが落ちている場合は
/// 先頭のヘルスチェックで早期にErrを返し、呼び出し側が「AI判定はスキップ」
/// と正直に表示できるようにする。
async fn run_ai_pass(root: &Path, ai_url: &str, static_findings: &[repo_scan::Finding]) -> Result<Vec<repo_scan::Finding>, ai_classify::AiError> {
    let ai = ai_classify::AiClassifier::new(ai_url);
    if !ai.health_check().await? {
        return Err(ai_classify::AiError::Unreachable(format!("{ai_url} did not report healthy")));
    }

    let already_flagged: HashSet<&Path> = static_findings.iter().map(|f| f.file.as_path()).collect();
    let mut out = Vec::new();
    for (path, text) in repo_scan::collect_scannable_files(root) {
        if already_flagged.contains(path.as_path()) {
            continue;
        }
        if text.trim().is_empty() {
            continue;
        }
        match ai.classify(&text).await {
            Ok(v) if v.is_suspicious => {
                out.push(repo_scan::Finding {
                    file: path,
                    kind: repo_scan::FindingKind::AiSuspicion,
                    // 静的な一致より確信度が低いヒューリスティックなので
                    // Criticalではなく中位に置く(誇張しない)。
                    severity: repo_scan::Severity::Medium,
                    detail: format!("ai:{} (score {:.3}, engine {})", v.label, v.score, v.engine),
                });
            }
            Ok(_) => {}
            Err(e) => {
                // 個別ファイルの失敗で全体を止めない。ただし黙らせない。
                eprintln!("warning: AI classification failed for {}: {e}", path.display());
            }
        }
    }
    Ok(out)
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
