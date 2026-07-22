//! 破壊的操作の検出(無断のディスクフォーマット・全削除・勝手な自動実行)。
//!
//! ユーザーの懸念: USBメモリを挿した時やメールのリンク/添付を開いた時に、
//! **無断で**HDD/SSDをフォーマットされたり、全フォルダ・全ファイルを
//! 削除されたり、変なウイルスが勝手に自動実行されたりすること。
//!
//! # 設計の要: 「スコープ」で危険かどうかを分ける
//!
//! **通常の開発でのフォルダ削除は検出しない**(ユーザー指示、2026-07-22)。
//! `rm -rf ./target`・`rm -rf node_modules`・`Remove-Item ./dist -Recurse`の
//! ような、**プロジェクト内の特定フォルダを対象にした削除は正当な操作**で
//! あり、これを一々警告すると誤検知だらけになって本当の危険が埋もれる。
//!
//! 危険と判定するのは、対象が**ドライブ全体・システムルート**の場合だけ:
//! - `rm -rf /`(ルート直下)・`--no-preserve-root`
//! - `del /s /q C:\`・`Remove-Item C:\ -Recurse`(ドライブ直下)
//! - `format C:`・`mkfs.ext4 /dev/sda`・`diskpart` + `clean`
//! - 生ディスクへの直接書き込み(`/dev/sda`・`\\.\PhysicalDrive0`)
//! - バックアップ/復元ポイントの破壊(ランサムウェアの前段によくある)
//! - リムーバブルメディアからの自動実行の仕込み(`autorun.inf`)
//! - Office文書の自動実行マクロ(`AutoOpen`/`Document_Open`+シェル実行)
//!
//! # 正直な開示(最重要)
//!
//! これは**実行される前の静的検査**であり、**実行中のフォーマットを
//! カーネルレベルで止める常駐ガードではない**。実際にブロックするには
//! Windowsのファイルシステムミニフィルタドライバや、LinuxのLSM/eBPFに
//! よる特権常駐サービスが必要で、それはEDR製品の領域。RS-Guardが提供
//! できるのは「USBを挿したら**中身を開く前に**検査して警告する」
//! 「メール添付を**実行する前に**検査する」という予防であって、
//! 実行時の強制阻止ではない。OS標準の実行時防御(Windowsの
//! 「コントロールされたフォルダー アクセス」・AppLocker、LinuxのSELinux/
//! AppArmor)と併用すること。

use regex::Regex;

/// ドライブ全体・システムルートを対象にした破壊的操作。
/// 各パターンは「対象がルート/ドライブ直下であること」を要求するよう
/// 書かれており、プロジェクト内フォルダの削除には一致しない。
pub fn destructive_patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // --- 全削除(ルート/ドライブ直下のみ) ---
        // `rm -rf /`・`rm -rf /*`。`rm -rf /home/me/proj`のように後ろに
        // パスが続くものには一致しない(直後が行末・空白・区切り・`*`のみ)。
        ("wipe-filesystem-root", Regex::new(r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+/(\*)?(\s|;|&|\||$)").unwrap()),
        // ルート保護を明示的に外す指定は、正当な用途がまず無い。
        ("rm-no-preserve-root", Regex::new(r"--no-preserve-root").unwrap()),
        // `del /s /q C:\`・`rmdir /s /q D:\`(ドライブ直下)。
        ("windows-wipe-drive-root", Regex::new(r"(?i)\b(del|rmdir|rd)\s+(/[sqfSQF]\s+)*[a-zA-Z]:\\(\*)?(\s|$)").unwrap()),
        // `Remove-Item C:\ -Recurse -Force`(ドライブ直下)。
        ("powershell-wipe-drive-root", Regex::new(r"(?i)Remove-Item[^\n]{0,40}\s[a-zA-Z]:\\(\*)?\s[^\n]{0,40}-Recurse").unwrap()),
        // `shutil.rmtree('/')`・`rmtree("C:\\")`(ルート/ドライブ直下)。
        ("python-rmtree-root", Regex::new(r#"rmtree\(\s*["'](/|[a-zA-Z]:\\\\?)["']"#).unwrap()),

        // --- ディスクのフォーマット・消去 ---
        ("format-drive", Regex::new(r"(?i)\bformat\s+[a-zA-Z]:\s").unwrap()),
        ("powershell-format-volume", Regex::new(r"(?i)\b(Format-Volume|Clear-Disk)\b").unwrap()),
        ("linux-mkfs-on-device", Regex::new(r"\bmkfs(\.[a-z0-9]+)?\s+[^\n]{0,20}/dev/(sd|nvme|hd|vd)").unwrap()),
        ("linux-wipefs-device", Regex::new(r"\bwipefs\s+[^\n]{0,20}/dev/(sd|nvme|hd|vd)").unwrap()),
        ("diskpart-clean", Regex::new(r"(?is)diskpart[\s\S]{0,200}\bclean\b").unwrap()),

        // --- 生ディスクへの直接書き込み(パーティション表/ブートセクタ破壊) ---
        ("raw-write-to-disk-device", Regex::new(r"\bdd\s+[^\n]{0,60}of=/dev/(sd|nvme|hd|vd)").unwrap()),
        ("raw-write-physicaldrive", Regex::new(r"(?i)\\\\\.\\PhysicalDrive[0-9]").unwrap()),

        // --- バックアップ/復元ポイントの破壊(ランサムウェアの前段) ---
        ("delete-volume-shadow-copies", Regex::new(r"(?is)vssadmin[\s\S]{0,80}delete[\s\S]{0,40}shadows").unwrap()),
        ("delete-backup-catalog", Regex::new(r"(?is)wbadmin[\s\S]{0,60}delete[\s\S]{0,40}catalog").unwrap()),
        ("disable-windows-recovery", Regex::new(r"(?is)bcdedit[\s\S]{0,80}recoveryenabled[\s\S]{0,20}no").unwrap()),

        // --- 無断の自動実行 ---
        // リムーバブルメディア(USB)の自動実行の仕込み。
        ("removable-autorun-exec", Regex::new(r"(?is)\[autorun\][\s\S]{0,200}(open|shellexecute)\s*=").unwrap()),
        // Office文書を開いただけで走るマクロ+シェル実行/外部取得の組み合わせ。
        (
            "office-macro-auto-exec",
            Regex::new(r"(?is)\b(AutoOpen|AutoExec|Document_Open|Workbook_Open)\b[\s\S]{0,200}(Shell|CreateObject|WScript|powershell)").unwrap(),
        ),
        // ダウンロードした実行ファイルをそのまま起動する(メール添付経由の典型)。
        ("download-then-execute", Regex::new(r"(?i)(Invoke-WebRequest|curl|wget)[^\n]{0,120}\.(exe|scr|bat|cmd|ps1)[^\n]{0,60}(Start-Process|&\s|\bstart\b)").unwrap()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(sample: &str) -> Vec<&'static str> {
        destructive_patterns().into_iter().filter(|(_, re)| re.is_match(sample)).map(|(n, _)| n).collect()
    }

    #[test]
    fn flags_filesystem_root_wipe() {
        assert!(hits("rm -rf / ").contains(&"wipe-filesystem-root"));
        assert!(hits("rm -rf /*").contains(&"wipe-filesystem-root"));
        assert!(hits("rm -rf --no-preserve-root /").contains(&"rm-no-preserve-root"));
    }

    /// ユーザー指示の中核: 通常の開発でのフォルダ削除は許容し検出しない。
    #[test]
    fn does_not_flag_ordinary_scoped_deletions() {
        for sample in [
            "rm -rf ./target",
            "rm -rf node_modules",
            "rm -rf /home/me/project/build",
            "rm -rf \"$TMPDIR/cache\"",
            "Remove-Item ./dist -Recurse -Force",
            "del /s /q .\\out",
            "shutil.rmtree('./build')",
        ] {
            assert!(hits(sample).is_empty(), "scoped deletion should be allowed, but {sample:?} matched {:?}", hits(sample));
        }
    }

    #[test]
    fn flags_drive_root_wipe_on_windows() {
        assert!(hits("del /s /q C:\\").contains(&"windows-wipe-drive-root"));
        assert!(hits("Remove-Item D:\\ -Recurse -Force").contains(&"powershell-wipe-drive-root"));
    }

    #[test]
    fn flags_disk_format_and_raw_writes() {
        assert!(hits("format C: /fs:ntfs").contains(&"format-drive"));
        assert!(hits("mkfs.ext4 /dev/sda1").contains(&"linux-mkfs-on-device"));
        assert!(hits("dd if=/dev/zero of=/dev/sda bs=1M").contains(&"raw-write-to-disk-device"));
        assert!(hits("diskpart\nselect disk 0\nclean").contains(&"diskpart-clean"));
    }

    #[test]
    fn flags_backup_destruction_used_by_ransomware() {
        assert!(hits("vssadmin delete shadows /all /quiet").contains(&"delete-volume-shadow-copies"));
        assert!(hits("wbadmin delete catalog -quiet").contains(&"delete-backup-catalog"));
    }

    #[test]
    fn flags_unauthorized_auto_execution() {
        assert!(hits("[autorun]\nopen=evil.exe").contains(&"removable-autorun-exec"));
        assert!(hits("Sub Document_Open()\n  Shell \"powershell -c iex(...)\"\nEnd Sub").contains(&"office-macro-auto-exec"));
    }

    #[test]
    fn ordinary_code_is_not_flagged() {
        for sample in ["fn main() { println!(\"hello\"); }", "const total = items.reduce((a,b)=>a+b, 0);", "SELECT * FROM users WHERE id = $1"] {
            assert!(hits(sample).is_empty(), "{sample:?} matched {:?}", hits(sample));
        }
    }
}
