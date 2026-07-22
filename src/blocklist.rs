//! パッケージ名ブロックリスト。
//!
//! **正直な開示(最重要)**: これはVirusTotal/npm audit/OSV等のような
//! ライブ更新される脅威インテリジェンスフィードではない。過去に
//! 実際に摘発・報告されたサプライチェーン攻撃(typosquat・依存関係
//! 混乱・乗っ取りメンテナ等)の中から、著名で確認可能なものを手動で
//! 抜粋しただけの**静的スナップショット**であり、新しい攻撃には対応
//! できない。「これに引っかからない = 安全」ではなく、「これに
//! 引っかかったら高確度で危険」という一方向の判定にのみ使うこと。
//! 本格的な脆弗性DBと組み合わせて使うことを前提とする(README参照)。

use std::collections::HashSet;

/// npmで実際に報告された悪意あるパッケージ名(2021-2023年頃に摘発された
/// typosquat/アカウント乗っ取り事例の一部、出典: npm公式のセキュリティ
/// 勧告・各種セキュリティ企業のレポート)。
pub fn npm_blocklist() -> HashSet<&'static str> {
    [
        "crossenv",
        "cross-env.js",
        "d3.js",
        "fabric-js",
        "ffmepg",
        "gruntcli",
        "http-proxy.js",
        "jquey",
        "mariadb",
        "mongose",
        "mssql-node",
        "node-fabric",
        "node-opencv",
        "node-opensl",
        "node-sqlite",
        "node-tkinter",
        "nodefabric",
        "nodesass",
        "opencv.js",
        "proxy.js",
        "shadowsock",
        "smb",
        "sqlite.js",
        "sqliter",
        "sqlserver",
        "tkinter",
        "ua-parser-js.bak",
    ]
    .into_iter()
    .collect()
}

/// crates.ioで報告された悪意ある/なりすましクレート名の一部
/// (出典: RustSecアドバイザリデータベースの一部エントリ)。
pub fn crates_io_blocklist() -> HashSet<&'static str> {
    ["faster_log", "fast_log2", "serdejson", "libssl-dev"].into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_blocklist_is_non_empty_and_lowercase() {
        let list = npm_blocklist();
        assert!(!list.is_empty());
        for name in &list {
            assert_eq!(*name, name.to_lowercase());
        }
    }

    #[test]
    fn crates_io_blocklist_is_non_empty() {
        assert!(!crates_io_blocklist().is_empty());
    }
}
