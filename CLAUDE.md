# 開発方針＆開発環境ルール(RS-Guard)

作業ドライブは`F:\runo`。この節は[`open-raid-z`](https://github.com/aon-co-jp/open-raid-z)の
`CLAUDE.md`を正本とし、各プロジェクトへコピーして同期する方針に準じる。
GitHubリポジトリ: [aon-co-jp/RS-Guard](https://github.com/aon-co-jp/RS-Guard)。

> ⚠️ **正直な開示(最重要、2026-07-22 初版)**: RS-Guardは**既存の
> アンチウイルスを置き換えず併用するツール**。独自のウイルス定義DBや
> 検知エンジンは持たない。依存名ブロックリストは過去の著名なサプライ
> チェーン攻撃の手動抜粋(静的スナップショット、ライブ更新なし)、
> スクリプト検査は正規表現ベースの静的解析(難読化・新種は検出不可)、
> 実ファイルスキャンはClamAVが別途導入済みの場合のみ委譲。**「作った
> 気になって安全と誤信する」リスクを避けるため、あえて自作エンジンは
> 作らない判断**(ユーザーへ「他のセキュリティアプリと一緒に使える」旨を
> 明言済み)。

## このプロジェクトの役割

このエコシステム(`F:\runo` / `aon-co-jp`)のリポジトリ・依存パッケージに
悪意あるコードが混入していないかを静的にチェックするサプライチェーン
スキャナ。ユーザーの懸念「関連リポジトリ/プロジェクトにコンピューター
ウイルスが入って実行されたら怖い」への対策として2026-07-22に着手。

## 技術スタック

`clap`ベースのCLI + `poem`(紹介ページ配信の`serve`サブコマンドのみ)。
DB非依存。`walkdir`+`regex`+`serde_json`で静的スキャン。

## 主要モジュール

- `src/blocklist.rs` — npm/crates.ioの既知悪意パッケージ名(静的、手動抜粋)。
- `src/repo_scan.rs` — `Cargo.toml`/`package.json`依存名の照合 + ソース/
  スクリプトの疑わしいパターン検出(正規表現)。
- `src/clamav.rs` — `clamdscan`/`clamscan`への薄いラッパー(未導入なら
  `NotInstalled`を正直に返す)。
- `src/main.rs` — `scan-repos`/`scan-file`/`doctor`/`serve`サブコマンド。
- `static/index.html` — 紹介・ダウンロードページ(`serve`が配信)。

## 運用構成(2026-07-22、ユーザー指示で確定)

- **runo.tokyo/RS-Guard**: 紹介・ダウンロードページ(`rs-guard serve`)。
  VPS上は`/root/runo.tokyo/RS-Guard`(2026-07-22クローン・ビルド済み)。
- **easy-web.tokyo/RS-Guard**: ログイン後にブラウザからスキャン実行できる
  実運用画面。**`open-easy-web`本体(`/root/open-easy-web/`、easy-web.tokyoの
  実体)へ統合**し、既存のOTP/TOTPログイン(`require_session`)配下で運用する
  方針(別リポジトリ`open-easy-web`側の作業、未着手)。

> ⚠️ **運用ルール(2026-07-22、ユーザー指示・重要)**: VPS・リポジトリ・
> ローカルドライブで新規フォルダや配置先が無い/命名に選択肢がある場合は、
> 勝手に作らず必ず事前にユーザーへ相談すること(easy-web.tokyoという
> ドメイン名フォルダは存在せず、実体は`open-easy-web`が提供している、
> といった構造を先に確認する)。

## HANDOFF

- **2026-07-22(続き) ウイルス/スパイウェア検出・AI二次判定・VPSデプロイ完了**:
  1. **ウイルス/スパイウェア静的検出**(`src/signatures.rs`/`src/spyware.rs`):
     マルウェアシグネチャ(EICAR・シェルコードローダー・ドロッパー・
     ランサムウェア型・pastebin実行)と、スパイウェア挙動3分類——無断の
     情報収集(SSH鍵/ブラウザ認証情報/環境変数/キーロガー/クリップボード/
     スクリーンショット)、持ち出し(環境変数のPOST・Discord/Telegram
     Webhook・DNSトンネリング)、**常駐・自動巡回**(cron・systemd・
     WindowsレジストリRun・スケジュールタスク・launchd・定期ビーコン)。
     `Severity`(Critical/High/Medium/Info)を追加し重大順にソート。
     **EICARはラベル部分のみで検出**し完全な68バイト検体は埋め込まない
     (自リポジトリがAVに検出される罠の回避)。`regex`クレートは先読み
     非対応のため全パターンで不使用。
  2. **AI二次判定**(`src/ai_classify.rs`、`--ai`/`--ai-url`): 静的ルールが
     **何も検出しなかったファイルだけ**をaruaru-llmの
     `/v1/classify-security`(open-cudaのopencuda-bert埋め込み)へ送り、
     意味的類似度で再評価する。スニペットは2000文字上限・タイムアウト30秒。
     AI検出は`FindingKind::AiSuspicion`/`Severity::Medium`(正規表現の
     完全一致より確信度が低いヒューリスティックなので誇張せず中位)。
     **実機E2E検証済み**: SSH鍵を読んでPOSTするJSを、パスとURLを文字列
     分割して正規表現を回避する形にしたところ静的ルールは取り逃がし、
     `--ai`が`persistence-beacon`(score 0.889)として正しく検出、通常の
     コードは検出されないことを確認。**AI到達不能時は黙って「安全」と
     言わず**`STATIC RULES ONLY`と警告することも確認。30テスト・
     clippy警告0。
  3. **VPSデプロイ**(`runo.tokyo/RS-Guard`、紹介・ダウンロードページ):
     `/root/runo.tokyo/RS-Guard`で`cargo build --release`→systemd
     `rs-guard.service`(`serve --port 8098`)→open-web-serverの
     `domains.toml`に`path_prefix = "/RS-Guard"`追加→nginxに
     `location /RS-Guard`追加(RS-Opsと同じ2層構成: nginx→8103→8098)。
     **実HTTP検証**: `/RS-Guard/`(200・タイトル/見出し/開示文を確認)・
     `/healthz`(200)・`install.sh`(200)・`install.ps1`(200)。既存の
     `/`・`/blog`・`/ec`・`/RS-Ops`・`/rs-git/ui/`・`/rs-sync/`が
     引き続き200であることも確認(リグレッション無し)。
  - 次にすべきこと: (1) **easy-web.tokyo/RS-Guardのログイン後実運用画面**
    (open-easy-web本体へ統合、ブラウザからスキャン実行)——未着手、
    (2) VPSへのClamAV導入判断(現状`doctor`は未導入を正直に報告)、
    (3) ブロックリスト/シグネチャの拡充(バックグラウンドエージェントに
    委任したが変更は着地しなかったことを`git`で裏取り済み、要再着手)、
    (4) Android版(Kotlin/Javaの別ツールチェーンが必要)。

- **2026-07-22 初版作成**: ユーザー指示「関連リポジトリや関連プロジェクトの
  中にコンピューターウイルスが入って実行されたら怖いので、セキュリティ
  対策を立てて機能搭載してほしい。Windows版とLinux版と(Androidも)他の
  セキュリティアプリとも一緒に使えるインストーラー付きセキュリティアプリ
  として開発して」を受けて着手。
  - **スコープ確認(AskUserQuestion)**: チェック対象=「エコシステム内の
    Gitリポ・依存パッケージ(推奨)」+「一般ファイルのEXE/スクリプト
    スキャン(ClamAV連携)」の両方。プレスボード順=Windows/Linuxを今回
    スコープ、Androidは次回以降(Kotlin/Javaの別ツールチェーンが必要な
    ため)。
  - **実装**: `scan-repos`(ブロックリスト依存名照合 + 疑わしいスクリプト
    パターンの正規表現検出)、`scan-file`/`doctor`(ClamAVラッパー)、
    `serve`(紹介ページ)。Windows/Linuxインストーラー
    (`install.sh`/`install.ps1`、cargoビルド方式、RS-Ops踏襲)。
  - **検証**: `cargo test` 10件全green(ブロック依存検出・疑わしい
    パターン検出・除外ディレクトリスキップ・クリーンプロジェクトで
    検出0・ClamAV未導入時のNotInstalled等)。`cargo clippy --all-targets`
    警告0件。実バイナリで`F:\runo`全体を実スキャンし、`install.sh`の
    `curl ... | sh`(rustupインストール、正当だが疑わしいパターンとして
    正しく検出)等を検出することを確認。VPS(`/root/runo.tokyo/RS-Guard`)
    でもビルド成功・`doctor`(ClamAV未導入を正直に報告)・`scan-repos`の
    実行を確認済み。
  - 次にすべきこと: (1) runo.tokyo/RS-Guardの紹介ページのVPSデプロイ
    (`rs-guard serve`のsystemd化 + nginx/open-web-server配線)、
    (2) easy-web.tokyo/RS-Guardのopen-easy-web統合(ログイン連携した
    スキャン実行UI)、(3) ClamAVをVPSへ導入するかの判断、(4) Android版。

## 関連プロジェクト

- [RS-Ops](https://github.com/aon-co-jp/RS-Ops) — エコシステムマップ+AI
  コンテキスト生成。インストーラー・serve配信パターンの参照元。
- [open-easy-web](https://github.com/aon-co-jp/open-easy-web) — easy-web.tokyoの
  実体。RS-Guardの実運用画面(ログイン連携)の統合先。
- [open-raid-z](https://github.com/aon-co-jp/open-raid-z) — 開発ルールの正本。
