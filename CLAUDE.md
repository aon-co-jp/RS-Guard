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

## 位置づけ: 「ClamAV＋α」(2026-07-22、ユーザー確認済み・正本記録)

RS-Guardは**ClamAVを置き換えるものではなく、ClamAVを土台にした「＋α」**
という位置づけで正式に確認済み。

**ClamAV(土台)**: 実ファイル/EXEの本格スキャン(数十万件超のシグネチャDB、
`freshclam`で継続更新される)を担う、実績あるオープンソースエンジン。

**RS-Guardの「＋α」部分(ClamAVがカバーしない領域)**:
1. **サプライチェーン検査**: `Cargo.toml`/`package.json`の依存パッケージ名を
   悪意ある既知パッケージと照合する(ClamAVはファイルスキャンのみで、
   依存関係の名前チェックはしない)。
2. **ソースコードの挙動パターン検査**: スパイウェア的な情報収集・
   持ち出し・常駐/自動巡回の**コード片**を正規表現で検出する(ClamAVは
   実行ファイル/既知検体のシグネチャマッチが主で、ソースコードの
   「これから書かれようとしている挙動」までは見ない)。
3. **破壊的操作/自動実行の検出**(USBのautorun・Officeマクロ・ドライブ
   全体フォーマット)も同様にソースコードレベルで検査する。
4. **AI二次判定**: 正規表現をすり抜けた言い換えコードを、aruaru-llmの
   埋め込み類似度で拾う(ClamAVのシグネチャ方式には無い層)。

つまり**「ClamAV = 実ファイルの最終防衛線」「RS-Guard = 開発中のコード・
依存関係・スクリプトに対する早期警戒網」**という役割分担であり、重複では
なく補完関係。「他のセキュリティアプリと一緒に使える」という当初の
ユーザー要望通りの設計であることを、この節で正式に確認・記録する。

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

- **2026-07-23(続き) `.github/workflows/release.yml`を新規追加、
  3点セット完備・v0.1.0タグでCI成功・GitHub Release実在確認まで完了**:
  エコシステム全体インストーラー整備計画(正本: `open-raid-z/CLAUDE.md`
  「エコシステム全体インストーラー整備計画」節)の一環。`install.sh`/
  `install.ps1`は既存(ソースからのcargoビルド方式、変更無し)だった
  ため、`release.yml`のみ新規追加した。Linux x86_64・Windows x86_64
  向けにプリビルド済みバイナリをビルドし、`install.sh`/`install.ps1`と
  一緒にtar.gz/zipへ同梱、GitHub Releasesへ`softprops/action-gh-release@v2`
  で添付する構成(sibling path依存は無し、確認済み)。`v0.1.0`タグを
  実際にpushし、`gh run list`で2ジョブ(Linux/Windows)とも
  `completed success`、`gh release view v0.1.0`で
  `rs-guard-linux-x86_64.tar.gz`/`rs-guard-windows-x86_64.zip`の
  両方が実在することを確認した(型チェックのみでの完了報告ではない)。
  README(日英)にもプリビルド済みバイナリの入手先を追記。
  - 次にすべきこと: Android版インストーラー(未着手、他リポジトリと
    共通のバックログ)。

- **2026-07-22(続き3) ClamAV自動導入(`doctor --install`)を実装**:
  ユーザーから「ClamAVのインストール推薦して、インストールを簡単にする
  仕様にして」との指示。あわせて「RS-Guardは『ClamAV＋α』という
  位置づけで良いか」との確認があり、上記「位置づけ」節として正式に
  記録・合意した。
  1. **`src/clamav.rs`**: `detect_install_plan()`——このマシンで使える
     パッケージマネージャ(Windows: choco→winget、macOS: brew、
     Linux: apt→dnf→pacman)を検出し、具体的なコマンド列
     (Linuxは`epel-release`等の前提込み、末尾に`freshclam`での定義DB
     初回取得も含む)を返す。`install_with(plan)`——実際にコマンドを
     順に実行し、各ステップの成否と出力末尾を`InstallStepResult`で返す。
     **権限は自動昇格しない**(黙って`sudo`を付けたりしない、失敗すれば
     正直にFAILとして表示し、ユーザー自身に`sudo`での再実行を促す)。
  2. **`main.rs`**: `Doctor { install: bool }`。`--install`無しなら従来通り
     手動手順を表示するだけ、`--install`ありなら検出→実行→再チェックまで
     行い、成功/失敗を正直に表示する。
  3. **検証**: `cargo test`**39件全green**(新規2件:
     `detect_install_plan_finds_something_or_honestly_returns_none`——
     このWindows開発機で実際に`winget`が検出されコマンド列が空でない
     ことを確認、`install_with_reports_failure_for_a_nonexistent_command`
     ——存在しないコマンドが黙って無視されずFAILと報告されることを確認)。
     `cargo clippy --all-targets`警告0件。
     **意図的に見送った検証**: このセッションではこの開発機(Windows)
     およびVPS(root権限あり)への実際のインストール実行は、ユーザーの
     ローカル環境を無断で変更しないという方針に基づき、コード完成・
     ユニットテスト・型検証までに留めた——実際の`--install`実行(特に
     VPSへのClamAV導入)は、ユーザー確認の上で別途実施すること。
  - 次にすべきこと: (1) VPS本番への再デプロイ(この`--install`機能を
    含む最新版)、(2) VPS上で実際に`rs-guard doctor --install`を実行し
    ClamAVを導入(AlmaLinuxなので`dnf`経路、root権限は満たしている)、
    (3) easy-web.tokyo/RS-Guardのログイン後実運用画面は引き続き未着手。

- **2026-07-22(続き2) 破壊的操作・無断自動実行の検出を追加**: ユーザー
  指示「USBスティックメモリーを差し込んだりe-mailをクリックしたりする
  際に、HDDやSSDを無断でフォーマットしようとしたり、全フォルダ・全
  ファイルを無断で削除しようとしたり、おかしなウイルスを無断で自動実行
  しようとするのを防御して。ただしウイルスでなくドライブ全体の削除で
  ないなら、フォルダ削除などは許容して」を受けて実装。
  1. **`src/destructive.rs`新設**: ドライブ全体・システムルートを対象に
     した操作だけを検出する設計(`rm -rf /`・`--no-preserve-root`・
     `del /s /q C:\`・`Remove-Item C:\ -Recurse`・`format`/
     `Format-Volume`/`mkfs`/`wipefs`・生ディスクへの`dd`/
     `\\.\PhysicalDriveN`書き込み・`vssadmin delete shadows`等の
     バックアップ破壊)。**`rm -rf ./target`のようなプロジェクト内の
     通常のフォルダ削除は意図的に検出しない**(ユーザー指示通り、
     対象がルート/ドライブ直下であることを要求する正規表現にすることで
     区別)。加えて無断の自動実行(USBの`autorun.inf`・Office文書の
     `AutoOpen`/`Document_Open`マクロ+シェル実行・ダウンロード直後の
     実行ファイル起動)も検出。
  2. **`repo_scan.rs`**: `FindingKind::DestructiveOperation`
     (`Severity::Critical`)を追加、`scan_text`の最優先チェックとして
     配線。スキャン対象拡張子に`.inf`(autorun)・`.bas`/`.vba`/`.cls`
     (VBAマクロのエクスポート形式)を追加。
  3. **正直な開示**(README両言語・モジュールdocに明記): これは
     実行前の静的検査であり、USB挿入時やメール添付実行時に**カーネル
     レベルでリアルタイムに阻止する常駐ガードではない**(それは
     Windowsミニフィルタドライバ/Linux LSM・eBPFによるEDR製品の領域)。
     OS標準の実行時防御(コントロールされたフォルダー アクセス・
     AppLocker・SELinux/AppArmor)と併用すべき旨を明記。
  4. **検証**: 実装中に`regex`クレートの罠を発見・修正——`(?is)`フラグの
     `s`は`.`の挙動のみ変え、`[^\n]`のような手書きの否定文字クラスには
     効かないため、複数行にまたがる`diskpart`+`clean`や`[autorun]`+
     `open=`のパターンが実際には一致しないバグがあった(ユニットテストで
     発見、`[^\n]`→`[\s\S]`に置換して解消)。`cargo test`
     **37件全green**、`cargo clippy --all-targets`警告0件。実バイナリで
     実ファイル3種(通常の`rm -rf ./target`等の掃除スクリプト・
     diskpart+Format-Volume+vssadminを含む悪性PS1・`autorun.inf`)を
     スキャンし、**掃除スクリプトは検出0件(誤検知なし)**・悪性PS1と
     autorun.infは合計4件のCriticalとして正しく検出されることを実HTTP
     ではなく実CLI実行で確認(古いビルドのバイナリで一度検証漏れが
     あったことに気づき再ビルドして再確認、という教訓も記録)。
  - 次にすべきこと: (1) VPS本番への再デプロイ(このパスの変更は
    ローカル検証のみ)、(2) easy-web.tokyo/RS-Guardのログイン後実運用
    画面(open-easy-web統合、引き続き未着手)、(3) 破壊的操作パターンの
    プラットフォーム別拡充(macOS`diskutil eraseDisk`等は未カバー)。

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

## HANDOFF追記(2026-07-31) インストーラーの電源プロファイル選択機能(未実装、エコシステム標準方針として記録)

`open-raid-z`のCLAUDE.md(全リポジトリ共通の設計思想セクション)に、
インストーラー(`install.sh`/`install.ps1`等)実行時に以下3つの電源
プロファイルを選択させる標準方針を追記した(ユーザー指示、2026-07-31):

1. **省電力(Power-saving)**: CPU使用率・ポーリング間隔を抑えた低負荷設定。
2. **省メモリ(Low-memory)**: メモリ確保量・キャッシュサイズを抑えた設定。
3. **常時電源接続(Always-on)**: 上記の抑制を行わないフル性能設定。
   **この場合のみ**ハードウェアアクセラレータ(NPU/GPU)のサポートを
   自動検出・自動有効化する(`open-cuda`の`GpuDevice`抽象化を利用)。

**正直な開示**: このリポジトリのインストーラーへの実装はまだ未着手。
実装時は`open-raid-z/CLAUDE.md`の該当節、および先行実装予定の
`open-redmine/CLAUDE.md`を参照し、`open-cuda`側のGPU/NPUベンダー検出
ロジックを再利用すること(車輪の再発明を避ける)。
- 次にすべきこと: このリポジトリの`install.sh`/`install.ps1`に上記3
  プロファイルの選択機能を追加する。

- **2026-10-18 公開**: LICENSE(Apache-2.0、Cargo.toml宣言どおり)追加・全履歴の機密検査済みでリポジトリを公開。既存のv0.1.0 Releaseを公開状態に。Android版・easy-web統合画面は未着手のまま。


## 依存の更新(2026-11-03)
reqwest 0.12→0.13(機能名`rustls-tls`→`rustls`)。ビルド・テスト通過。

## API 方針: REST 全廃・gRPC / Connect へ (2026-11-04)

### 日本語
- **REST は全廃する。新しい API は REST で作らない。** ブラウザや `curl` から呼ぶ API は **Connect の単純呼び出し**(`POST /<パッケージ>.<Service>/<Method>`、`content-type: application/json`、本文は JSON)、サービス間は **gRPC / gRPC-web**(RPoem の管理API `open_runo.admin.v1.Admin` と同じ流儀)。ストリーミングは、必要になってから。
- **既存の REST は、触るときに順に移す。** 移したら旧 REST の経路は消す。移行が終わるまで残るが、**新規には追加しない**。
- **JSON は RS-JSON に統一**する(読み込みは `from_str_secure` / `parse_secure` でサイズ・深さ・重複キーの上限つき、書き出しは `rust_json::fast`)。ブラウザの WASM に `prost` は入れない(サイズが増えるため)。
- **例外(自分たちの API ではなく、相手の規格が決めているもの)**: ACME、OAuth/OIDC のコールバック、第三者(GitHub など)からの Webhook、ヘルスチェック、静的ファイル配信、OTLP など。これらは規格どおりの HTTP を受ける。
- 参考実装: `RPoem`(`open_runo.admin.v1.Admin`)、`open-easy-web`(`server/src/connect.rs`、`proto/open_easy_web/admin/v1/admin.proto`)。
- ※ このリポジトリのコードが既に方針どおりかどうかは、各リポジトリの現状による。この節は方針の記録であり、コードの変更を意味しない。

### English
- **REST is being abolished. New APIs are not built as REST.** APIs called from browsers or `curl` use **Connect unary calls** (`POST /<package>.<Service>/<Method>`, `content-type: application/json`, JSON body); service-to-service calls use **gRPC / gRPC-web** (the same style as RPoem's admin API `open_runo.admin.v1.Admin`). Streaming only when it is actually needed.
- **Existing REST endpoints are migrated one by one, when they are touched.** The old REST route is removed once migrated. Until migration is finished they remain, but **no new ones are added**.
- **JSON is unified on RS-JSON**: reading with `from_str_secure` / `parse_secure` (size, depth and duplicate-key limits), writing with `rust_json::fast`. `prost` is not put into browser WASM (it would grow the binary).
- **Exceptions (shapes dictated by someone else's standard, not our own API)**: ACME, OAuth/OIDC callbacks, webhooks from third parties (e.g. GitHub), health checks, static file serving, OTLP, and so on. These accept plain HTTP as the standard requires.
- Reference implementations: `RPoem` (`open_runo.admin.v1.Admin`) and `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Note: whether the code in a given repository already follows this policy depends on that repository. This section records the policy; it does not mean the code has been changed.

### Deutsch (KI-Übersetzung, redaktionell überarbeitet; noch nicht von Muttersprachlern geprüft)
- **REST wird vollständig abgeschafft; neue APIs entstehen nicht mehr als REST.** APIs, die aus dem Browser oder per `curl` aufgerufen werden, verwenden **unäre Connect-Aufrufe** (`POST /<Paket>.<Service>/<Methode>`, `content-type: application/json`, JSON-Body). Zwischen Diensten kommen **gRPC bzw. gRPC-web** zum Einsatz, im selben Stil wie die Admin-API von RPoem (`open_runo.admin.v1.Admin`). Streaming wird erst ergänzt, wenn es tatsächlich gebraucht wird.
- **Bestehende REST-Endpunkte werden schrittweise umgestellt, und zwar immer dann, wenn man ohnehin an ihnen arbeitet.** Sobald ein Endpunkt umgestellt ist, wird die alte REST-Route entfernt. Bis zum Abschluss der Migration bleiben die übrigen bestehen, es werden aber **keine neuen mehr hinzugefügt**.
- **JSON wird einheitlich über RS-JSON verarbeitet**: Gelesen wird mit `from_str_secure` bzw. `parse_secure` (mit Obergrenzen für Größe, Verschachtelungstiefe und doppelte Schlüssel), geschrieben mit `rust_json::fast`. `prost` wird nicht in das Browser-WASM aufgenommen, da es die Datei vergrößern würde.
- **Ausnahmen (Schnittstellen, deren Form ein fremder Standard vorgibt und die nicht zu unserer eigenen API gehören)**: ACME, OAuth/OIDC-Callbacks, Webhooks von Drittanbietern (z. B. GitHub), Health-Checks, die Auslieferung statischer Dateien, OTLP und Ähnliches. Diese nehmen, wie vom jeweiligen Standard verlangt, gewöhnliches HTTP entgegen.
- Referenzimplementierungen: `RPoem` (`open_runo.admin.v1.Admin`) und `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Hinweis: Ob der Code eines einzelnen Repositorys diese Richtlinie bereits erfüllt, hängt vom jeweiligen Repository ab. Dieser Abschnitt dokumentiert lediglich die Richtlinie; er besagt nicht, dass der Code schon angepasst wurde.

### Русский (перевод выполнен с помощью ИИ и отредактирован; носителями языка пока не проверен)
- **От REST мы полностью отказываемся; новые API больше не создаются в стиле REST.** API, к которым обращаются из браузера или через `curl`, используют **унарные вызовы Connect** (`POST /<пакет>.<Service>/<Method>`, `content-type: application/json`, тело запроса — JSON). Для взаимодействия между сервисами применяются **gRPC и gRPC-web** — в том же стиле, что и административный API RPoem (`open_runo.admin.v1.Admin`). Потоковая передача данных добавляется лишь тогда, когда в ней действительно возникает необходимость.
- **Существующие REST-эндпоинты переводятся поэтапно — по мере того, как с ними приходится работать.** После перевода старый REST-маршрут удаляется. Пока миграция не завершена, оставшиеся эндпоинты сохраняются, но **новые не добавляются**.
- **Работа с JSON унифицирована на основе RS-JSON**: чтение — через `from_str_secure` или `parse_secure` (с ограничениями на размер, глубину вложенности и повторяющиеся ключи), запись — через `rust_json::fast`. `prost` в браузерный WASM не включается, поскольку это увеличило бы размер файла.
- **Исключения (интерфейсы, форму которых определяет чужой стандарт, а не наш собственный API)**: ACME, обратные вызовы OAuth/OIDC, вебхуки сторонних сервисов (например, GitHub), проверки работоспособности, раздача статических файлов, OTLP и тому подобное. Такие интерфейсы принимают обычный HTTP, как того требует соответствующий стандарт.
- Эталонные реализации: `RPoem` (`open_runo.admin.v1.Admin`) и `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Примечание: соответствует ли код конкретного репозитория этой политике, зависит от самого репозитория. Данный раздел лишь фиксирует политику и не означает, что код уже изменён.

## API 方針の補足: 用語の整理と使い分け (2026-11-04)

### 日本語
**1つに統一するものではなく、別の層の話です。** 「REST の代わり」になるのは Connect・gRPC・GraphQL だけで、WASM は画面を作る技術です。

| 用語 | 何か | REST の代わりか |
|---|---|---|
| REST | URL と HTTP メソッドで操作を表す API の作り方 | 全廃する側 |
| **Connect** | `POST /サービス名/メソッド名` に JSON を送る形式。`curl` でもブラウザの `fetch` でも呼べる | はい(**採用**) |
| **gRPC** | 同じ「サービス/メソッド」の考え方を、バイナリ(protobuf)と HTTP/2 で行う形式。速く、ストリーミングも得意 | はい(**サービス同士に採用**) |
| gRPC-web | gRPC のブラウザ向けの変形版 | はい(必要なら) |
| GraphQL | 欲しい項目を問い合わせる形式 | 一部だけ(**問い合わせ(読み取り)専用**) |
| WASM | Rust をブラウザの中で動かす仕組み | いいえ(画面を作る技術) |

- **ブラウザの画面や `curl` から呼ぶ API は Connect**(POST、JSON を RS-JSON で読み書き)。ブラウザの WASM は素の gRPC を話せず、Connect なら `fetch` のままで、`prost` を足さずに済む(画面のサイズも増えない)。
- **サービス同士の通信(サーバー間、重い処理、ストリーミング)は gRPC。** 多くは Connect で足りるので、ストリーミングが必要になった所だけ gRPC に上げる。
- **GraphQL は、まとめて問い合わせたいときの読み取り専用。** 書き込み(操作)には使わない。
- **WASM は画面を作る技術として、そのまま使う。** 画面から呼ぶ API が Connect になっただけ。
- 外部の規格が形を決めるもの(ACME、OAuth のコールバック、第三者の Webhook、ヘルスチェック、静的ファイル、OTLP)は、規格どおりの HTTP のまま。
- **迷ったら Connect。**

### English
**These are not alternatives to unify; they sit at different layers.** Only Connect, gRPC and GraphQL can replace REST; WASM is a way to build the UI.

| Term | What it is | Replaces REST? |
|---|---|---|
| REST | API style that expresses operations through URLs and HTTP methods | The thing being abolished |
| **Connect** | `POST /Service/Method` with a JSON body; callable from `curl` and from a browser `fetch` | Yes (**adopted**) |
| **gRPC** | The same service/method idea over binary (protobuf) and HTTP/2; fast, good at streaming | Yes (**for service-to-service**) |
| gRPC-web | A browser-friendly variant of gRPC | Yes (if needed) |
| GraphQL | A query language: ask for exactly the fields you want | Partly (**read-only queries**) |
| WASM | Runs Rust inside the browser | No (a UI technology) |

- **APIs called from browser screens or `curl` use Connect** (POST, JSON read and written with RS-JSON). Browser WASM cannot speak plain gRPC; with Connect it stays a `fetch`, and `prost` is not needed (the binary does not grow).
- **Service-to-service calls (server to server, heavy work, streaming) use gRPC.** Connect is enough in most places; move a call to gRPC only where streaming is actually needed.
- **GraphQL is read-only**, for queries that gather several pieces of data. It is not used for writes (operations).
- **WASM stays as the way to build the UI.** The API it calls simply became Connect.
- Interfaces whose shape an outside standard dictates (ACME, OAuth callbacks, third-party webhooks, health checks, static files, OTLP) stay plain HTTP.
- **When in doubt, use Connect.**

### Deutsch (KI-Übersetzung, sprachlich überarbeitet; noch nicht von Muttersprachlern geprüft)
**Es geht nicht darum, eine einzige Technik auszuwählen – die Begriffe liegen auf unterschiedlichen Ebenen.** Als Ersatz für REST kommen nur Connect, gRPC und GraphQL in Frage; WASM dagegen ist eine Technik, mit der die Benutzeroberfläche gebaut wird.

| Begriff | Was ist das? | Ersatz für REST? |
|---|---|---|
| REST | Ein API-Stil, bei dem Operationen über URLs und HTTP-Methoden ausgedrückt werden | wird abgeschafft |
| **Connect** | `POST /Dienst/Methode` mit JSON im Body; aufrufbar mit `curl` ebenso wie mit `fetch` im Browser | ja (**gewählt**) |
| **gRPC** | Dasselbe Prinzip aus Dienst und Methode, aber über binäres protobuf und HTTP/2; schnell und gut für Streaming geeignet | ja (**zwischen Diensten**) |
| gRPC-web | Eine für den Browser angepasste Variante von gRPC | ja (bei Bedarf) |
| GraphQL | Abfragesprache, mit der man genau die benötigten Felder anfordert | teilweise (**nur für lesende Abfragen**) |
| WASM | Führt Rust-Code direkt im Browser aus | nein (Technik für die Oberfläche) |

- **APIs, die von Browseroberflächen oder per `curl` aufgerufen werden, verwenden Connect** (POST; JSON wird mit RS-JSON gelesen und geschrieben). WASM im Browser kann kein reines gRPC sprechen. Mit Connect bleibt es bei einem gewöhnlichen `fetch`, und `prost` ist nicht nötig – die WASM-Datei wird dadurch nicht größer.
- **Für die Kommunikation zwischen Diensten (Server zu Server, rechenintensive Aufgaben, Streaming) wird gRPC eingesetzt.** In den meisten Fällen reicht Connect aus; auf gRPC wird nur dort umgestellt, wo Streaming tatsächlich gebraucht wird.
- **GraphQL dient ausschließlich lesenden Abfragen**, wenn mehrere Informationen gebündelt abgefragt werden sollen. Für Schreibzugriffe (Operationen) wird es nicht verwendet.
- **WASM bleibt die Technik für die Oberfläche.** Geändert hat sich lediglich, dass die aufgerufene API nun auf Connect beruht.
- Schnittstellen, deren Form durch einen externen Standard festgelegt ist (ACME, OAuth-Callbacks, Webhooks von Drittanbietern, Health-Checks, statische Dateien, OTLP), bleiben gewöhnliches HTTP.
- **Im Zweifel: Connect.**

### Русский (перевод выполнен с помощью ИИ и литературно отредактирован; носителями языка пока не проверен)
**Это не варианты, из которых нужно выбрать один, а технологии разных уровней.** Заменить REST могут только Connect, gRPC и GraphQL; WASM же — это способ создания пользовательского интерфейса.

| Термин | Что это | Заменяет REST? |
|---|---|---|
| REST | Стиль построения API, при котором операции выражаются через URL и HTTP-методы | отменяется |
| **Connect** | `POST /Сервис/Метод` с телом в формате JSON; вызывается как из `curl`, так и из браузерного `fetch` | да (**выбран**) |
| **gRPC** | Тот же принцип «сервис — метод», но поверх двоичного формата protobuf и HTTP/2; работает быстро и хорошо подходит для потоковой передачи | да (**для связи между сервисами**) |
| gRPC-web | Адаптированный для браузера вариант gRPC | да (при необходимости) |
| GraphQL | Язык запросов: клиент запрашивает ровно те поля, которые ему нужны | частично (**только запросы на чтение**) |
| WASM | Позволяет выполнять код на Rust прямо в браузере | нет (технология для интерфейса) |

- **API, которые вызываются из браузерных интерфейсов или через `curl`, строятся на Connect** (POST; JSON читается и записывается через RS-JSON). Браузерный WASM не умеет работать с «чистым» gRPC. С Connect достаточно обычного `fetch`, а `prost` не требуется — размер WASM-файла не увеличивается.
- **Для обмена между сервисами (сервер — сервер, ресурсоёмкие задачи, потоковая передача) применяется gRPC.** В большинстве случаев достаточно Connect; на gRPC переходят только там, где потоковая передача действительно необходима.
- **GraphQL используется только для чтения**, когда нужно получить сразу несколько связанных данных. Для записи (операций) он не применяется.
- **WASM по-прежнему остаётся технологией для интерфейса.** Изменилось лишь то, что вызываемый им API теперь построен на Connect.
- Интерфейсы, форма которых задана внешним стандартом (ACME, обратные вызовы OAuth, вебхуки сторонних сервисов, проверки работоспособности, статические файлы, OTLP), остаются обычным HTTP.
- **Если есть сомнения — выбирайте Connect.**
