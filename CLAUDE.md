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
