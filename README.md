# RS-Guard

日本語 | [English](#english)

このエコシステム(`F:\runo` / `aon-co-jp`)のリポジトリ・依存パッケージに
悪意あるコードが混入していないかを静的にチェックするサプライチェーン
スキャナ。加えて、既にClamAVが導入されている環境では`clamdscan`/`clamscan`
へ処理を委譲して実ファイル/EXEをスキャンできる。

> ⚠️ **正直な開示(最重要)**: RS-Guardは**既存のアンチウイルスを
> 置き換えるものではなく、併用するツール**です。独自のウイルス定義
> データベースや検知エンジンは持ちません。
> - 依存パッケージ名のブロックリストは、過去に実際に摘発された著名な
>   サプライチェーン攻撃(typosquat等)を手動で抜粋した**静的スナップ
>   ショット**であり、ライブ更新される脅威フィードではありません。
>   「引っかからない=安全」ではなく「引っかかったら高確度で危険」という
>   一方向の判定にのみ使ってください。
> - スクリプトの疑わしいパターン検出は正規表現ベースの**静的解析**で、
>   難読化・新種の攻撃は検出できません。
> - 実ファイルスキャンは**ClamAVが別途インストールされている場合のみ**
>   機能します(未導入なら正直にその旨を返し、黙って「クリーン」とは
>   報告しません)。
> - **破壊的操作・自動実行の検出はすべて実行前の静的検査**であり、
>   USBメモリ挿入時やメール添付を開く際に**カーネルレベルでリアル
>   タイムに阻止する常駐ガードではありません**。実際にフォーマットや
>   全削除を実行時に強制阻止するには、Windowsのファイルシステム
>   ミニフィルタドライバやLinuxのLSM/eBPFによる特権常駐サービスが
>   必要で、これはEDR製品の領域です。RS-Guardが提供するのは
>   「USBの中身を開く前」「メール添付を実行する前」に検査して警告する
>   予防であり、OS標準の実行時防御(Windowsの「コントロールされた
>   フォルダー アクセス」・AppLocker、LinuxのSELinux/AppArmor)と
>   併用してください。
> - **プロジェクト内のフォルダ削除は誤検知しません**——`rm -rf
>   ./target`のような開発時の通常操作は許容し、ドライブ全体・
>   システムルートを対象にした操作のみを危険と判定します。

## 位置づけ: 「ClamAV＋α」

RS-Guardは**ClamAVを置き換えるものではなく、ClamAVを土台にした「＋α」**
です。ClamAVが実ファイル/EXEの本格スキャン(数十万件超のシグネチャDB)を
担う一方、RS-Guardは①依存パッケージ名のサプライチェーン検査、②ソース
コード中のスパイウェア的挙動パターン検査、③破壊的操作/自動実行の検出、
④正規表現をすり抜けた言い換えコードのAI二次判定——という、ClamAVが
カバーしない領域を補います。**「ClamAV = 実ファイルの最終防衛線」
「RS-Guard = 開発中のコード・依存関係・スクリプトに対する早期警戒網」**
という補完関係です。

## できること

- **`rs-guard scan-repos <dir>`**: `Cargo.toml`/`package.json`の依存名を
  ブロックリストと照合し、ソース/スクリプト(`.sh`/`.ps1`/`.js`/`.py`等)に
  `curl | bash`パイプ・PowerShell `-EncodedCommand`・base64復号後の即時実行
  などの疑わしいパターンが無いかを検査する。加えて以下も検出する:
  - **ウイルス検体シグネチャ**(EICARテストファイル・シェルコード
    ローダー・ドロッパー・ランサムウェア型の一括暗号化)。
  - **スパイウェア挙動**(無断の情報収集〈SSH鍵・ブラウザ保存認証情報・
    環境変数・キーロガー〉・持ち出し〈Webhook・DNSトンネリング〉・
    常駐/自動巡回〈cron・systemdタイマー・レジストリRun・
    スケジュールタスク・定期ビーコン〉)。
  - **破壊的操作**(USBメモリのautorun仕込み・Office文書マクロの自動
    実行・ドライブ全体のフォーマット/全削除・バックアップ破壊)。
    **プロジェクト内の通常のフォルダ削除(`rm -rf ./target`等)は誤検知
    せず許容する**——検出対象はドライブ全体・システムルートを狙った
    操作のみ(下記の正直な開示を参照)。
  `--ai`でaruaru-llmへの二次判定(埋め込み類似度によるAI判定)も有効化
  できる。`--json`でCI連携用の出力も可能。
- **`rs-guard scan-file <path>`**: ClamAVへ委譲して実ファイル/ディレクトリを
  スキャンする。ClamAV未導入なら終了コード2でエラーを返す。
- **`rs-guard doctor`**: ClamAVの実行可否を確認し、未導入ならOS別の
  インストール手順を表示する。
- **`rs-guard serve --port <n>`**: 紹介・ダウンロード用の最小HTTPサーバー
  (`runo.tokyo/RS-Guard`での公開ページ用)。

## 運用構成(このエコシステム)

- **runo.tokyo/RS-Guard**: 紹介・ダウンロードページ(`rs-guard serve`)。
- **easy-web.tokyo/RS-Guard**: ログイン後にブラウザからスキャンを実行できる
  実運用画面(`open-easy-web`本体へ統合、既存のOTP/TOTPログイン配下)。

## インストール

Web UI(`runo.tokyo/RS-Guard`)の「Install locally」から、Linux向け
`install.sh`・Windows向け`install.ps1`をダウンロードできる。いずれも
ソースからcargoでビルドする(署名済みバイナリ・deb/msiパッケージングは
未実装、正直に開示)。**Androidは未対応**(Kotlin/Javaの別ツールチェーンが
必要なため、将来のイテレーションで検討)。

2026-07-23、`.github/workflows/release.yml`を追加し、タグ(`v0.1.0`〜)
push時にLinux x86_64・Windows x86_64向けのプリビルド済みバイナリを
[GitHub Releases](https://github.com/aon-co-jp/RS-Guard/releases)へ
自動添付するようにした(`install.sh`/`install.ps1`のソースビルド方式は
そのまま維持、プリビルド済みバイナリを直接使いたい場合の代替手段として
提供)。

---

## English

A supply-chain scanner that statically checks the repositories and
dependency packages of this ecosystem (`F:\runo` / `aon-co-jp`) for signs of
malicious code. When ClamAV is already installed, it can also delegate real
file/EXE scanning to `clamdscan`/`clamscan`.

> ⚠️ **Honest disclosure (most important)**: RS-Guard **complements your
> existing antivirus rather than replacing it.** It ships no virus-definition
> database or detection engine of its own.
> - The dependency-name blocklist is a **static, manually curated snapshot**
>   of well-known past supply-chain attacks (typosquats, etc.), not a
>   live-updated threat feed. Use it as a one-directional signal: "not
>   flagged" does NOT mean "safe", but "flagged" means "high-confidence
>   dangerous".
> - Suspicious-script detection is regex-based **static analysis**; it cannot
>   catch obfuscated or novel attacks.
> - Real file scanning works **only if ClamAV is separately installed** (if
>   not, it says so honestly rather than silently reporting "clean").
> - **All destructive-operation and auto-execution detection is pre-execution
>   static analysis, not a kernel-level realtime guard** that blocks a USB
>   drive or email attachment the instant it runs. Actually forcing a format
>   or mass-delete to fail at runtime needs a Windows filesystem minifilter
>   driver or a Linux LSM/eBPF-based privileged service — that's EDR-product
>   territory. RS-Guard's job is to inspect *before* you open what's on a USB
>   drive or run an email attachment; pair it with your OS's own runtime
>   defenses (Windows Controlled Folder Access / AppLocker, Linux
>   SELinux/AppArmor).
> - **Ordinary in-project folder deletions are never flagged** — everyday
>   commands like `rm -rf ./target` are allowed; only operations targeting an
>   entire drive or the filesystem root are treated as dangerous.

### Positioning: "ClamAV + alpha"

RS-Guard **does not replace ClamAV — it builds on top of it.** ClamAV covers
real file/EXE scanning (a signature database of hundreds of thousands of
entries). RS-Guard adds what ClamAV doesn't cover: ① supply-chain checks on
dependency package names, ② source-code-level spyware behavior patterns,
③ destructive-operation / unauthorized-auto-exec detection, and ④ an AI
second opinion for reworded code that slips past the regexes. In short:
**"ClamAV = the last line of defense for real files" / "RS-Guard = an early
warning net for code, dependencies, and scripts still being developed."**

### What it does

- **`rs-guard scan-repos <dir>`**: matches `Cargo.toml`/`package.json`
  dependency names against a blocklist, and scans source/scripts (`.sh`,
  `.ps1`, `.js`, `.py`, etc.) for suspicious patterns (`curl | bash` pipes,
  PowerShell `-EncodedCommand`, base64-decode-then-eval, and so on). Also
  detects: **virus signatures** (EICAR test file, shellcode loaders,
  droppers, ransomware-style mass encryption); **spyware behavior**
  (unauthorized data collection — SSH keys, browser credential stores,
  env vars, keyloggers — exfiltration via webhooks/DNS tunneling, and
  persistence/auto-patrol via cron, systemd timers, Windows Run keys,
  scheduled tasks, periodic beacons); and **destructive operations**
  (USB autorun payloads, Office macro auto-execution, whole-drive
  format/wipe, backup destruction) while deliberately NOT flagging
  ordinary in-project folder deletions. `--ai` adds an aruaru-llm
  embedding-similarity second opinion. `--json` for CI integration.
- **`rs-guard scan-file <path>`**: delegates to ClamAV for a real scan;
  returns exit code 2 with an error if ClamAV is not installed.
- **`rs-guard doctor`**: checks ClamAV availability and prints per-OS install
  guidance if missing.
- **`rs-guard serve --port <n>`**: minimal HTTP server for the public
  intro/download page (`runo.tokyo/RS-Guard`).

### Deployment in this ecosystem

- **runo.tokyo/RS-Guard**: intro & download page (`rs-guard serve`).
- **easy-web.tokyo/RS-Guard**: the logged-in operational UI where team members
  run scans from the browser (integrated into `open-easy-web`, behind its
  existing OTP/TOTP login).

### Install

From the "Install locally" section of the web UI, download `install.sh`
(Linux) or `install.ps1` (Windows). Both build from source with cargo (no
signed binaries or deb/msi packaging yet — disclosed honestly). **Android is
not supported** (it needs a separate Kotlin/Java toolchain; planned for a
future iteration).

As of 2026-07-23, `.github/workflows/release.yml` builds and attaches
prebuilt Linux x86_64 / Windows x86_64 binaries to
[GitHub Releases](https://github.com/aon-co-jp/RS-Guard/releases) on every
`v*` tag push, as an alternative to the source-build `install.sh`/`install.ps1`
flow above (which remains unchanged).

## ���C�Z���X / License

Apache-2.0(`LICENSE`�Q��)�B / Apache-2.0 (see `LICENSE`).

## �������E���� / Not yet done

Android�ŃC���X�g�[���[�A�u���E�U����X�L���������s���郍�O�C�������(easy-web.tokyo����)�͖�����ł��B / The Android installer and the login-protected web UI (easy-web.tokyo integration) are not implemented yet.

