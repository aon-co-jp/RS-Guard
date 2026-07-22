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

## できること

- **`rs-guard scan-repos <dir>`**: `Cargo.toml`/`package.json`の依存名を
  ブロックリストと照合し、ソース/スクリプト(`.sh`/`.ps1`/`.js`/`.py`等)に
  `curl | bash`パイプ・PowerShell `-EncodedCommand`・base64復号後の即時実行
  などの疑わしいパターンが無いかを検査する。`--json`でCI連携用の出力も可能。
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

### What it does

- **`rs-guard scan-repos <dir>`**: matches `Cargo.toml`/`package.json`
  dependency names against a blocklist, and scans source/scripts (`.sh`,
  `.ps1`, `.js`, `.py`, etc.) for suspicious patterns (`curl | bash` pipes,
  PowerShell `-EncodedCommand`, base64-decode-then-eval, and so on). `--json`
  for CI integration.
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
