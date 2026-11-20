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

## ライセンス / License

Apache-2.0(`LICENSE`参照)。 / Apache-2.0 (see `LICENSE`).

## 未実装・今後 / Not yet done

Android版インストーラー、ブラウザからスキャンを実行するログイン制画面(easy-web.tokyo統合)は未着手です。 / The Android installer and the login-protected web UI (easy-web.tokyo integration) are not implemented yet.

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
