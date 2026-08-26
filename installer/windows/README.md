# このフォルダについて / About this folder

`rs-guard.iss` はこのインストーラーを**作るための** [Inno Setup](https://jrsoftware.org/isinfo.php)
ビルドスクリプトです。`RS-Guard-installer.exe` はこのフォルダ内に実体として置いてあります
(ユーザー指示により、v0.1.0でローカルビルドしたバイナリを直接コミット)。

**⬇ 今すぐダウンロード**: [RS-Guard-installer.exe](RS-Guard-installer.exe)

**正直な開示**: このファイルはビルド成果物であり、`rs-guard.iss`やソースコードを変更しても
自動的には更新されません(手動での再ビルド・再コミットが必要)。CIの`release.yml`は
Windows向けバイナリのzip(`rs-guard-windows-x86_64.zip`、`install.ps1`同梱)を
GitHub Releasesへ公開しますが、この`.exe`インストーラー自体は自動ビルドしていないため、
現時点でこのインストーラーを自動ビルド・公開するCIは無く、このファイルが唯一の
配布経路です。

---

`rs-guard.iss` is the [Inno Setup](https://jrsoftware.org/isinfo.php) script used to **build**
this installer. `RS-Guard-installer.exe` is committed directly in this folder as the actual
binary (built locally from v0.1.0, per user request).

**⬇ Download now**: [RS-Guard-installer.exe](RS-Guard-installer.exe)

**Honest disclosure**: this file is a build artifact — it does not update automatically when
`rs-guard.iss` or the source code changes (it must be manually rebuilt and re-committed). The
`release.yml` CI workflow publishes a Windows binary zip (`rs-guard-windows-x86_64.zip`,
bundled with `install.ps1`) to GitHub Releases, but it does not build this `.exe` installer
itself, so there is currently no CI that auto-builds or publishes this installer — this file
is the only distribution channel for it.
