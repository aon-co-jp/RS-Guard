#!/usr/bin/env bash
# RS-Guard installer for Linux.
# Honest scope: builds the `rs-guard` CLI from source with cargo (no
# prebuilt binary signing/packaging pipeline exists yet) and installs it to
# ~/.local/bin. This tool does not replace your antivirus — it runs
# alongside it (a repo/dependency pattern scanner, plus an optional
# ClamAV wrapper if ClamAV is separately installed). Requires: git, curl,
# a Rust toolchain (installed automatically via rustup if missing).
set -euo pipefail

INSTALL_DIR="${RS_GUARD_HOME:-$HOME/.local/rs-guard}"
BIN_DIR="${RS_GUARD_BIN_DIR:-$HOME/.local/bin}"
REPO_URL="https://github.com/aon-co-jp/RS-Guard.git"

echo "== RS-Guard installer (Linux) =="

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust toolchain not found; installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

if [ ! -d "$INSTALL_DIR" ]; then
  git clone "$REPO_URL" "$INSTALL_DIR"
else
  echo "Existing install found at $INSTALL_DIR, pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only
fi

cd "$INSTALL_DIR"
cargo build --release

mkdir -p "$BIN_DIR"
cp "$INSTALL_DIR/target/release/rs-guard" "$BIN_DIR/rs-guard"

echo
echo "Installed: $BIN_DIR/rs-guard"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: $BIN_DIR is not on your PATH. Add it, e.g.: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo
echo "Checking for ClamAV (optional, used by 'rs-guard scan-file')..."
"$BIN_DIR/rs-guard" doctor || true

echo
echo "Usage:"
echo "  rs-guard scan-repos /path/to/your/repos   # dependency-name + suspicious-script scan"
echo "  rs-guard scan-file /path/to/file-or-dir   # delegates to ClamAV if installed"
echo "  rs-guard doctor                           # check ClamAV availability"
