#!/bin/sh
# Install Razorwire on Linux or macOS from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/razorwire-dev/razorwire/main/install.sh | sh
#
# GITHUB_TOKEN is only needed to install from a private copy of the
# repository: set it to a token that can read that copy (a fine-grained token
# with "Contents: read" is enough), and fetch this script with it too.
#
# Settings, all optional:
#   RAZORWIRE_VERSION       a release tag like v0.2.0 (default: the latest)
#   RAZORWIRE_INSTALL_DIR   where the binary goes (default: ~/.local/bin)
#   GITHUB_TOKEN            only for a private copy of the repository
#
# The download is checked against the release's SHA256SUMS before anything
# is installed.
set -eu

REPO="${RAZORWIRE_REPO:-razorwire-dev/razorwire}"
API="${RAZORWIRE_API:-https://api.github.com}"
WEB="${RAZORWIRE_WEB:-https://github.com}"
VERSION="${RAZORWIRE_VERSION:-latest}"
DIR="${RAZORWIRE_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'razorwire install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "this needs $1"; }
need curl
need tar
need uname
need mktemp

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  fail "this needs sha256sum or shasum to check the download"
fi

target="${RAZORWIRE_TARGET:-}"
if [ -z "$target" ]; then
  os=$(uname -s)
  arch=$(uname -m)
  case "$os/$arch" in
    Linux/x86_64 | Linux/amd64) target=x86_64-unknown-linux-musl ;;
    Darwin/arm64 | Darwin/aarch64) target=aarch64-apple-darwin ;;
    Darwin/x86_64) target=x86_64-apple-darwin ;;
    MINGW* | MSYS* | CYGWIN*) fail "on Windows, run install.ps1 in PowerShell instead" ;;
    *) fail "there is no release build for $os $arch yet. Build it from source: cargo install --path ." ;;
  esac
fi
asset="razorwire-$target.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "${GITHUB_TOKEN:-}" ]; then
  # A private repository's release files can only be fetched through the API.
  if [ "$VERSION" = latest ]; then
    release="$API/repos/$REPO/releases/latest"
  else
    release="$API/repos/$REPO/releases/tags/$VERSION"
  fi
  curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    "$release" -o "$tmp/release.json" ||
    fail "cannot read the release from GitHub. Check GITHUB_TOKEN and RAZORWIRE_VERSION"
  asset_url() {
    tr ',{}' '\n\n\n' <"$tmp/release.json" | sed -n \
      -e 's/^[[:space:]]*"url"[[:space:]]*:[[:space:]]*"\(.*\/releases\/assets\/[0-9]*\)"[[:space:]]*$/url \1/p' \
      -e 's/^[[:space:]]*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)"[[:space:]]*$/name \1/p' |
      awk -v want="$1" '$1 == "url" { url = $2 } $1 == "name" && $2 == want && url != "" { print url; exit }'
  }
  fetch() {
    url=$(asset_url "$1")
    [ -n "$url" ] || fail "the release has no $1"
    # curl does not pass the token on when GitHub redirects to its storage.
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/octet-stream" \
      "$url" -o "$2" || fail "cannot download $1"
  }
else
  if [ "$VERSION" = latest ]; then
    base="$WEB/$REPO/releases/latest/download"
  else
    base="$WEB/$REPO/releases/download/$VERSION"
  fi
  fetch() {
    curl -fsSL "$base/$1" -o "$2" ||
      fail "cannot download $1. Check your internet connection and RAZORWIRE_VERSION"
  }
fi

say "Downloading $asset ($VERSION)"
fetch "$asset" "$tmp/$asset"
fetch SHA256SUMS "$tmp/SHA256SUMS"
expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || fail "SHA256SUMS does not list $asset, so it was not installed"
actual=$(checksum "$tmp/$asset")
[ "$expected" = "$actual" ] || fail "$asset does not match its checksum, so it was not installed"

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$DIR"
cp "$tmp/razorwire-$target/razorwire" "$tmp/razorwire.new"
chmod 755 "$tmp/razorwire.new"
mv -f "$tmp/razorwire.new" "$DIR/razorwire"

say "Installed $("$DIR/razorwire" --version) at $DIR/razorwire"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) say "$DIR is not on your PATH. Add it with: export PATH=\"$DIR:\$PATH\"" ;;
esac
say "Next: razorwire help. The example policy and executor are in the release archive and the repository."
