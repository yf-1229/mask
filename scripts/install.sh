#!/bin/sh
#
# mask — one-line install.
#
#   curl -fsSL https://mask.branchead.com/install.sh | sh
#
# Downloads the release binary for this machine, checks it against the release's
# SHA256SUMS, and puts it on your PATH. That is all it does:
#
#   - no configuration file is written (mask.toml holds your upstream API key,
#     so it stays yours to create, mode 600, in ~/.config/mask);
#   - no service is started, no port is opened, no key is read;
#   - nothing is installed outside the prefix you choose.
#
# Re-run it to upgrade. `--uninstall` removes the binary and leaves your config
# and dictionary alone.

set -eu

PROG=mask
REPO=yf-1229/mask
GITHUB_BASE="https://github.com/$REPO/releases"

die() {
	printf 'mask install: %s\n' "$*" >&2
	exit 1
}

info() { printf '%s\n' "$*"; }

warn() { printf 'mask install: warning: %s\n' "$*" >&2; }

usage() {
	cat <<EOF
Install $PROG from the $REPO releases.

Usage: sh install.sh [options]

  --prefix DIR      install under DIR, binary at DIR/bin/$PROG
                    (default: ~/.local, or /usr/local as root)
  --system          shorthand for --prefix /usr/local, needs root
  --version VER     install this release instead of the latest
  --base-url URL    where the release assets live
                    (default: $GITHUB_BASE)
                    a mirror is expected at URL/<tag>/<asset>, tag being
                    "latest" or "v<version>"; file:// URLs work
  --target TRIPLE   override the detected platform triple
  --no-verify       skip the SHA256SUMS check — installing an unverified binary
  --dry-run         say what would happen, download nothing
  --uninstall       remove the binary from the prefix
  -h, --help        this text

Environment: MASK_INSTALL_PREFIX, MASK_VERSION, MASK_INSTALL_BASE,
MASK_INSTALL_TARGET.

The script itself is short on purpose — read it before you pipe it:
  curl -fsSL https://mask.branchead.com/install.sh | less
EOF
}

# --- arguments ---------------------------------------------------------------

BASE=${MASK_INSTALL_BASE:-$GITHUB_BASE}
VERSION=${MASK_VERSION:-latest}
PREFIX=${MASK_INSTALL_PREFIX:-}
TARGET=${MASK_INSTALL_TARGET:-}
SYSTEM=0
VERIFY=1
DRY_RUN=0
UNINSTALL=0

while [ $# -gt 0 ]; do
	case "$1" in
	--prefix) [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
	--prefix=*) PREFIX=${1#*=}; shift ;;
	--system) SYSTEM=1; shift ;;
	--version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
	--version=*) VERSION=${1#*=}; shift ;;
	--base-url) [ $# -ge 2 ] || die "--base-url needs a value"; BASE=$2; shift 2 ;;
	--base-url=*) BASE=${1#*=}; shift ;;
	--target) [ $# -ge 2 ] || die "--target needs a value"; TARGET=$2; shift 2 ;;
	--target=*) TARGET=${1#*=}; shift ;;
	--no-verify) VERIFY=0; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	--uninstall) UNINSTALL=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown option: $1 (try --help)" ;;
	esac
done

BASE=${BASE%/}

# --- platform ----------------------------------------------------------------

detect_target() {
	os=$(uname -s 2>/dev/null || echo unknown)
	arch=$(uname -m 2>/dev/null || echo unknown)
	case "$os" in
	Linux)
		case "$arch" in
		x86_64 | amd64) echo x86_64-unknown-linux-gnu ;;
		aarch64 | arm64) echo aarch64-unknown-linux-gnu ;;
		*) die "no prebuilt binary for Linux/$arch — build from source: cargo install --path . (or use the .deb)" ;;
		esac
		;;
	Darwin)
		case "$arch" in
		x86_64) echo x86_64-apple-darwin ;;
		arm64 | aarch64) echo aarch64-apple-darwin ;;
		*) die "no prebuilt binary for macOS/$arch" ;;
		esac
		;;
	*)
		die "no prebuilt binary for $os — build from source (cargo install --path .), or pick one from https://github.com/$REPO/releases"
		;;
	esac
}

[ -n "$TARGET" ] || TARGET=$(detect_target)

# --- prefix ------------------------------------------------------------------

if [ -z "$PREFIX" ]; then
	if [ "$SYSTEM" = 1 ]; then
		PREFIX=/usr/local
	elif [ "$(id -u)" = 0 ]; then
		PREFIX=/usr/local
	else
		PREFIX=${HOME:-}/.local
	fi
fi
[ -n "$PREFIX" ] && [ "$PREFIX" != /.local ] || die "HOME is unset — pass --prefix DIR"
case "$PREFIX" in
/) ;;
*) PREFIX=${PREFIX%/} ;;
esac

# Say it before touching anything: --system is a system-wide write, and a
# half-explained permission error under /usr/local is how people end up running
# the whole download as root.
if [ "$SYSTEM" = 1 ] && [ "$(id -u)" != 0 ]; then
	die "--system installs to /usr/local and needs root: sudo sh install.sh --system"
fi

bin_dir="$PREFIX/bin"
bin="$bin_dir/$PROG"

if [ "$UNINSTALL" = 1 ]; then
	if [ -e "$bin" ]; then
		rm -f "$bin" || die "cannot remove $bin (try sudo)"
		info "removed $bin"
	else
		info "nothing installed at $bin"
	fi
	info "left in place on purpose: your config (~/.config/mask/mask.toml) and dictionary"
	exit 0
fi

# --- release url -------------------------------------------------------------

case "$VERSION" in
latest | "")
	# GitHub resolves this redirect to the newest release, so an unpinned
	# install picks up upgrades by definition. Pin with --version to make it
	# repeatable.
	TAG=latest
	;;
*)
	TAG="v$(printf '%s' "$VERSION" | sed 's/^v//')"
	;;
esac

asset_url() { # asset-name
	if [ "$BASE" = "$GITHUB_BASE" ]; then
		# GitHub's own layout: /releases/latest/download/<asset> for the newest
		# release, /releases/download/<tag>/<asset> for a pinned one.
		if [ "$TAG" = latest ]; then
			printf '%s/latest/download/%s\n' "$BASE" "$1"
		else
			printf '%s/download/%s/%s\n' "$BASE" "$TAG" "$1"
		fi
	else
		# A mirror: <base>/<tag>/<asset>, tag being "latest" or "v<version>".
		printf '%s/%s/%s\n' "$BASE" "$TAG" "$1"
	fi
}

asset="$PROG-$TARGET"
url=$(asset_url "$asset")
sums_url=$(asset_url SHA256SUMS)

if [ "$DRY_RUN" = 1 ]; then
	info "platform   $TARGET"
	info "release    $TAG"
	info "download   $url"
	if [ "$VERIFY" = 1 ]; then
		info "verify     $sums_url"
	fi
	info "install    $bin"
	exit 0
fi

# --- download ----------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # url dest
	url=$1
	dest=$2
	case "$url" in
	file://*)
		# A local mirror for tests and airgapped hosts. The caller owns the
		# message, because "cannot read the binary" and "cannot read the
		# checksums" mean different things to the user.
		cp "${url#file://}" "$dest" || return 1
		return 0
		;;
	https://*) ;;
	http://localhost/* | http://127.0.0.1/* | http://127.0.0.1:* | "http://[::1]"*)
		warn "plain http from a loopback address; the download is not protected in transit"
		;;
	http://*)
		# The binary is installed and then runs with your API key. A plain-http
		# mirror anywhere but loopback is a man in the middle by construction.
		die "refusing plain http from $(printf '%s' "$url" | sed -e 's|^http://||' -e 's|[:/].*||') — use https, or a file:// mirror"
		;;
	*) die "unsupported URL scheme: $url" ;;
	esac

	if have curl; then
		case "$url" in
		https://*) curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 2 -o "$dest" "$url" ;;
		*) curl -fsSL --retry 2 -o "$dest" "$url" ;;
		esac
	elif have wget; then
		wget -q -O "$dest" "$url"
	else
		die "neither curl nor wget is installed"
	fi
}

sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	elif have shasum; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif have openssl; then
		openssl dgst -sha256 "$1" | sed 's/.*= *//'
	else
		die "no SHA-256 tool (sha256sum, shasum or openssl) — pass --no-verify to skip the check"
	fi
}

need_download_dir() {
	mkdir -p "$bin_dir" || die "cannot create $bin_dir — use --prefix DIR you own, or sudo for --system"
	[ -w "$bin_dir" ] || die "$bin_dir is not writable — use --prefix DIR you own, or sudo for --system"
}

tmp=
sums=
cleanup() {
	[ -n "$tmp" ] && rm -f "$tmp"
	[ -n "$sums" ] && rm -f "$sums"
	return 0
}
trap cleanup EXIT INT TERM HUP

need_download_dir

tmp=$(mktemp "${TMPDIR:-/tmp}/mask-download.XXXXXX") || die "mktemp failed"
info "downloading $PROG $TAG ($TARGET)"
fetch "$url" "$tmp" || die "download failed: $url"
[ -s "$tmp" ] || die "downloaded an empty file from $url"

if [ "$VERIFY" = 1 ]; then
	sums=$(mktemp "${TMPDIR:-/tmp}/mask-sums.XXXXXX") || die "mktemp failed"
	fetch "$sums_url" "$sums" || die "cannot fetch $sums_url — refusing to install an unverified binary (--no-verify overrides)"
	expected=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$sums")
	[ -n "$expected" ] || die "$sums_url has no line for $asset — refusing to install an unverified binary"
	actual=$(sha256_of "$tmp")
	if [ "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" != "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" ]; then
		die "checksum mismatch for $asset — expected $expected, got $actual; nothing was installed"
	fi
	info "checksum  ok ($asset)"
else
	warn "--no-verify: installing a binary whose checksum nobody checked"
fi

# --- install -----------------------------------------------------------------

staged="$bin_dir/.$PROG.$$.new"
stage_failed() {
	rm -f "$staged"
	die "$*"
}
cp "$tmp" "$staged" || stage_failed "cannot write $staged"
chmod 0755 "$staged" || stage_failed "cannot make $staged executable"
# Same directory, so the rename replaces the file when upgrading an installed
# mask: a half-written binary never sits on PATH.
mv -f "$staged" "$bin" || stage_failed "cannot replace $bin"

reported=$("$bin" --version 2>/dev/null) || reported=
if [ -z "$reported" ]; then
	warn "installed $bin, but it will not run here — probably a newer C library than this system has"
	warn "on Debian/Ubuntu, use the .deb from https://github.com/$REPO/releases instead"
else
	info "installed $reported -> $bin"
fi

case ":${PATH:-}:" in
*":$bin_dir:"*) ;;
*)
	info ""
	info "$bin_dir is not on your PATH yet:"
	info "  echo 'export PATH=\"$bin_dir:\$PATH\"' >> ~/.profile && . ~/.profile"
	;;
esac

info ""
info "next:"
info "  1. mkdir -p ~/.config/mask && chmod 700 ~/.config/mask"
info "     curl -fsSL https://raw.githubusercontent.com/$REPO/main/mask.toml.example \\"
info "       -o ~/.config/mask/mask.toml && chmod 600 ~/.config/mask/mask.toml"
info "     \$EDITOR ~/.config/mask/mask.toml   # upstream.base_url, upstream.api_key"
info "  2. mask serve        # from your own terminal: the operator token is printed there"
info "  3. point your client at http://127.0.0.1:8080"
