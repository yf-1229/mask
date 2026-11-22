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

# A mirror reached with https://user:token@host/ is a normal configuration, and
# the token must not end up in a message someone pastes into an issue.
redact() { printf '%s\n' "$1" | sed 's|^\([A-Za-z][A-Za-z0-9+.-]*://\)[^/]*@|\1***@|'; }

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
                    "latest" or "v<version>". https, file:// and — only for
                    this machine — http on a loopback host are accepted;
                    credentials in an http URL are refused, and a token in an
                    https URL is never echoed
  --target TRIPLE   override the detected platform triple
  --no-verify       skip the SHA256SUMS check — installing an unverified binary
  --dry-run         say what would happen, download and remove nothing
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
# The default was built from $HOME above; if HOME was empty it produced a path
# that is not a home directory, so say what to do instead of installing there.
[ "$PREFIX" != /.local ] || die "HOME is unset — pass --prefix DIR"
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
	if [ ! -e "$bin" ]; then
		info "nothing installed at $bin"
	elif [ "$DRY_RUN" = 1 ]; then
		# --dry-run is the flag people are told to try before trusting the
		# script; it must not be the one path that deletes something.
		info "would remove $bin"
		exit 0
	else
		rm -f "$bin" || die "cannot remove $bin (try sudo)"
		info "removed $bin"
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
	info "download   $(redact "$url")"
	if [ "$VERIFY" = 1 ]; then
		info "verify     $(redact "$sums_url")"
	fi
	info "install    $bin"
	exit 0
fi

# --- download ----------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# The host of a URL, without scheme, credentials, port or path.
#
# A prefix match on "http://127.0.0.1" is not an origin check: `curl` reads
# `http://127.0.0.1:9999@evil.example/x` as credentials for evil.example, and
# `[::1]evil.example` is a name, not the address in brackets. So the host is
# parsed out, and a bracket form is only accepted when nothing but an optional
# port follows it.
url_host() {
	_rest=${1#*://}
	_rest=${_rest%%[/?#]*}
	# Defensive: callers refuse credentials before asking for the host. If one
	# stops doing that, this still compares the host rather than the userinfo.
	case "$_rest" in
	*@*) _rest=${_rest##*@} ;;
	esac
	case "$_rest" in
	\[*)
		_host=${_rest%%]*}
		case "${_rest#"$_host"]}" in
		"" | :*) printf '%s]\n' "$_host" ;;
		*) printf '%s\n' "$_rest" ;;
		esac
		;;
	*) printf '%s\n' "${_rest%%:*}" ;;
	esac
}

fetch() { # url dest
	_url=$1
	_dest=$2
	case "$_url" in
	file://*)
		# A local mirror for tests and airgapped hosts. The caller owns the
		# message, because "cannot read the binary" and "cannot read the
		# checksums" mean different things to the user.
		cp "${_url#file://}" "$_dest" || return 1
		return 0
		;;
	esac

	# Credentials in a plain-http URL are how a loopback-looking prefix hides a
	# remote host. Over https they are a normal way to reach a private mirror, so
	# the refusal lives in the http arm, not here.
	case "$_url" in
	https://*) ;;
	http://*)
		_authority=${_url#*://}
		_authority=${_authority%%[/?#]*}
		case "$_authority" in
		*@*) die "refusing a URL with credentials in it — nothing was downloaded" ;;
		esac
		# The binary is installed and then runs with your API key. Plain http
		# from anywhere but this machine is a man in the middle by construction.
		_host=$(url_host "$_url" | tr '[:upper:]' '[:lower:]')
		case "$_host" in
		localhost | 127.0.0.1 | "[::1]")
			warn "plain http from a loopback address; the download is not protected in transit"
			;;
		"")
			die "refusing plain http to a URL with no host — use https, or a file:// mirror"
			;;
		*) die "refusing plain http from $_host — use https, or a file:// mirror" ;;
		esac
		;;
	*) die "unsupported URL scheme: $(redact "$_url")" ;;
	esac

	# Credentials go to the downloader as an option, not inside the URL: curl and
	# wget quote the URL in their own errors, and `-s` does not silence those.
	# They are still in argv, so `ps` can see them for the length of the
	# download — use a mirror without credentials if that matters.
	_creds=
	case "$_url" in
	*://*@*)
		_scheme=${_url%%://*}
		_rest=${_url#*://}
		_creds=${_rest%%@*}
		_url="$_scheme://${_rest#*@}"
		;;
	esac

	if have curl; then
		set -- -fsSL --retry 2
		if [ -n "$_creds" ]; then
			set -- "$@" --user "$_creds"
		fi
		case "$_url" in
		https://*) set -- "$@" --proto '=https' --proto-redir '=https' --tlsv1.2 ;;
		esac
		curl "$@" -o "$_dest" "$_url"
	elif have wget; then
		set --
		if [ -n "$_creds" ]; then
			_wuser=${_creds%%:*}
			case "$_creds" in
			*:*) _wpass=${_creds#*:} ;;
			*) _wpass= ;;
			esac
			set -- --user="$_wuser" --password="$_wpass"
		fi
		case "$_url" in
		# wget follows a redirect to plain http unless it is told not to.
		https://*) wget --https-only -q "$@" -O "$_dest" "$_url" ;;
		*) wget -q "$@" -O "$_dest" "$_url" ;;
		esac
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
staged=
cleanup() {
	[ -n "$tmp" ] && rm -f "$tmp"
	[ -n "$sums" ] && rm -f "$sums"
	# A signal between the copy and the rename would otherwise leave a
	# dotfile in the user's bin directory forever.
	[ -n "$staged" ] && rm -f "$staged"
	return 0
}
trap cleanup EXIT INT TERM HUP

need_download_dir

tmp=$(mktemp "${TMPDIR:-/tmp}/mask-download.XXXXXX") || die "mktemp failed"
info "downloading $PROG $TAG ($TARGET)"
fetch "$url" "$tmp" || die "download failed: $(redact "$url")"
[ -s "$tmp" ] || die "downloaded an empty file from $(redact "$url")"

if [ "$VERIFY" = 1 ]; then
	sums=$(mktemp "${TMPDIR:-/tmp}/mask-sums.XXXXXX") || die "mktemp failed"
	fetch "$sums_url" "$sums" || die "cannot fetch $(redact "$sums_url") — refusing to install an unverified binary (--no-verify overrides)"
	expected=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$sums")
	[ -n "$expected" ] || die "$(redact "$sums_url") has no line for $asset — refusing to install an unverified binary"
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

if [ "$VERIFY" = 1 ]; then
	reported=$("$bin" --version 2>/dev/null) || reported=
	if [ -z "$reported" ]; then
		warn "installed $bin, but it will not run here — probably a newer C library than this system has"
		warn "on Debian/Ubuntu, use the .deb from https://github.com/$REPO/releases instead"
	else
		info "installed $reported -> $bin"
	fi
else
	# With no checksum to trust, do not also execute what was downloaded.
	info "installed (unverified) -> $bin"
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
info "  1. on a first install, create the config (skip this if you have one):"
info "     mkdir -p ~/.config/mask && chmod 700 ~/.config/mask"
info "     curl -fsSL https://raw.githubusercontent.com/$REPO/main/mask.toml.example \\"
info "       -o ~/.config/mask/mask.toml"
info "     chmod 600 ~/.config/mask/mask.toml   # it will hold your upstream API key"
info "     \$EDITOR ~/.config/mask/mask.toml    # upstream.base_url, upstream.api_key"
info "  2. mask serve        # from your own terminal: the operator token is printed there"
info "  3. point your client at http://127.0.0.1:8080"
