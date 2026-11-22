#!/bin/sh
#
# Build a Debian binary package (.deb) for mask from an already-built binary.
#
#   packaging/debian/build-deb.sh --binary target/release/mask --output dist
#
# No dpkg-buildpackage, no debhelper, no second copy of the source tree: the
# package is one executable, one man page and the documents. `dpkg-deb` is the
# only tool required, so the same script runs in CI, in a release container and
# on a laptop.
#
# The package deliberately ships no systemd unit and no configuration file. The
# gateway is started by a person from their own terminal (that is where the
# operator token for /admin is printed), and mask.toml holds the upstream API
# key, so it belongs in ~/.config/mask with mode 600 — not in /etc where a
# package postinst would put it and where every user could read it.

set -eu
# A package that depends on the builder's umask is not reproducible: fix the
# modes the tree gets, then override the few files that need more.
umask 022

PROG=mask
MAINTAINER_DEFAULT="Yuta Fujiwara <yuta@branchead.com>"

die() { printf 'build-deb: %s\n' "$*" >&2; exit 1; }
note() { printf 'build-deb: %s\n' "$*" >&2; }

usage() {
	cat <<'EOF'
Usage: packaging/debian/build-deb.sh [options]

  --binary PATH     the built executable        (default: target/release/mask)
  --version VER     package version             (default: from `mask --version`)
  --arch ARCH       amd64 | arm64 | i386 | armhf (default: read from the binary)
  --depends EXPR    override the Depends field  (default: libc6 >= required glibc)
  --maintainer WHO  override the Maintainer field
  --output DIR      where to write the .deb     (default: dist)
  -h, --help        this text

Only what the package actually needs is derived: the architecture from the
ELF header, the glibc floor from the versioned symbols the binary imports.
EOF
}

# --- arguments ---------------------------------------------------------------

BINARY=target/release/mask
VERSION=
ARCH=
DEPENDS=
MAINTAINER=$MAINTAINER_DEFAULT
OUTPUT=dist

while [ $# -gt 0 ]; do
	case "$1" in
	--binary) [ $# -ge 2 ] || die "--binary needs a value"; BINARY=$2; shift 2 ;;
	--binary=*) BINARY=${1#*=}; shift ;;
	--version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
	--version=*) VERSION=${1#*=}; shift ;;
	--arch) [ $# -ge 2 ] || die "--arch needs a value"; ARCH=$2; shift 2 ;;
	--arch=*) ARCH=${1#*=}; shift ;;
	--depends) [ $# -ge 2 ] || die "--depends needs a value"; DEPENDS=$2; shift 2 ;;
	--depends=*) DEPENDS=${1#*=}; shift ;;
	--maintainer) [ $# -ge 2 ] || die "--maintainer needs a value"; MAINTAINER=$2; shift 2 ;;
	--maintainer=*) MAINTAINER=${1#*=}; shift ;;
	--output) [ $# -ge 2 ] || die "--output needs a value"; OUTPUT=$2; shift 2 ;;
	--output=*) OUTPUT=${1#*=}; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown option: $1 (try --help)" ;;
	esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

case "$BINARY" in
/*) ;;
*) BINARY="$ROOT/$BINARY" ;;
esac

[ -f "$BINARY" ] || die "no binary at $BINARY — run 'cargo build --release --locked' first"
[ -x "$BINARY" ] || die "$BINARY is not executable"

command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb not found — this needs a Debian-based build host"

# --- identity ----------------------------------------------------------------

max_glibc() { # binary -> "2.34" or empty for a static binary
	detail=
	if command -v objdump >/dev/null 2>&1; then
		detail=$(objdump -T "$1" 2>/dev/null || true)
	elif command -v readelf >/dev/null 2>&1; then
		detail=$(readelf --dyn-syms --wide "$1" 2>/dev/null || true)
	fi
	printf '%s\n' "$detail" |
		grep -o 'GLIBC_[0-9][0-9.]*' |
		sed 's/^GLIBC_//' |
		awk -F. '{ key = $1 * 10000 + $2 * 100 + $3; if (key > best) { best = key; v = $0 } } END { if (best) print v }'
}

detect_arch() { # binary -> dpkg architecture
	if command -v file >/dev/null 2>&1; then
		desc=$(file -b "$1" 2>/dev/null || true)
		case "$desc" in
		*"ARM aarch64"* | *"ARM64"* | *"aarch64"*) echo arm64; return ;;
		*"x86-64"* | *"x86_64"*) echo amd64; return ;;
		*"80386"*) echo i386; return ;;
		*"ARM,"*) echo armhf; return ;;
		esac
	fi
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	i?86) echo i386 ;;
	armv7l | armhf) echo armhf ;;
	*) die "cannot tell the architecture of $1 — pass --arch" ;;
	esac
}

if [ -z "$VERSION" ]; then
	# `mask --version` prints "mask 1.0.0"; the version is the only thing that
	# should ever appear there, so take the last word and validate it.
	VERSION=$("$BINARY" --version 2>/dev/null | awk '{print $NF}')
	[ -n "$VERSION" ] || die "cannot read a version from $BINARY — pass --version"
fi

case "$VERSION" in
[0-9]*) ;;
*) die "a Debian version must start with a digit, got '$VERSION'" ;;
esac
case "$VERSION" in
*[!A-Za-z0-9.+~-]*) die "a Debian version may only hold letters, digits and . + ~ -, got '$VERSION'" ;;
esac

[ -n "$ARCH" ] || ARCH=$(detect_arch "$BINARY")
case "$ARCH" in
amd64 | arm64 | i386 | armhf | ppc64el | riscv64 | s390x) ;;
*) die "unsupported architecture '$ARCH'" ;;
esac

if [ -z "$DEPENDS" ]; then
	glibc=$(max_glibc "$BINARY")
	# The floor comes from the symbol set the binary actually imports, so a
	# build on an older release produces a package that says so instead of a
	# hardcoded claim that turns into "GLIBC_2.39 not found" at runtime.
	#
	# ca-certificates is not optional in practice: rustls reads the system root
	# store, so without it every https upstream fails verification.
	if [ -n "$glibc" ]; then
		DEPENDS="libc6 (>= $glibc), ca-certificates"
	else
		DEPENDS=ca-certificates
	fi
fi

# --- staging -----------------------------------------------------------------

work=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$work"' EXIT INT TERM HUP

pkgdir="$work/${PROG}_${VERSION}_${ARCH}"
docdir="$pkgdir/usr/share/doc/$PROG"

mkdir -p "$pkgdir/usr/bin" "$pkgdir/usr/share/man/man1" "$docdir" "$pkgdir/DEBIAN"
cp "$BINARY" "$pkgdir/usr/bin/$PROG"
chmod 0755 "$pkgdir/usr/bin/$PROG"

# The man page carries the version in its header; -n keeps the gzip timestamp
# out of the file so two builds of one commit are byte-identical.
sed "s|@VERSION@|$VERSION|g" "$SCRIPT_DIR/mask.1" | gzip -9n >"$pkgdir/usr/share/man/man1/$PROG.1.gz"
chmod 0644 "$pkgdir/usr/share/man/man1/$PROG.1.gz"

for doc in README.md CHANGELOG.md mask.toml.example; do
	if [ -f "$ROOT/$doc" ]; then
		cp "$ROOT/$doc" "$docdir/$doc"
		chmod 0644 "$docdir/$doc"
	fi
done
cp "$SCRIPT_DIR/copyright" "$docdir/copyright"
chmod 0644 "$docdir/copyright"

# Installed-Size is in KiB, rounded up, and covers /usr only: DEBIAN is
# package metadata, not payload.
installed_size=$(du -sk "$pkgdir/usr" | cut -f1)

sed \
	-e "s|@VERSION@|$VERSION|g" \
	-e "s|@ARCH@|$ARCH|g" \
	-e "s|@MAINTAINER@|$MAINTAINER|g" \
	-e "s|@INSTALLED_SIZE@|$installed_size|g" \
	-e "s|@DEPENDS@|$DEPENDS|g" \
	"$SCRIPT_DIR/control.in" >"$pkgdir/DEBIAN/control"
chmod 0644 "$pkgdir/DEBIAN/control"
if [ -z "$DEPENDS" ]; then
	grep -v '^Depends:[[:space:]]*$' "$pkgdir/DEBIAN/control" >"$pkgdir/DEBIAN/control.tmp"
	mv "$pkgdir/DEBIAN/control.tmp" "$pkgdir/DEBIAN/control"
fi

if command -v md5sum >/dev/null 2>&1; then
	(cd "$pkgdir" && find usr -type f -print | sort | while IFS= read -r f; do md5sum "$f"; done) >"$pkgdir/DEBIAN/md5sums"
	chmod 0644 "$pkgdir/DEBIAN/md5sums"
fi

# dpkg records the staging tree's modes as the installed ones, so make the
# directories explicit rather than inherit whatever the build user's umask was.
find "$pkgdir" -type d -exec chmod 0755 {} +

mkdir -p "$OUTPUT"
deb="$OUTPUT/${PROG}_${VERSION}_${ARCH}.deb"
rm -f "$deb"
# --root-owner-group: files belong to root:root even when an unprivileged user
# builds the package. -Zxz keeps the payload small; the binary is already
# stripped by the release profile.
dpkg-deb --root-owner-group -Zxz --build "$pkgdir" "$deb" >/dev/null || die "dpkg-deb failed"

size=$(wc -c <"$deb" | tr -d ' ')
note "wrote $deb (${size} bytes, ${installed_size} KiB installed, Depends: ${DEPENDS:-none})"
printf '%s\n' "$deb"
