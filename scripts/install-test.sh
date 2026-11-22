#!/bin/sh
#
# Prove that the two front doors still work.
#
#   sh scripts/install-test.sh            # needs a built binary
#
# This exercises what a user meets, not what the code does:
#
#   packaging/debian/build-deb.sh  -> a .deb that dpkg-deb accepts, whose
#                                     metadata is truthful, whose payload has no
#                                     service and no config file, and whose
#                                     binary runs once unpacked;
#   scripts/install.sh             -> a curl|sh install against a local mirror,
#                                     including the ways it must refuse (a bad
#                                     checksum, a missing SHA256SUMS, plain http
#                                     off loopback, an unknown flag).
#
# No network, no root, no gateway: the mirror is a file:// directory holding the
# same asset names a release publishes. Exit status is the number of failures.
#
# The one step that touches the host, `dpkg -i`, only runs when
# MASK_TEST_DPKG_INSTALL=1 is set (CI sets it on a throwaway runner) and no
# `mask` package is already installed there.

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BINARY=${MASK_TEST_BINARY:-$ROOT/target/release/mask}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/mask-install-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM HUP

failures=0
pass() { printf '  ok    %s\n' "$*"; }
fail() {
	printf '  FAIL  %s\n' "$*" >&2
	failures=$((failures + 1))
}
group() { printf '\n%s\n' "$*"; }

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# --- preconditions -----------------------------------------------------------

group "preconditions"

if [ ! -x "$BINARY" ]; then
	printf 'install-test: no binary at %s\n' "$BINARY" >&2
	printf 'install-test: run cargo build --release --locked first\n' >&2
	exit 2
fi
pass "binary present: ${BINARY#"$ROOT"/}"

version=$("$BINARY" --version 2>/dev/null | awk '{print $NF}')
case "$version" in
[0-9]*) pass "binary reports version $version" ;;
*) fail "binary reports no usable version" ; version=0.0.0 ;;
esac

if sh -n "$ROOT/scripts/install.sh" 2>/dev/null; then
	pass "scripts/install.sh parses under sh"
else
	fail "scripts/install.sh does not parse under sh"
fi

if command -v dash >/dev/null 2>&1; then
	if dash -n "$ROOT/scripts/install.sh" 2>/dev/null; then
		pass "scripts/install.sh parses under dash (POSIX)"
	else
		fail "scripts/install.sh is not POSIX — dash rejects it"
	fi
else
	printf '  skip  dash not installed\n'
fi

# --- the deb -----------------------------------------------------------------

if ! command -v dpkg-deb >/dev/null 2>&1; then
	group "debian package"
	printf '  skip  dpkg-deb not installed\n'
else
	group "debian package"

	debdir="$WORK/deb"
	if sh "$ROOT/packaging/debian/build-deb.sh" --binary "$BINARY" --output "$debdir" >/dev/null 2>"$WORK/deb.err"; then
		pass "build-deb.sh produced a package"
	else
		fail "build-deb.sh failed: $(cat "$WORK/deb.err")"
	fi

	deb=
	for candidate in "$debdir"/mask_*.deb; do
		[ -f "$candidate" ] && deb=$candidate
	done
	if [ -z "$deb" ]; then
		fail "no .deb in $debdir"
	else
		base=$(basename "$deb")
		case "$base" in
		mask_"$version"_*.deb) pass "artifact name follows mask_<version>_<arch>.deb ($base)" ;;
		*) fail "unexpected artifact name: $base" ;;
		esac

		dpkg-deb --info "$deb" >"$WORK/control" 2>/dev/null

		for field in "Package: mask" "Version: $version" "Architecture: " "Maintainer: " "Installed-Size: " "Section: utils" "Description: "; do
			if grep -qF -- "$field" "$WORK/control"; then
				pass "control has '$field'"
			else
				fail "control lacks '$field'"
			fi
		done

		# Depends must be a claim the payload can keep: either no libc at all
		# (static) or a floor that came from the binary's own symbol versions,
		# plus the root store rustls reads at runtime.
		depends=$(sed -n 's/^ Depends: //p' "$WORK/control")
		case "$depends" in
		*"libc6 (>= "[0-9]*) pass "control declares the glibc floor the binary imports ($depends)" ;;
		"") pass "control declares no Depends (static binary)" ;;
		*) fail "Depends names no libc floor: $depends" ;;
		esac
		case "$depends" in
		*ca-certificates*) pass "control pulls the CA bundle rustls needs" ;;
		*) fail "Depends omits ca-certificates: ${depends:-none}" ;;
		esac

		dpkg-deb --contents "$deb" >"$WORK/contents" 2>/dev/null

		for path in ./usr/bin/mask ./usr/share/man/man1/mask.1.gz ./usr/share/doc/mask/copyright ./usr/share/doc/mask/README.md ./usr/share/doc/mask/mask.toml.example; do
			if grep -qF -- " $path" "$WORK/contents"; then
				pass "payload has $path"
			else
				fail "payload lacks $path"
			fi
		done

		# The operator's side is a human's: a package that enables a daemon or
		# writes a config with a key in it would take that away.
		for forbidden in ./etc/ ./lib/systemd/ ./usr/lib/systemd/ ./usr/lib/tmpfiles.d/; do
			if grep -qF -- " $forbidden" "$WORK/contents"; then
				fail "payload contains $forbidden — mask ships a binary, not a service"
			fi
		done
		pass "payload ships no /etc and no service unit"

		if awk '$1 !~ /^d/ && $NF ~ /^\.\// { n++ } END { exit n > 0 ? 0 : 1 }' "$WORK/contents"; then
			pass "payload has files"
		else
			fail "payload has no files"
		fi

		# Extracted binary must be the one we built and must run.
		mkdir -p "$WORK/debroot"
		dpkg-deb -x "$deb" "$WORK/debroot"
		if [ -x "$WORK/debroot/usr/bin/mask" ] && [ "$("$WORK/debroot/usr/bin/mask" --version 2>/dev/null)" = "mask $version" ]; then
			pass "unpacked binary runs and reports $version"
		else
			fail "unpacked binary does not run or reports the wrong version"
		fi

		# Same payload, byte for byte, as the binary the release uploads: no
		# strip, no wrapper, no second build that could drift.
		if [ "$(sha256_of "$WORK/debroot/usr/bin/mask")" = "$(sha256_of "$BINARY")" ]; then
			pass "unpacked binary is byte-identical to $BINARY"
		else
			fail "unpacked binary differs from $BINARY"
		fi

		if command -v groff >/dev/null 2>&1; then
			gunzip -c "$WORK/debroot/usr/share/man/man1/mask.1.gz" >"$WORK/mask.1"
			if groff -man -Kutf8 -Tutf8 -z "$WORK/mask.1" 2>"$WORK/man.err"; then
				pass "man page parses"
			else
				fail "man page does not parse: $(head -1 "$WORK/man.err")"
			fi
		else
			printf '  skip  groff not installed, man page not rendered\n'
		fi

		# A real dpkg install is the only way to know the metadata is
		# satisfiable on this system. It is opt-in because it changes the host:
		# on a developer's machine `mask` may already be installed, and the
		# cleanup would remove it.
		already_installed=no
		if command -v dpkg-query >/dev/null 2>&1; then
			case "$(dpkg-query -W -f='${Status}' mask 2>/dev/null || true)" in
			*"install ok installed"*) already_installed=yes ;;
			esac
		fi
		if [ "${MASK_TEST_DPKG_INSTALL:-0}" != 1 ]; then
			printf '  skip  dpkg -i not attempted (opt in with MASK_TEST_DPKG_INSTALL=1)\n'
		elif [ "$already_installed" = yes ]; then
			printf '  skip  a mask package is already installed on this host\n'
		elif [ "$(id -u)" = 0 ]; then
			if dpkg -i "$deb" >"$WORK/dpkg.log" 2>&1; then
				pass "dpkg -i installed the package"
				if [ "$(/usr/bin/mask --version 2>/dev/null)" = "mask $version" ]; then
					pass "/usr/bin/mask runs after install"
				else
					fail "/usr/bin/mask does not run after install"
				fi
				dpkg -r mask >>"$WORK/dpkg.log" 2>&1 && pass "dpkg -r removed it" || fail "dpkg -r failed"
			else
				fail "dpkg -i refused the package: $(tail -3 "$WORK/dpkg.log")"
			fi
		else
			printf '  skip  not root, dpkg -i not attempted\n'
		fi
	fi
fi

# --- install.sh --------------------------------------------------------------

group "install.sh against a local mirror"

mirror="$WORK/mirror"
tag="v$version"
target=test-arch
asset="mask-$target"
mkdir -p "$mirror/$tag"
installer="$ROOT/scripts/install.sh"
prefix="$WORK/prefix"
installed="$prefix/bin/mask"

write_mirror() { # binary
	cp "$1" "$mirror/$tag/$asset"
	chmod 0755 "$mirror/$tag/$asset"
	(cd "$mirror/$tag" && printf '%s  %s\n' "$(sha256_of "$asset")" "$asset") >"$mirror/$tag/SHA256SUMS"
}

# A mirror needs a stable, unpacked binary; the release build is exactly that.
write_mirror "$BINARY"

if sh "$installer" --base-url "file://$mirror" --version "$version" --target "$target" --prefix "$prefix" >"$WORK/install.log" 2>&1; then
	pass "fresh install exits 0"
else
	fail "fresh install failed: $(tail -3 "$WORK/install.log")"
fi

if [ -x "$installed" ] && [ "$("$installed" --version 2>/dev/null)" = "mask $version" ]; then
	pass "installed binary runs and reports $version"
else
	fail "installed binary is missing or broken"
fi

if [ "$(sha256_of "$installed")" = "$(sha256_of "$BINARY")" ]; then
	pass "installed binary matches the mirror"
else
	fail "installed binary differs from the mirror"
fi

# Re-running is an upgrade: same path, no leftovers.
before=$(ls -a "$prefix/bin")
if sh "$installer" --base-url "file://$mirror" --version "$version" --target "$target" --prefix "$prefix" >>"$WORK/install.log" 2>&1; then
	if [ "$(ls -a "$prefix/bin")" = "$before" ]; then
		pass "re-install overwrites in place, no temp files left behind"
	else
		fail "re-install left something behind: $(ls -a "$prefix/bin" | tr '\n' ' ')"
	fi
else
	fail "re-install failed"
fi

# A wrong checksum must not touch what is already installed.
good=$(sha256_of "$mirror/$tag/$asset")
printf 'corrupted' >"$mirror/$tag/$asset"
if sh "$installer" --base-url "file://$mirror" --version "$version" --target "$target" --prefix "$prefix" >"$WORK/badsum.log" 2>&1; then
	fail "install accepted a corrupted binary"
else
	pass "corrupted binary is refused"
fi
if grep -q 'checksum mismatch' "$WORK/badsum.log"; then
	pass "the refusal says why (checksum mismatch)"
else
	fail "the refusal does not mention the checksum: $(tail -2 "$WORK/badsum.log")"
fi
if [ "$(sha256_of "$installed")" = "$good" ]; then
	pass "a refused upgrade left the installed binary untouched"
else
	fail "a refused upgrade damaged the installed binary"
fi

# Without SHA256SUMS there is nothing to check the download against.
write_mirror "$BINARY"
mv "$mirror/$tag/SHA256SUMS" "$WORK/SHA256SUMS.held"
if sh "$installer" --base-url "file://$mirror" --version "$version" --target "$target" --prefix "$prefix" >"$WORK/nosums.log" 2>&1; then
	fail "install proceeded without a SHA256SUMS to verify against"
else
	pass "missing SHA256SUMS is refused (fail closed)"
fi
if grep -q 'unverified' "$WORK/nosums.log"; then
	pass "the refusal offers the deliberate override (--no-verify)"
else
	fail "the refusal does not explain itself: $(tail -2 "$WORK/nosums.log")"
fi

# The override exists for a mirror that has no sums yet, and says it is unverified.
if sh "$installer" --base-url "file://$mirror" --version "$version" --target "$target" --prefix "$prefix" --no-verify >"$WORK/noverify.log" 2>&1; then
	if grep -q 'no-verify' "$WORK/noverify.log"; then
		pass "--no-verify installs and warns that nothing was verified"
	else
		fail "--no-verify installed without a warning"
	fi
else
	fail "--no-verify failed on a mirror without SHA256SUMS"
fi
mv "$WORK/SHA256SUMS.held" "$mirror/$tag/SHA256SUMS"

# An unknown release is a download failure, reported as one.
if sh "$installer" --base-url "file://$mirror" --version 9.9.9 --target "$target" --prefix "$prefix" >"$WORK/norelease.log" 2>&1; then
	fail "install accepted a release that does not exist"
else
	pass "a missing release is refused"
fi

# Plain http to a non-loopback host is a man in the middle, by construction.
if sh "$installer" --base-url http://example.invalid/releases --version "$version" --target "$target" --prefix "$prefix" >"$WORK/http.log" 2>&1; then
	fail "install accepted plain http from a remote host"
else
	if grep -q 'refusing plain http' "$WORK/http.log"; then
		pass "plain http off loopback is refused"
	else
		fail "plain http refusal does not explain itself: $(tail -2 "$WORK/http.log")"
	fi
fi

# --dry-run must not create or touch anything.
dry="$WORK/dry"
if sh "$installer" --base-url "file://$mirror" --version "$version" --target "$target" --prefix "$dry" --dry-run >"$WORK/dry.log" 2>&1; then
	if [ ! -e "$dry" ]; then
		pass "--dry-run writes nothing"
	else
		fail "--dry-run created $dry"
	fi
	grep -q 'file://' "$WORK/dry.log" && pass "--dry-run prints the URL it would fetch" || fail "--dry-run printed no URL"
else
	fail "--dry-run failed"
fi

# Unknown flags are refused rather than ignored.
if sh "$installer" --nonsense >"$WORK/flag.log" 2>&1; then
	fail "install accepted an unknown flag"
else
	pass "an unknown flag is refused"
fi

# --system is a system-wide write: without root it must stop before touching
# /usr/local, not fail halfway through.
if [ "$(id -u)" = 0 ]; then
	printf '  skip  running as root, --system refusal not applicable\n'
elif sh "$installer" --system --base-url "file://$mirror" --version "$version" --target "$target" >"$WORK/system.log" 2>&1; then
	fail "--system succeeded without root"
else
	if grep -q 'needs root' "$WORK/system.log"; then
		pass "--system without root stops with the command to run"
	else
		fail "--system without root failed without saying why: $(tail -2 "$WORK/system.log")"
	fi
fi

if sh "$installer" --help >/dev/null 2>&1; then
	pass "--help exits 0"
else
	fail "--help exits non-zero"
fi

# Uninstall removes the binary and leaves the operator's files alone.
mkdir -p "$WORK/home/.config/mask"
printf 'placeholder\n' >"$WORK/home/.config/mask/mask.toml"
if HOME="$WORK/home" sh "$installer" --uninstall --prefix "$prefix" >"$WORK/uninstall.log" 2>&1; then
	if [ -e "$installed" ]; then
		fail "--uninstall left the binary in place"
	else
		pass "--uninstall removed the binary"
	fi
	if [ -f "$WORK/home/.config/mask/mask.toml" ]; then
		pass "--uninstall left the config alone"
	else
		fail "--uninstall deleted something it did not install"
	fi
else
	fail "--uninstall failed"
fi

# --- verdict -----------------------------------------------------------------

printf '\n'
if [ "$failures" -eq 0 ]; then
	printf 'install-test: ok\n'
	exit 0
fi
printf 'install-test: %d failure(s)\n' "$failures" >&2
exit "$failures"
