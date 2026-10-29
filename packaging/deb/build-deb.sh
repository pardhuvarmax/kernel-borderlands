#!/bin/sh
# packaging/deb/build-deb.sh — build kernel-borderlands_<ver>_<arch>.deb from
# the current tree. Build ON the target distro (Ubuntu 24.04 for the demo VM):
# the binaries link the build host's glibc, so a .deb built on a newer
# distro will not run on an older one.
#
#   make build                       # compiles everything (needs go, cargo, npm, clang, bpftool)
#   packaging/deb/build-deb.sh       # -> dist/kernel-borderlands_1.1.0_amd64.deb
set -eu
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
VERSION="${VERSION:-1.1.0}"
ARCH="$(dpkg --print-architecture)"
STAGE="$REPO_ROOT/dist/deb-stage"
OUT="$REPO_ROOT/dist"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$OUT"
make install-pkg PREFIX=/usr DESTDIR="$STAGE"

# The checkout may sit under a setgid directory; dpkg-deb rejects a 2755
# DEBIAN/ and the bit must not leak into the package's own directories.
find "$STAGE" -type d -exec chmod g-s {} +
find "$STAGE" -type d -exec chmod 0755 {} +

sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$ARCH/" packaging/deb/control.in > "$STAGE/DEBIAN/control"
cp packaging/deb/conffiles packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$STAGE/DEBIAN/"
install -Dm644 packaging/deb/README.Debian "$STAGE/usr/share/doc/kernel-borderlands/README.Debian"
printf 'Installed-Size: %s\n' "$(du -sk "$STAGE" | cut -f1)" >> "$STAGE/DEBIAN/control"

chmod 0755 "$STAGE/DEBIAN"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT/kernel-borderlands_${VERSION}_${ARCH}.deb"
echo "built $OUT/kernel-borderlands_${VERSION}_${ARCH}.deb"
