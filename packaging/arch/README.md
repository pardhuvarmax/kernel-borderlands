# arch

Arch Linux packaging: `PKGBUILD` (builds from the surrounding tree; `!lto` and a neutral toolchain environment are required) and `kernel-borderlands.install` (post-install hooks). `makepkg -f` here produces `kernel-borderlands-<version>-1-x86_64.pkg.tar.zst`; the package contents come from `make install-pkg` in the root `Makefile`. Overview: [`../README.md`](../README.md).
