# deb

Debian/Ubuntu packaging. `build-deb.sh` stages `make install-pkg` and builds the `.deb` with `dpkg-deb`; `control.in` is the package metadata template; `conffiles` lists the `/etc/kb` files dpkg preserves across upgrades; `postinst`, `prerm`, `postrm` are the maintainer scripts (they provision the `kb` group, `operator` user and SSH host key, and start nothing); `README.Debian` is installed as the package's quick-start. Build on the target distro: the binaries link the build host's glibc. Overview: [`../README.md`](../README.md).
