# Release artifacts

| File | What it is |
| --- | --- |
| `KB-Field-Manual-Arch.pdf`, `KB-Field-Manual-Ubuntu.pdf` | The field manual, one edition per distribution (source: [`../latex/field-manual/`](../latex/field-manual/)) |
| `SHA256SUMS` | Checksums of the manuals **and** the two packages below |
| `kernel-borderlands_1.1.0_amd64.deb` | Ubuntu/Debian package (built on Ubuntu 24.04, glibc 2.39) |
| `kernel-borderlands-1.1.0-1-x86_64.pkg.tar.zst` | Arch package |

**The two packages are not tracked in git** (about 42 MB per rebuild of incompressible history); they are git-ignored and meant to be published as GitHub Release assets. Verify with `sha256sum -c SHA256SUMS`. Build instructions: [`../packaging/README.md`](../packaging/README.md).
