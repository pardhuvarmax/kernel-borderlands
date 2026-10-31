# field-manual

Source of "The Kernel Borderlands" field manual: one source, two editions (Arch and Ubuntu).

| Path | Role |
| --- | --- |
| `main.tex`, `preamble.tex` | Document root and macros |
| `chapters/` | One `.tex` file per chapter |
| `generated/` | CLI reference text produced from the real `kbctl`/`kbd` binaries (`make help`) |
| `Makefile` | `make` builds both PDFs into `build/`; needs LuaLaTeX (TeX Live) |

Built PDFs are copied to [`../../dist/`](../../dist/). Regenerate the CLI reference after changing any command: `make help BIN=../../bin`.
