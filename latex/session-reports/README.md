# latex/session-reports/

Dated LaTeX writeups of individual working sessions, in the same four-side-border
visual style as `latex/bug-reports/` (reuses its preamble: TikZ page border, `fancyhdr`
header/footer, black-and-white `listings`, the `devcredit` signature macro).

One subdirectory per session, named by date: `YYYY-MM-DD/main.tex` builds to
`YYYY-MM-DD/main.pdf` with `lualatex main.tex` (run twice, for the table of contents
and cross-references). Each report is self-contained — commit hashes, diffstats, and
figures are pulled from `git show`/`git diff --stat` and the files as committed, not
reconstructed from memory, so it stays accurate if read later without the original
chat context.

- `2026-11-01/` — attack-lab network-using benign scenarios + third corpus, feature
  schema v2 (`dest_class`/`dest_port`), and the KB-AL-150 CVE registry (148/150 entries
  over five research passes). Covers the session running 2026-10-31 20:12 through
  2026-11-01 00:57.
