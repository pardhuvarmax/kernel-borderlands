# latex/

LaTeX source for Kernel Borderlands research papers.

- `paper/` — the main KB paper: architecture, feature set, mathematical
  formulation of every learned/statistical decision procedure, a
  security audit, and a brief section noting NOMAD, the hardware trust
  module now developed in parallel in its own separate repository
  (`github.com/pardhuvarmax/the-nomad`), not documented in depth here.
  Build with `pdflatex main.tex && bibtex main && pdflatex main.tex &&
  pdflatex main.tex` from inside `paper/`.
- `bug-reports/` — LaTeX writeups of specific defects found during
  development.

NOMAD's own standalone paper draft (previously `nomad/`) has moved with
the rest of NOMAD's design work to its separate repository and has been
removed from here.
