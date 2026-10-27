# Builds "The Kernel Borderlands" for both distributions.
#   make            -> build/KB-Field-Manual-Arch.pdf and build/KB-Field-Manual-Ubuntu.pdf
#   make help       -> regenerate generated/*.txt from the real kbctl/kbd binaries (BIN=../../bin)
# Needs LuaLaTeX (TeX Live) with tcolorbox, tikz, listings, fontspec and the Latin Modern OTF fonts.
BIN ?= ../../bin
SRC  = main.tex preamble.tex $(wildcard chapters/*.tex)

.PHONY: all arch ubuntu help clean
all: arch ubuntu
arch:   build/KB-Field-Manual-Arch.pdf
ubuntu: build/KB-Field-Manual-Ubuntu.pdf

build/KB-Field-Manual-Arch.pdf: $(SRC)
	latexmk -lualatex -interaction=nonstopmode -halt-on-error -outdir=build -jobname=KB-Field-Manual-Arch \
	  -lualatex='lualatex %O "\def\KBDISTRO{arch}\input{%S}"' main.tex
build/KB-Field-Manual-Ubuntu.pdf: $(SRC)
	latexmk -lualatex -interaction=nonstopmode -halt-on-error -outdir=build -jobname=KB-Field-Manual-Ubuntu \
	  -lualatex='lualatex %O "\def\KBDISTRO{ubuntu}\input{%S}"' main.tex

help:
	./gen-help.sh $(BIN)

clean:
	rm -rf build
