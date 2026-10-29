"""Every top-level package main.py's import graph needs must be in the Makefile's
explicit install-pkg list (it ships named dirs, not a glob). A miss means the
installed kbagents dies on import, which a source-tree test run cannot see."""
import os, re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def test_install_pkg_ships_every_aads_package():
    aads = os.path.join(ROOT, "kb-aads")
    pkgs = {d for d in os.listdir(aads)
            if os.path.isfile(os.path.join(aads, d, "__init__.py")) or d in ("agents", "comms", "marl", "api")}
    mk = open(os.path.join(ROOT, "Makefile")).read()
    line = next(l for l in mk.splitlines() if "cp -r kb-aads/agents" in l)
    shipped = set(re.findall(r"kb-aads/(\w+)", line))
    missing = {p for p in pkgs if p not in ("tests", "demo", "venv", "__pycache__")} - shipped
    assert not missing, f"kb-aads packages not shipped by make install-pkg: {sorted(missing)}"
