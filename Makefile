# ==============================================================================
# Unified Kernel Borderlands Compilation & Installation Layout
# ==============================================================================

# Install layout. Defaults keep the historical `sudo make install` ->
# /usr/local behaviour; the .deb / Arch packages run
# `make install-pkg PREFIX=/usr DESTDIR=<staging>` (packaging/deb/build-deb.sh,
# packaging/arch/PKGBUILD) so both share this one definition of what ships.
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
LIBDIR     ?= $(PREFIX)/lib
SYSCONFDIR ?= /etc
UNITDIR    ?= $(if $(filter /usr/local,$(PREFIX)),/etc/systemd/system,$(PREFIX)/lib/systemd/system)
DESTDIR    ?=
GOARCH     ?= $(shell go env GOARCH)

.PHONY: all build install install-pkg clean

all: build

build:
	@echo "🛠️  Compiling all subsystem targets into top-level bin/..."
	mkdir -p bin
	@echo "[Stage-1/5] Build C-based low-level eBPF core library bindings"
	$(MAKE) -C kb-core
	
	@echo "[Stage-2/5] Build the main Go system daemon (kbd) into the root bin/"
	# Added -a flag to completely bypass Go's stale build cache loops
	cd kb-control-plane && GOOS=linux GOARCH=$(GOARCH) go build -a -ldflags="-s -w" -o ../bin/kbd ./cmd/kbd
	
	@echo "[Stage-3/5] Build the Rust eBPF policy engine and manually copy it to the root bin/"
	cd kb-checker && cargo build --release
	cp kb-checker/target/release/kb-checker ./bin/kb-checker
	
	@echo "[Stage-4/5] Build the companion Go CLI tool into the root bin/"
	# Added -a flag here as well to force fresh compilation layers
	cd kb-op/kbctl && GOOS=linux GOARCH=$(GOARCH) go build -a -ldflags="-s -w" -o ../../bin/kbctl .
	
	@echo "[Stage-5/5] Build Vite frontend assets and bundle the Rust Master Broker into the root bin/"
	cd kb-op/kb-mcp && GOOS=linux GOARCH=$(GOARCH) go build -a -ldflags="-s -w" -o ../../bin/mcp-server .
	cd kb-op/kb-dashboard && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run build
	cd kb-op/kb-tui && cargo build --release
	cp kb-op/kb-tui/target/release/kb-tui ./bin/kbopd

install:
	@echo "📦 Deploying centralized binaries to $(DESTDIR)$(BINDIR)..."
	install -Dm755 kb-core/build/kbd_sensor $(DESTDIR)$(BINDIR)/kbd_sensor
	install -Dm755 bin/kbd $(DESTDIR)$(BINDIR)/kbd
	install -Dm755 bin/kb-checker $(DESTDIR)$(BINDIR)/kb-checker
	install -Dm755 bin/kbopd $(DESTDIR)$(BINDIR)/kbopd
	install -Dm755 bin/kbctl $(DESTDIR)$(BINDIR)/kbctl
	install -Dm755 bin/mcp-server $(DESTDIR)$(BINDIR)/mcp-server

# Everything a package needs beyond the six binaries. Explicit file lists
# only — never a directory glob — because kb-core/ and kb-control-plane/ hold
# dev-only ssh_host_ed25519_key / authorized_keys files that must never ship.
# Units and the SSH wrapper are rewritten from the dev /usr/local/bin paths to
# $(BINDIR); the operator sshd config goes to /etc/kb/ (not
# /etc/ssh/sshd_config.d/, which the host's own sshd also includes and would
# then bind port 2222 itself).
install-pkg: install
	install -Dm755 packaging/ssh/kb-tui-session-wrapper.sh $(DESTDIR)$(BINDIR)/kb-tui-session-wrapper.sh
	sed -i 's#/usr/local/bin#$(BINDIR)#g' $(DESTDIR)$(BINDIR)/kb-tui-session-wrapper.sh
	install -Dm755 packaging/bin/kbagents $(DESTDIR)$(BINDIR)/kbagents
	for u in packaging/systemd/*.service; do \
		install -Dm644 $$u $(DESTDIR)$(UNITDIR)/$$(basename $$u); \
		sed -i -e 's#/usr/local/bin#$(BINDIR)#g' \
			-e 's#/etc/ssh/sshd_config.d/kb-operator.conf#$(SYSCONFDIR)/kb/sshd_kb-operator.conf#' \
			$(DESTDIR)$(UNITDIR)/$$(basename $$u); \
	done
	install -Dm644 packaging/ssh/kb-operator.conf $(DESTDIR)$(SYSCONFDIR)/kb/sshd_kb-operator.conf
	sed -i 's#/usr/local/bin#$(BINDIR)#g' $(DESTDIR)$(SYSCONFDIR)/kb/sshd_kb-operator.conf
	for f in policy rules workloads; do \
		install -Dm640 kb-control-plane/config/$$f.yaml $(DESTDIR)$(SYSCONFDIR)/kb/$$f.yaml; \
	done
	install -Dm640 config/agents.yaml $(DESTDIR)$(SYSCONFDIR)/kb/agents.yaml
	install -Dm755 scripts/setup/provision.sh $(DESTDIR)$(LIBDIR)/kb/provision.sh
	install -dm755 $(DESTDIR)$(LIBDIR)/kb/aads
	cp -r kb-aads/agents kb-aads/api kb-aads/comms kb-aads/consensus kb-aads/marl kb-aads/swarm $(DESTDIR)$(LIBDIR)/kb/aads/
	install -m644 kb-aads/main.py kb-aads/requirements.txt $(DESTDIR)$(LIBDIR)/kb/aads/
	find $(DESTDIR)$(LIBDIR)/kb/aads -name __pycache__ -type d -prune -exec rm -rf {} +
	# Trim dev/training-only content. containment_ppo IS loaded at runtime by
	# agents/containment.py (RLModule.from_checkpoint); jury_ppo is not loaded
	# by anything, and session.log is a dev artifact.
	rm -rf $(DESTDIR)$(LIBDIR)/kb/aads/marl/checkpoints/jury_ppo $(DESTDIR)$(LIBDIR)/kb/aads/marl/session.log
	# Checkpoints are pickles (code runs when loaded): ship an integrity manifest.
	# Verify with: cd /usr/lib/kb/aads/marl/checkpoints && sha256sum -c SHA256SUMS
	cd $(DESTDIR)$(LIBDIR)/kb/aads/marl/checkpoints && find containment_ppo -type f | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/doc/kernel-borderlands/LICENSE
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/kernel-borderlands/README.md

clean:
	@echo "🧹 Purging local compilation targets..."
	$(MAKE) -C kb-core clean
	cd kb-checker && cargo clean
	cd kb-op/kb-tui && cargo clean
	rm -rf bin/ kb-op/bin/kbctl kb-op/kb-dashboard/dist

